package com.foxy.keygen.data

import android.util.Base64
import com.foxy.keygen.data.model.Entitlement
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject

const val GUARDIAN_ENDPOINT_DEFAULT = "https://vpn.mozilla.org"
private const val GUARDIAN_MAX_CHALLENGE_ATTEMPTS = 5

class GuardianHttpError(message: String, val statusCode: Int? = null) : Exception(message)
class QuotaExceededError(message: String) : Exception(message)
class TokenInvalidError(message: String) : Exception(message)

data class ProxyPass(
    val token: String,
    val expiresAtEpochSeconds: Long?,
    val quotaMax: Long? = null,
    val quotaRemaining: Long? = null,
    val quotaReset: Long? = null,
)

class GuardianClient(
    private val challengeSolver: FastlyChallengeSolver = FastlyChallengeSolver(ControlPlaneHttp.cookieJar),
) {

    suspend fun fetchProxyPass(endpoint: String, accessToken: String): ProxyPass = withContext(Dispatchers.IO) {
        val url = "${endpoint.trimEnd('/')}/api/v1/fpn/token"
        authorizedRequest("GET", url, accessToken).use { resp ->
            when (resp.code) {
                401, 403 -> throw TokenInvalidError("access token was rejected by Guardian")
                429 -> throw QuotaExceededError("account proxy quota exceeded")
            }
            val text = resp.body?.string().orEmpty()
            if (resp.code != 200) {
                throw GuardianHttpError("failed to fetch proxy pass: HTTP ${resp.code}: ${text.take(2048)}", resp.code)
            }
            val body = JSONObject(text)
            val token = body.optString("token", "")
            if (token.isEmpty()) throw GuardianHttpError("proxy pass response did not contain a token")
            ProxyPass(
                token = token,
                expiresAtEpochSeconds = body.optLong("expires_at", 0L).takeIf { it > 0 }
                    ?: jwtExpiryEpochSeconds(token),
                quotaMax = resp.header("X-Quota-Limit")?.toLongOrNull(),
                quotaRemaining = resp.header("X-Quota-Remaining")?.toLongOrNull(),
                quotaReset = parseQuotaReset(resp.header("X-Quota-Reset")),
            )
        }
    }

    suspend fun fetchUserInfo(endpoint: String, accessToken: String): Entitlement = withContext(Dispatchers.IO) {
        val url = "${endpoint.trimEnd('/')}/api/v1/fpn/status"
        val entitlement = authorizedRequest("GET", url, accessToken).use { resp ->
            val text = resp.body?.string().orEmpty()
            if (resp.code != 200) {
                throw GuardianHttpError("failed to fetch account info: HTTP ${resp.code}: ${text.take(2048)}", resp.code)
            }
            parseEntitlement(JSONObject(text))
        }

        if (entitlement.limitedBandwidth) {
            val pass = runCatching { fetchProxyPass(endpoint, accessToken) }.getOrNull()
            entitlement.copy(
                quotaRemaining = pass?.quotaRemaining ?: entitlement.quotaRemaining,
                quotaReset = pass?.quotaReset ?: entitlement.quotaReset,
            )
        } else {
            entitlement
        }
    }

    suspend fun activateGuardian(endpoint: String, accessToken: String): Entitlement = withContext(Dispatchers.IO) {
        val url = "${endpoint.trimEnd('/')}/api/v1/fpn/activate"
        authorizedRequest("POST", url, accessToken).use { resp ->
            val text = resp.body?.string().orEmpty()
            if (resp.code != 200) {
                throw GuardianHttpError("failed to activate guardian entitlement: HTTP ${resp.code}: ${text.take(2048)}", resp.code)
            }
            parseEntitlement(JSONObject(text))
        }
    }

    private fun parseEntitlement(body: JSONObject): Entitlement = Entitlement(
        subscribed = body.optBoolean("subscribed", false),
        uid = body.optString("uid", ""),
        maxBytes = if (body.has("maxBytes") && !body.isNull("maxBytes")) {
            body.optLong("maxBytes", -1L).takeIf { it >= 0 }
        } else {
            null
        },
        limitedBandwidth = body.optBoolean("limited_bandwidth", false),
    )

    /**
     * X-Quota-Reset arrives either as unix seconds or as an RFC 3339 instant
     * («2026-11-26T18:00:00.000Z») — Mozilla's own client accepts both. The
     * previous release read the header with toLongOrNull() only, so whenever
     * Guardian answered with an instant the reset date was silently lost and
     * the quota card never showed the recharge day. Epoch millis are
     * normalised too.
     */
    private fun parseQuotaReset(raw: String?): Long? {
        val value = raw?.trim().orEmpty()
        if (value.isEmpty()) return null
        value.toLongOrNull()?.let { n ->
            return when {
                n > 1_000_000_000_000L -> n / 1000L   // epoch milliseconds
                n > 1_000_000_000L -> n               // epoch seconds
                else -> null
            }
        }
        return runCatching { java.time.Instant.parse(value).epochSecond }.getOrNull()
            ?: runCatching {
                // tolerate an instant without a zone — treat it as UTC
                java.time.LocalDateTime.parse(value)
                    .toInstant(java.time.ZoneOffset.UTC).epochSecond
            }.getOrNull()
    }

    /**
     * Account status + the metered-quota headers of a fresh proxy pass.
     * [Entitlement.quotaReset] carries the moment the monthly volume is
     * re-granted (unix seconds) so the dashboard can show the recharge day.
     *
     * BRAND-NEW ACCOUNTS: Guardian does not serve fpn/status for an account
     * that was never activated — the main app activates right before its
     * first connect, but an account added straight into the keygen never
     * went through that step, so the quota card read «دریافت اطلاعات ناموفق»
     * forever. If status is refused (402/403/404) or says subscribed=false,
     * activate the entitlement once and read the status again.
     */
    suspend fun fetchAccountOverview(endpoint: String, accessToken: String): Entitlement = withContext(Dispatchers.IO) {
        val first = runCatching { fetchUserInfo(endpoint, accessToken) }
        val entitlement = when {
            first.isSuccess -> first.getOrThrow()
            shouldSelfActivate(first.exceptionOrNull()) -> {
                // one activation attempt, then one status retry — if Mozilla
                // still refuses, the real error of the RETRY is surfaced
                val activated = runCatching { activateGuardian(endpoint, accessToken) }
                activated.fold(
                    onSuccess = { activatedEntitlement ->
                        runCatching { fetchUserInfo(endpoint, accessToken) }
                            .getOrElse { activatedEntitlement }
                    },
                    onFailure = { throw it },
                )
            }
            else -> throw first.exceptionOrNull() ?: GuardianHttpError("unknown guardian failure")
        }

        val quotaReady = entitlement.quotaRemaining != null && entitlement.quotaReset != null
        if (quotaReady && entitlement.subscribed) {
            entitlement
        } else {
            val pass = runCatching { fetchProxyPass(endpoint, accessToken) }.getOrNull()
                ?: return@withContext entitlement
            entitlement.copy(
                quotaRemaining = entitlement.quotaRemaining ?: pass.quotaRemaining,
                quotaReset = entitlement.quotaReset ?: pass.quotaReset,
            )
        }
    }

    private fun shouldSelfActivate(failure: Throwable?): Boolean {
        val status = (failure as? GuardianHttpError)?.statusCode ?: return false
        return status == 402 || status == 403 || status == 404
    }

    private suspend fun authorizedRequest(method: String, url: String, accessToken: String): Response {
        fun buildRequest(): Request {
            val builder = Request.Builder().url(url).applyMozillaVpnHeaders()
            builder.header("Content-Type", "application/json")
            builder.header("Authorization", "Bearer $accessToken")
            if (method == "POST") builder.post(ByteArray(0).toRequestBody(null))
            return builder.build()
        }
        var response = ControlPlaneHttp.client.newCall(buildRequest()).execute()
        var attempts = 1
        while (response.code == 406 && attempts < GUARDIAN_MAX_CHALLENGE_ATTEMPTS) {
            response.close()
            challengeSolver.solveAndInstall()
            response = ControlPlaneHttp.client.newCall(buildRequest()).execute()
            attempts++
        }
        return response
    }
}

internal fun jwtExpiryEpochSeconds(token: String): Long? {
    val parts = token.split('.')
    if (parts.size < 2) return null
    val payload = runCatching {
        var b64 = parts[1]
        while (b64.length % 4 != 0) b64 += "="
        String(
            android.util.Base64.decode(b64, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP),
            Charsets.UTF_8,
        )
    }.getOrNull() ?: return null
    return runCatching { JSONObject(payload).optLong("exp", 0L) }.getOrNull()?.takeIf { it > 0 }
}
