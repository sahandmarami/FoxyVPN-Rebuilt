package com.vauth.foxyvpn.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Live usage reporting through a private GitHub gist.
 *
 * The gist holds two files:
 *   registry.json -> { "keys": [ {id, name, gb, exp, revoked, issued} ] }   (written by FoxyKeygen)
 *   usage.json    -> { "usages": { <id>: {used, status, updated} } }        (written by this app)
 *
 * The app refreshes its own entry only, so the distributor's FoxyKeygen can
 * show every key's consumption live. Reporting failures are logged and
 * retried on the next sync tick; enforcement stays fully local.
 */
object GistReporter {

    private const val TAG = "GistReporter"

    /**
     * Local SOCKS5 port of the running tunnel, or 0 when the VPN is down.
     * The app excludes its own traffic from the tunnel, so control-plane
     * requests normally leave through the raw ISP connection. From some
     * networks (sanctioned/filtered routes) api.github.com refuses that, and
     * then usage reporting, usage restore and revocation ALL silently die.
     * When a tunnel is up we therefore send gist traffic through it first
     * (loopback SOCKS -> edge -> GitHub) and fall back to the direct route.
     */
    @Volatile
    var tunnelSocksPort: Int = 0

    private var tunnelClient: OkHttpClient? = null
    private var tunnelClientPort: Int = 0

    private fun clientThroughTunnel(): OkHttpClient? {
        val port = tunnelSocksPort
        if (port <= 0) return null
        val existing = tunnelClient
        if (existing != null && tunnelClientPort == port) return existing
        val built = ControlPlaneHttp.client.newBuilder()
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(25, TimeUnit.SECONDS)
            .callTimeout(30, TimeUnit.SECONDS)
            .build()
        tunnelClient = built
        tunnelClientPort = port
        return built
    }

    /**
     * Executes a gist request: through the tunnel when one is up, otherwise
     * (or when that route fails) directly. Returns null only when both routes
     * failed — the caller treats that as "offline" and retries later.
     */
    private fun execute(request: Request): Response? {
        val viaTunnel = clientThroughTunnel()
        if (viaTunnel != null) {
            try {
                return viaTunnel.newCall(request).execute()
            } catch (e: Exception) {
                AppLogger.d(TAG, "gist request via tunnel failed, falling back to direct: ${e.message}")
            }
        }
        return try {
            ControlPlaneHttp.client.newCall(request).execute()
        } catch (e: Exception) {
            AppLogger.d(TAG, "gist request failed on both routes: ${e.message}")
            null
        }
    }

    data class RegistryEntry(
        val id: String,
        val name: String,
        val gb: Long,
        val exp: Long,
        val revoked: Boolean,
    )

    data class ReportContext(
        val gistId: String,
        val token: String,
        val keyId: String,
    )

    private val inFlight = AtomicBoolean(false)

    fun contextFromKey(key: QuotaKey): ReportContext? {
        val payload = key.payload
        if (payload.gist.isBlank() || payload.gt.isBlank()) return null
        return ReportContext(payload.gist, payload.gt, payload.id)
    }

    /** Result of a combined revocation-check + usage-report round trip. */
    data class SyncResult(
        val revoked: Boolean,
        /** True when the registry answered and contained this key. */
        val present: Boolean,
        val reported: Boolean,
        /** Usage another device (or an earlier session) last reported — for resuming. */
        val reportedUsedBytes: Long = 0L,
        /** Monthly quota-reset timestamp the distributor's keygen attached to this key. */
        val resetAtEpochSeconds: Long = 0L,
    )

    /**
     * One round trip that serves both directions of the dashboard:
     * reads the registry (revocation flag) and writes this device's usage.
     * Returns null when the gist could not be reached (caller retries later).
     */
    suspend fun sync(
        ctx: ReportContext,
        usedBytes: Long,
        limitBytes: Long,
        expired: Boolean,
    ): SyncResult? = withContext(Dispatchers.IO) {
        if (!inFlight.compareAndSet(false, true)) return@withContext null
        try {
            val gist = fetchGist(ctx.gistId, ctx.token)
            if (gist == null) {
                AppLogger.d(TAG, "gist sync: fetch failed (will retry on the next tick)")
                return@withContext null
            }
            var revoked = false
            var present = false
            var resetAt = 0L
            gist.first.optJSONArray("keys")?.let { keys ->
                for (i in 0 until keys.length()) {
                    val entry = keys.optJSONObject(i) ?: continue
                    if (entry.optString("id") == ctx.keyId) {
                        present = true
                        revoked = entry.optBoolean("revoked", false)
                        resetAt = entry.optLong("reset", 0L)
                        break
                    }
                }
            }
            val status = when {
                revoked -> "revoked"
                expired -> "expired"
                limitBytes > 0 && usedBytes >= limitBytes -> "exhausted"
                else -> "active"
            }
            val reported = patchUsage(gist.second, ctx, usedBytes, status) >= 0
            if (!reported) AppLogger.d(TAG, "gist sync: usage patch failed (will retry)")
            val reportedUsed = gist.second.optJSONObject("usages")
                ?.optJSONObject(ctx.keyId)?.optLong("used", 0L) ?: 0L
            SyncResult(
                revoked = revoked,
                present = present,
                reported = reported,
                reportedUsedBytes = reportedUsed,
                resetAtEpochSeconds = resetAt,
            )
        } finally {
            inFlight.set(false)
        }
    }

    /**
     * True when the registry (reachable!) marks this key revoked or no longer
     * lists it at all — the distributor deleted it. False when the gist could
     * not be reached: being offline must not brick the key.
     */
    suspend fun isRevoked(ctx: ReportContext): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val pair = fetchGist(ctx.gistId, ctx.token) ?: return@runCatching false
            val keys = pair.first.optJSONArray("keys") ?: return@runCatching false
            for (i in 0 until keys.length()) {
                val entry = keys.optJSONObject(i) ?: continue
                if (entry.optString("id") == ctx.keyId) {
                    return@runCatching entry.optBoolean("revoked", false)
                }
            }
            // the registry answered but does not know this key: it was deleted
            true
        }.getOrElse {
            AppLogger.d(TAG, "revocation check failed (treating as not revoked): ${it.message}")
            false
        }
    }

    /**
     * The usage this device last reported for the key — used to resume the
     * counter after logout or a reinstall.
     */
    suspend fun fetchReportedUsage(ctx: ReportContext): Long? = withContext(Dispatchers.IO) {
        runCatching {
            val gist = fetchGist(ctx.gistId, ctx.token) ?: return@runCatching null
            gist.second.optJSONObject("usages")?.optJSONObject(ctx.keyId)
                ?.optLong("used", 0L)
                ?.takeIf { it > 0L }
        }.getOrNull()
    }

    /**
     * Reports cumulative usage. [statusOverride] forces a final state when the
     * key just became exhausted/expired; otherwise the status is derived from
     * the local limit.
     */
    suspend fun reportUsage(
        ctx: ReportContext,
        usedBytes: Long,
        limitBytes: Long,
        expired: Boolean,
        statusOverride: String? = null,
    ): Boolean = withContext(Dispatchers.IO) {
        if (!inFlight.compareAndSet(false, true)) return@withContext false
        try {
            val gist = fetchGist(ctx.gistId, ctx.token) ?: return@withContext false
            val status = statusOverride ?: when {
                expired -> "expired"
                limitBytes > 0 && usedBytes >= limitBytes -> "exhausted"
                else -> "active"
            }
            patchUsage(gist.second, ctx, usedBytes, status) >= 0
        } finally {
            inFlight.set(false)
        }
    }

    /** Writes [usedBytes] into the usage map of [usageDoc] and patches the gist.
     *  Monotonic: a client never LOWERS the stored usage — a friend who just
     *  reinstalled (counter at 0) must not wipe the dashboard's real number.
     *  The pre-write value is returned so callers can restore their counter. */
    private fun patchUsage(usageDoc: JSONObject, ctx: ReportContext, usedBytes: Long, status: String): Long {
        val usage = usageDoc
        val usages = usage.optJSONObject("usages") ?: JSONObject().also { usage.put("usages", it) }
        val previous = usages.optJSONObject(ctx.keyId)
        val previousUsed = previous?.optLong("used", 0L) ?: 0L
        usages.put(
            ctx.keyId,
            JSONObject()
                .put("used", maxOf(usedBytes, previousUsed))
                .put("status", status)
                .put("updated", System.currentTimeMillis() / 1000L),
        )
        val ok = patchGist(ctx.gistId, ctx.token, "usage.json", usage.toString())
        return if (ok) previousUsed else -1L
    }

    private fun fetchGist(gistId: String, ghToken: String): Pair<JSONObject, JSONObject>? {
        val request = Request.Builder()
            .url("https://api.github.com/gists/$gistId")
            .header("Authorization", "Bearer $ghToken")
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "FoxyVPN-Key")
            .get()
            .build()
        execute(request)?.use { resp ->
            if (resp.code != 200) return null
            val body = runCatching { JSONObject(resp.body?.string().orEmpty()) }.getOrNull() ?: return null
            val files = body.optJSONObject("files") ?: return null
            val registry = fileContent(files, "registry.json", ghToken)?.let { runCatching { JSONObject(it) }.getOrNull() }
            val usage = fileContent(files, "usage.json", ghToken)?.let { runCatching { JSONObject(it) }.getOrNull() }
            return Pair(registry ?: JSONObject(), usage ?: JSONObject().put("usages", JSONObject()))
        }
        return null
    }

    private fun fileContent(files: JSONObject, name: String, ghToken: String): String? {
        val file = files.optJSONObject(name) ?: return null
        if (file.optString("type") != "file") return null
        return runCatching {
            val url = file.optString("raw_url")
            if (url.isNotBlank()) {
                val req = Request.Builder().url(url)
                    .header("Authorization", "Bearer $ghToken").header("User-Agent", "FoxyVPN-Key").get().build()
                execute(req)?.use { r ->
                    if (r.code == 200) r.body?.string() else null
                }
            } else {
                file.optString("content").takeIf { it.isNotBlank() }
            }
        }.getOrNull()
    }

    private fun patchGist(gistId: String, ghToken: String, fileName: String, content: String): Boolean {
        val payload = JSONObject().put(
            "files",
            JSONObject().put(fileName, JSONObject().put("content", content)),
        )
        val request = Request.Builder()
            .url("https://api.github.com/gists/$gistId")
            .header("Authorization", "Bearer $ghToken")
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "FoxyVPN-Key")
            .patch(payload.toString().toRequestBody("application/json".toMediaType()))
            .build()
        execute(request)?.use { resp ->
            return resp.code in 200..299
        }
        return false
    }
}
