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
        /** True ONLY when a fully-read registry explicitly flags this key revoked. */
        val revoked: Boolean,
        /** True when the registry answered and contained this key. */
        val present: Boolean,
        val reported: Boolean,
        /** Usage another device (or an earlier session) last reported — for resuming. */
        val reportedUsedBytes: Long = 0L,
        /** "updated" timestamp of the usage entry that was read (unix seconds). */
        val reportedUpdatedAt: Long = 0L,
        /** Monthly quota-reset timestamp the distributor's keygen attached to this key. */
        val resetAtEpochSeconds: Long = 0L,
    )

    /**
     * What one gist read produced. [registry] is null when registry.json could
     * NOT actually be read (raw fetch failed, body truncated, JSON broken).
     * Distinguishing "read and empty" from "could not read" is what keeps a
     * flaky network from being mistaken for a revocation.
     */
    private data class GistSnapshot(
        val registry: JSONObject?,
        val usage: JSONObject,
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
            if (gist == null || gist.registry == null) {
                // gist unreachable OR registry.json unreadable: a transient
                // failure, never a verdict. Callers keep the session running
                // and retry on the next tick.
                AppLogger.d(TAG, "gist sync: registry not readable this tick (will retry)")
                return@withContext null
            }
            var revoked = false
            var present = false
            var resetAt = 0L
            gist.registry.optJSONArray("keys")?.let { keys ->
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
            val reported = patchUsage(gist.usage, ctx, usedBytes, status) >= 0
            if (!reported) AppLogger.d(TAG, "gist sync: usage patch failed (will retry)")
            val usageEntry = gist.usage.optJSONObject("usages")?.optJSONObject(ctx.keyId)
            SyncResult(
                revoked = revoked,
                present = present,
                reported = reported,
                reportedUsedBytes = usageEntry?.optLong("used", 0L) ?: 0L,
                reportedUpdatedAt = usageEntry?.optLong("updated", 0L) ?: 0L,
                resetAtEpochSeconds = resetAt,
            )
        } finally {
            inFlight.set(false)
        }
    }

    /**
     * Strict revocation verdict: true ONLY when a fully-read registry
     * explicitly carries revoked=true for this key. Every other outcome —
     * gist unreachable, registry.json unreadable, key not listed, parse
     * hiccups — is false. A partial read or a recreated gist must never
     * brick a valid key; that false positive is exactly what locked users
     * out with «این کلید غیرفعال شده است».
     */
    suspend fun isRevoked(ctx: ReportContext): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val snapshot = fetchGist(ctx.gistId, ctx.token) ?: return@runCatching false
            val registry = snapshot.registry ?: return@runCatching false
            val keys = registry.optJSONArray("keys") ?: return@runCatching false
            for (i in 0 until keys.length()) {
                val entry = keys.optJSONObject(i) ?: continue
                if (entry.optString("id") == ctx.keyId) {
                    return@runCatching entry.optBoolean("revoked", false)
                }
            }
            // the registry answered but does not list this key. That can mean
            // a deleted key — or a recreated/partial registry. Deletion has
            // its own explicit path (باطل‌کردن کلید), so absence is NOT
            // treated as revocation; the session simply stays unmanaged.
            AppLogger.d(TAG, "registry does not list this key; not treating absence as revocation")
            false
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
            gist.usage.optJSONObject("usages")?.optJSONObject(ctx.keyId)
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
            patchUsage(gist.usage, ctx, usedBytes, status) >= 0
        } finally {
            inFlight.set(false)
        }
    }

    /**
     * The monthly volume was re-granted: authoritatively zero this key's
     * usage entry. Unlike the regular monotonic patch this MAY lower the
     * stored value — the new period legitimately starts from 0 — and it
     * stamps [periodStartEpochSeconds] so older (previous-period) numbers
     * can be recognised and ignored when they show up again.
     */
    suspend fun pushPeriodReset(ctx: ReportContext, periodStartEpochSeconds: Long): Boolean =
        withContext(Dispatchers.IO) {
            if (!inFlight.compareAndSet(false, true)) return@withContext false
            try {
                val gist = fetchGist(ctx.gistId, ctx.token) ?: return@withContext false
                val usage = gist.usage
                val usages = usage.optJSONObject("usages") ?: JSONObject().also { usage.put("usages", it) }
                usages.put(
                    ctx.keyId,
                    JSONObject()
                        .put("used", 0L)
                        .put("status", "active")
                        .put("updated", System.currentTimeMillis() / 1000L)
                        .put("periodStart", periodStartEpochSeconds),
                )
                patchGist(ctx.gistId, ctx.token, "usage.json", usage.toString())
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

    private fun fetchGist(gistId: String, ghToken: String): GistSnapshot? {
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
            // registry == null means "could not actually read registry.json"
            // — a broken/unreachable raw fetch, NOT an empty registry.
            val registry = fileContent(files, "registry.json", ghToken)
                ?.let { runCatching { JSONObject(it) }.getOrNull() }
            val usage = fileContent(files, "usage.json", ghToken)?.let { runCatching { JSONObject(it) }.getOrNull() }
            return GistSnapshot(
                registry = registry,
                usage = usage ?: JSONObject().put("usages", JSONObject()),
            )
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
