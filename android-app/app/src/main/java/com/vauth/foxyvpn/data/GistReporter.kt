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
 *
 * دو اصل سخت این نسخه:
 *  ۱) گزارش مصرف هرگز به خواندن registry.json گره نخورده است — حتی وقتی
 *     registry ناخواناست، مصرف همچنان نوشته می‌شود (قبلاً همین گره، دلیل
 *     «بدون گزارش» ماندن کلیدساز بود).
 *  ۲) هر شکست دسته‌بندی می‌شود (توکن/مجوز/مخزن/شبکه/سقف درخواست) تا رابط
 *     کاربری دلیل واقعی را نشان دهد، نه همیشه «اینترنت را بررسی کنید».
 */
object GistReporter {

    private const val TAG = "GistReporter"

    /** Why a gist round trip failed. */
    enum class SyncIssue {
        NONE,          // everything worked
        NETWORK,       // unreachable on both routes (offline / blocked route)
        AUTH,          // HTTP 401 — the embedded token is invalid/expired/revoked
        FORBIDDEN,     // HTTP 403 — token lacks gist permission for this gist
        RATE_LIMITED,  // HTTP 403 with exhausted rate limit (or 429)
        NOT_FOUND,     // HTTP 404 — the gist does not exist (deleted/recreated)
    }

    /** Persian, user-facing one-liner for the last issue (empty when NONE). */
    fun issueLabel(issue: SyncIssue): String = when (issue) {
        SyncIssue.NONE -> ""
        SyncIssue.NETWORK -> "شبکه در دسترس نیست؛ با اتصال VPN دوباره تلاش می‌شود"
        SyncIssue.AUTH -> "توکن مخزن نامعتبر است — کلید جدید از کلیدساز بگیرید"
        SyncIssue.FORBIDDEN -> "توکن دسترسی Gist ندارد — در کلیدساز مخزن را دوباره وصل کنید"
        SyncIssue.RATE_LIMITED -> "سقف درخواست گیت‌هاب پر شده؛ کمی بعد تلاش می‌شود"
        SyncIssue.NOT_FOUND -> "مخزن گزارش پیدا نشد — کلید جدید از کلیدساز بگیرید"
    }

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

    // ---- channel health, consumed by the home-screen heartbeat ----------
    /** When a sync round last fully succeeded (usage written), unix ms. 0 = never. */
    @Volatile var lastSyncOkAtMs: Long = 0L
        private set
    /** Persian label of the last failure ("" when the last round was fine). */
    @Volatile var lastSyncIssueLabel: String = ""
        private set
    /** When the last round ended (success OR failure), unix ms. */
    @Volatile var lastSyncAttemptAtMs: Long = 0L
        private set

    private fun noteSuccess() {
        lastSyncOkAtMs = System.currentTimeMillis()
        lastSyncIssueLabel = ""
        lastSyncAttemptAtMs = lastSyncOkAtMs
    }

    private fun noteFailure(issue: SyncIssue) {
        lastSyncAttemptAtMs = System.currentTimeMillis()
        if (issue != SyncIssue.NONE) lastSyncIssueLabel = issueLabel(issue)
    }

    private var tunnelClient: OkHttpClient? = null
    private var tunnelClientPort: Int = 0

    /** Route that worked last time; keeps flapping between the two to a minimum. */
    @Volatile private var preferTunnel: Boolean = true

    private fun clientThroughTunnel(): OkHttpClient? {
        val port = tunnelSocksPort
        if (port <= 0) return null
        val existing = tunnelClient
        if (existing != null && tunnelClientPort == port) return existing
        val built = ControlPlaneHttp.client.newBuilder()
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .callTimeout(20, TimeUnit.SECONDS)
            .build()
        tunnelClient = built
        tunnelClientPort = port
        return built
    }

    /**
     * Executes a gist request over the remembered-good route first and falls
     * back to the other one. Returns null only when BOTH routes failed to
     * even produce a response (true network-level failure).
     */
    private fun execute(request: Request): Response? {
        val tunnel = clientThroughTunnel()
        val firstClient: OkHttpClient
        val secondClient: OkHttpClient?
        if (preferTunnel && tunnel != null) {
            firstClient = tunnel
            secondClient = ControlPlaneHttp.client
        } else {
            firstClient = ControlPlaneHttp.client
            secondClient = tunnel // null when the VPN is down
        }
        try {
            val resp = firstClient.newCall(request).execute()
            preferTunnel = tunnel != null && firstClient === tunnel
            return resp
        } catch (e: Exception) {
            AppLogger.d(TAG, "gist request on the primary route failed: ${e.message}")
        }
        if (secondClient != null) {
            try {
                val resp = secondClient.newCall(request).execute()
                preferTunnel = true
                return resp
            } catch (e: Exception) {
                AppLogger.d(TAG, "gist request on the fallback route failed: ${e.message}")
            }
        }
        return null
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
        /** False when the registry could not be read this round (unmanaged). */
        val registryReadable: Boolean,
        /** True when the usage entry was actually written to the gist. */
        val reported: Boolean,
        /** Usage another device (or an earlier session) last reported — for resuming. */
        val reportedUsedBytes: Long = 0L,
        /** "updated" timestamp of the usage entry that was read (unix seconds). */
        val reportedUpdatedAt: Long = 0L,
        /** Monthly quota-reset timestamp the distributor's keygen attached to this key. */
        val resetAtEpochSeconds: Long = 0L,
        /** Precise failure class when something did not work. */
        val issue: SyncIssue = SyncIssue.NONE,
    )

    /**
     * What one gist read produced. [registry] is null when registry.json could
     * NOT actually be read (raw fetch failed, body truncated, JSON broken).
     * Distinguishing "read and empty" from "could not read" keeps a flaky
     * network from being mistaken for a revocation — and since the usage
     * patch below no longer depends on the registry, an unreadable registry
     * only suspends revocation checks, never usage reporting.
     */
    private data class GistSnapshot(
        val registry: JSONObject?,
        val usage: JSONObject,
    )

    private class GistFetch(val snapshot: GistSnapshot?, val issue: SyncIssue, val detail: String)

    /**
     * One round trip that serves both directions of the dashboard:
     * reads the registry (revocation flag) and writes this device's usage.
     * Returns null ONLY when the gist itself was unreachable (offline) —
     * every other outcome is a classified [SyncResult].
     */
    suspend fun sync(
        ctx: ReportContext,
        usedBytes: Long,
        limitBytes: Long,
        expired: Boolean,
    ): SyncResult? = withContext(Dispatchers.IO) {
        if (!inFlight.compareAndSet(false, true)) return@withContext null
        try {
            val fetch = fetchGist(ctx.gistId, ctx.token)
            val gist = fetch.snapshot
            if (gist == null) {
                // the gist was not even read: offline / token / deleted gist
                AppLogger.d(TAG, "gist sync failed: ${fetch.issue} (${fetch.detail})")
                noteFailure(fetch.issue)
                return@withContext null
            }
            var revoked = false
            var present = false
            var resetAt = 0L
            var registryReadable = false
            gist.registry?.optJSONArray("keys")?.let { keys ->
                registryReadable = true
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
            val patchCode = patchUsage(gist.usage, ctx, usedBytes, status)
            val reported = patchCode in 200..299
            val issue = when {
                reported -> SyncIssue.NONE
                else -> classifyHttp(patchCode)
            }
            if (reported) {
                AppLogger.d(
                    TAG,
                    "gist sync ok: usage=${usedBytes}B, registryRead=${registryReadable}, revoked=$revoked",
                )
                noteSuccess()
            } else {
                AppLogger.d(TAG, "gist sync: usage patch failed HTTP=$patchCode")
                noteFailure(issue)
            }
            val usageEntry = gist.usage.optJSONObject("usages")?.optJSONObject(ctx.keyId)
            SyncResult(
                revoked = revoked,
                present = present,
                registryReadable = registryReadable,
                reported = reported,
                reportedUsedBytes = usageEntry?.optLong("used", 0L) ?: 0L,
                reportedUpdatedAt = usageEntry?.optLong("updated", 0L) ?: 0L,
                resetAtEpochSeconds = resetAt,
                issue = issue,
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
     * brick a valid key.
     */
    suspend fun isRevoked(ctx: ReportContext): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val fetch = fetchGist(ctx.gistId, ctx.token)
            val registry = fetch.snapshot?.registry ?: return@runCatching false
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
            val fetch = fetchGist(ctx.gistId, ctx.token)
            fetch.snapshot?.usage
                ?.optJSONObject("usages")?.optJSONObject(ctx.keyId)
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
            val fetch = fetchGist(ctx.gistId, ctx.token)
            val gist = fetch.snapshot ?: run {
                noteFailure(fetch.issue)
                return@withContext false
            }
            val status = statusOverride ?: when {
                expired -> "expired"
                limitBytes > 0 && usedBytes >= limitBytes -> "exhausted"
                else -> "active"
            }
            val code = patchUsage(gist.usage, ctx, usedBytes, status)
            if (code in 200..299) noteSuccess() else noteFailure(classifyHttp(code))
            code in 200..299
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
                val fetch = fetchGist(ctx.gistId, ctx.token)
                val gist = fetch.snapshot ?: return@withContext false
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
                patchGist(ctx.gistId, ctx.token, "usage.json", usage.toString()) in 200..299
            } finally {
                inFlight.set(false)
            }
        }

    /** Writes [usedBytes] into the usage map of [usageDoc] and patches the gist.
     *  Monotonic: a client never LOWERS the stored usage — a friend who just
     *  reinstalled (counter at 0) must not wipe the dashboard's real number.
     *  Returns the HTTP status of the patch (2xx = success, -1 = network). */
    private fun patchUsage(usageDoc: JSONObject, ctx: ReportContext, usedBytes: Long, status: String): Int {
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
        return patchGist(ctx.gistId, ctx.token, "usage.json", usage.toString())
    }

    private fun classifyHttp(code: Int): SyncIssue = when {
        code == 401 -> SyncIssue.AUTH
        code == 404 -> SyncIssue.NOT_FOUND
        code == 429 -> SyncIssue.RATE_LIMITED
        code == 403 -> SyncIssue.FORBIDDEN
        else -> SyncIssue.NETWORK
    }

    private fun fetchGist(gistId: String, ghToken: String): GistFetch {
        val request = Request.Builder()
            .url("https://api.github.com/gists/$gistId")
            .header("Authorization", "Bearer $ghToken")
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "FoxyVPN-Key")
            .get()
            .build()
        val resp = execute(request) ?: return GistFetch(null, SyncIssue.NETWORK, "no response on either route")
        resp.use {
            if (it.code != 200) {
                return GistFetch(null, classifyHttp(it.code), "HTTP ${it.code} on gist read")
            }
            val body = runCatching { JSONObject(it.body?.string().orEmpty()) }.getOrNull()
                ?: return GistFetch(null, SyncIssue.NETWORK, "gist response was not JSON")
            val files = body.optJSONObject("files")
                ?: return GistFetch(null, SyncIssue.NETWORK, "gist response had no files")
            // registry == null means "could not actually read registry.json"
            // — a broken/unreachable raw fetch, NOT an empty registry.
            val registry = fileContent(files, "registry.json", ghToken)
                ?.let { runCatching { JSONObject(it) }.getOrNull() }
            val usage = fileContent(files, "usage.json", ghToken)?.let { runCatching { JSONObject(it) }.getOrNull() }
            return GistFetch(
                GistSnapshot(
                    registry = registry,
                    usage = usage ?: JSONObject().put("usages", JSONObject()),
                ),
                SyncIssue.NONE,
                "ok",
            )
        }
    }

    /**
     * Reads a gist file. The gist API response ALREADY carries the file
     * content inline for small files, so the inline content is used FIRST —
     * the extra raw_url request (gist.githubusercontent.com, a different CDN
     * that is frequently unreachable from some networks) is only a fallback.
     */
    private fun fileContent(files: JSONObject, name: String, ghToken: String): String? {
        val file = files.optJSONObject(name) ?: return null
        if (file.optString("type") != "file") return null
        return runCatching {
            val inline = file.optString("content").orEmpty()
            if (inline.isNotBlank() && !file.optBoolean("truncated", false)) return@runCatching inline
            val url = file.optString("raw_url")
            if (url.isNotBlank()) {
                val req = Request.Builder().url(url)
                    .header("Authorization", "Bearer $ghToken").header("User-Agent", "FoxyVPN-Key").get().build()
                execute(req)?.use { r ->
                    if (r.code == 200) r.body?.string() else null
                }
            } else {
                inline.takeIf { it.isNotBlank() }
            }
        }.getOrNull()
    }

    /** PATCHes one file of the gist. Returns the HTTP status (2xx = ok, -1 = network). */
    private fun patchGist(gistId: String, ghToken: String, fileName: String, content: String): Int {
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
            return resp.code
        }
        return -1
    }
}
