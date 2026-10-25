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
        SyncIssue.FORBIDDEN -> "گیت‌هاب نوشتن گزارش را رد کرد (۴۰۳) — در کلیدساز «تست نوشتن» را بزنید؛ اگر ادامه داشت مخزن تازه بسازید"
        SyncIssue.RATE_LIMITED -> "گیت‌هاب موقتاً نوشتن را بسته (سقف/سوءاستفاده) — بعد از چند دقیقه خودش تلاش می‌کند"
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

    // ---- write discipline -----------------------------------------------
    // GitHub flags gists that are PATCHed hundreds of times per hour as
    // abuse and then refuses ALL writes (HTTP 403) while reads keep working
    // — the «توکن دسترسی Gist ندارد» / «HTTP 403» storm. The old build
    // reported every 20s from EVERY device; now writes are deduped, gap-
    // limited and backed off exponentially so the channel never trips again.
    private class WriteState {
        @Volatile var lastWriteOkAtMs: Long = 0L
        @Volatile var lastWrittenUsed: Long = -1L
        @Volatile var cooldownUntilMs: Long = 0L
        @Volatile var backoffIndex: Int = 0
        @Volatile var lastWriteIssue: SyncIssue = SyncIssue.NONE
    }

    private val writeStates = java.util.concurrent.ConcurrentHashMap<String, WriteState>()

    private fun writeStateFor(keyId: String): WriteState = writeStates.getOrPut(keyId) { WriteState() }

    private val WRITE_BACKOFF_STEPS_MS =
        longArrayOf(5L, 15L, 45L, 90L).map { it * 60_000L }.toLongArray()

    /** Minimum gap between two successful usage writes of the same key. */
    private const val MIN_WRITE_GAP_MS = 3L * 60_000L
    /** Smallest usage delta that justifies an earlier write. */
    private const val WRITE_DELTA_BYTES = 512L * 1024L
    /** Idle connections still refresh their status at this cadence. */
    private const val IDLE_WRITE_HEARTBEAT_MS = 15L * 60_000L

    /** Whole-channel read cooldown (GET refused with 403/429 — primary limit). */
    @Volatile private var readCooldownUntilMs: Long = 0L
    @Volatile private var readBackoffIndex: Int = 0

    /**
     * When >0, regular usage patches pause until a successful period-reset
     * push zeroes the stored entry (monthly recharge) — otherwise the
     * monotonic patch would keep re-raising the previous month's number.
     */
    @Volatile var suspendPatchesForPeriodStartSec: Long = 0L

    /** Body of the last failed HTTP answer, for precise 403 classification. */
    @Volatile private var lastErrorBody: String = ""

    /** true = write now; false = skip (data already current or cooling down). */
    private fun shouldAttemptWrite(st: WriteState, usedBytes: Long, nowMs: Long): Boolean {
        if (st.lastWriteOkAtMs <= 0L) return true
        if (usedBytes < st.lastWrittenUsed) return true // a reset legitimately lowers it
        val changed = usedBytes - st.lastWrittenUsed >= WRITE_DELTA_BYTES
        val gapOver = nowMs - st.lastWriteOkAtMs >= MIN_WRITE_GAP_MS
        val heartbeat = nowMs - st.lastWriteOkAtMs >= IDLE_WRITE_HEARTBEAT_MS
        return (changed && gapOver) || heartbeat
    }

    /** Arms the exponential write cooldown after a refused write. */
    private fun armWriteBackoff(st: WriteState, httpCode: Int, nowMs: Long) {
        val idx = minOf(st.backoffIndex, WRITE_BACKOFF_STEPS_MS.size - 1)
        st.cooldownUntilMs = nowMs + WRITE_BACKOFF_STEPS_MS[idx]
        if (httpCode > 0) st.backoffIndex = minOf(st.backoffIndex + 1, WRITE_BACKOFF_STEPS_MS.size)
        if (httpCode == -1) {
            // network-level failure: a short cooldown, not the abuse ladder
            st.cooldownUntilMs = nowMs + 2L * 60_000L
        }
    }

    private fun writeIssueWhileCooling(st: WriteState): SyncIssue =
        st.lastWriteIssue.takeIf { it != SyncIssue.NONE } ?: SyncIssue.RATE_LIMITED

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
            if (System.currentTimeMillis() < readCooldownUntilMs) return@withContext null
            val fetch = fetchGist(ctx.gistId, ctx.token)
            val gist = fetch.snapshot
            if (gist == null) {
                // the gist was not even read: offline / token / deleted gist
                AppLogger.d(TAG, "gist sync failed: ${fetch.issue} (${fetch.detail})")
                if (fetch.issue == SyncIssue.RATE_LIMITED) {
                    val idx = minOf(readBackoffIndex, WRITE_BACKOFF_STEPS_MS.size - 1)
                    readCooldownUntilMs = System.currentTimeMillis() + WRITE_BACKOFF_STEPS_MS[idx]
                    readBackoffIndex++
                    AppLogger.d(TAG, "gist reads refused; cooling down ${WRITE_BACKOFF_STEPS_MS[idx] / 60_000L} min")
                }
                noteFailure(fetch.issue)
                return@withContext null
            }
            readBackoffIndex = 0
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
            val st = writeStateFor(ctx.keyId)
            val nowMs = System.currentTimeMillis()
            var reported: Boolean
            var issue: SyncIssue
            when {
                suspendPatchesForPeriodStartSec > 0L -> {
                    // a monthly reset is being pushed separately; a regular
                    // patch would only re-raise the old number
                    reported = true
                    issue = SyncIssue.NONE
                    AppLogger.d(TAG, "usage patch paused while the period reset is being pushed")
                }
                nowMs < st.cooldownUntilMs -> {
                    reported = false
                    issue = writeIssueWhileCooling(st)
                    AppLogger.d(TAG, "usage write in cooldown for another ${(st.cooldownUntilMs - nowMs) / 60_000L} min")
                }
                shouldAttemptWrite(st, usedBytes, nowMs) -> {
                    val patchCode = patchUsage(gist.usage, ctx, usedBytes, status)
                    if (patchCode in 200..299) {
                        st.lastWriteOkAtMs = nowMs
                        st.lastWrittenUsed = usedBytes
                        st.backoffIndex = 0
                        reported = true
                        issue = SyncIssue.NONE
                    } else {
                        issue = classifyHttp(patchCode)
                        st.lastWriteIssue = issue
                        armWriteBackoff(st, patchCode, nowMs)
                        reported = false
                        AppLogger.d(TAG, "gist sync: usage patch failed HTTP=$patchCode")
                    }
                }
                else -> {
                    // the dashboard already holds a current-enough number —
                    // a healthy no-op, NOT a failure
                    reported = true
                    issue = SyncIssue.NONE
                }
            }
            if (reported) {
                AppLogger.d(
                    TAG,
                    "gist sync ok: usage=${usedBytes}B, registryRead=${registryReadable}, revoked=$revoked",
                )
                noteSuccess()
            } else {
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
            if (System.currentTimeMillis() < readCooldownUntilMs) return@runCatching false
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
            if (System.currentTimeMillis() < readCooldownUntilMs) return@runCatching null
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
        force: Boolean = false,
    ): Boolean = withContext(Dispatchers.IO) {
        if (!inFlight.compareAndSet(false, true)) return@withContext false
        try {
            val st = writeStateFor(ctx.keyId)
            val nowMs = System.currentTimeMillis()
            if (nowMs < readCooldownUntilMs) return@withContext false
            if (nowMs < st.cooldownUntilMs && !force && statusOverride == null) {
                // final statuses (exhausted/revoked/expired) always try —
                // they are rare and matter more than the cooldown
                noteFailure(writeIssueWhileCooling(st))
                return@withContext false
            }
            if (
                !force && statusOverride == null && suspendPatchesForPeriodStartSec <= 0L &&
                !shouldAttemptWrite(st, usedBytes, nowMs)
            ) {
                // nothing new to tell the dashboard
                return@withContext true
            }
            if (force && suspendPatchesForPeriodStartSec > 0L && statusOverride == null) {
                // never overwrite a pending period reset with the old number
                return@withContext true
            }
            val fetch = fetchGist(ctx.gistId, ctx.token)
            val gist = fetch.snapshot ?: run {
                noteFailure(fetch.issue)
                return@withContext false
            }
            readBackoffIndex = 0
            val status = statusOverride ?: when {
                expired -> "expired"
                limitBytes > 0 && usedBytes >= limitBytes -> "exhausted"
                else -> "active"
            }
            val code = patchUsage(gist.usage, ctx, usedBytes, status)
            if (code in 200..299) {
                st.lastWriteOkAtMs = System.currentTimeMillis()
                st.lastWrittenUsed = usedBytes
                st.backoffIndex = 0
                noteSuccess()
            } else {
                st.lastWriteIssue = classifyHttp(code)
                armWriteBackoff(st, code, nowMs)
                noteFailure(st.lastWriteIssue)
            }
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
                if (System.currentTimeMillis() < readCooldownUntilMs) return@withContext false
                val fetch = fetchGist(ctx.gistId, ctx.token)
                val gist = fetch.snapshot ?: return@withContext false
                readBackoffIndex = 0
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
                val code = patchGist(ctx.gistId, ctx.token, "usage.json", usage.toString())
                if (code in 200..299) {
                    // the stored entry is zeroed - regular patches may resume
                    suspendPatchesForPeriodStartSec = 0L
                    val st = writeStateFor(ctx.keyId)
                    st.lastWriteOkAtMs = System.currentTimeMillis()
                    st.lastWrittenUsed = 0L
                    st.backoffIndex = 0
                    noteSuccess()
                    true
                } else {
                    val st = writeStateFor(ctx.keyId)
                    st.lastWriteIssue = classifyHttp(code)
                    armWriteBackoff(st, code, System.currentTimeMillis())
                    noteFailure(st.lastWriteIssue)
                    false
                }
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
        code == 403 -> {
            val low = lastErrorBody.lowercase()
            val transient = listOf("abuse", "secondary", "rate limit", "temporarily", "retry").any { it in low }
            if (transient) SyncIssue.RATE_LIMITED else SyncIssue.FORBIDDEN
        }
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
                lastErrorBody = runCatching { it.body?.string().orEmpty() }.getOrDefault("")
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
            val code = resp.code
            if (code !in 200..299) {
                lastErrorBody = runCatching { resp.body?.string().orEmpty() }.getOrDefault("")
            } else {
                lastErrorBody = ""
            }
            return code
        }
        return -1
    }
}
