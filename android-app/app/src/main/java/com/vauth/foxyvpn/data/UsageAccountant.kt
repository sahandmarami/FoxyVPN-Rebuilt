package com.vauth.foxyvpn.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicLong

/**
 * Cumulative traffic accounting for the activated quota key.
 *
 * The native tunnel reports per-session totals that reset on reconnect, so
 * [observe] feeds monotonically increasing deltas into the persistent store.
 * Enforcement state (quota/time exhausted) is derived here and consumed by
 * FoxyVpnService before and during a session.
 */
object UsageAccountant {

    enum class BlockReason { NONE, QUOTA, EXPIRED, REVOKED }

    private var store: ActivatedKeyStore? = null
    private var key: QuotaKey? = null
    private val lastNativeTotal = AtomicLong(-1L)
    private val usedBytes = AtomicLong(0L)
    private val lastPersistAt = AtomicLong(0L)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile var blockReason: BlockReason = BlockReason.NONE
        private set
    @Volatile private var reporterContext: GistReporter.ReportContext? = null

    /** Last registry round trip: did it answer? Set by [refreshFromRegistryAsync]/service ticks. */
    @Volatile var lastRegistrySyncOk: Boolean = false
        private set
    @Volatile var lastRegistrySyncAtMs: Long = 0L
        private set

    fun attach(activatedKeyStore: ActivatedKeyStore, quotaKey: QuotaKey?) {
        store = activatedKeyStore
        key = quotaKey
        reporterContext = quotaKey?.let { GistReporter.contextFromKey(it) }
        val stored = activatedKeyStore.loadUsage()
        usedBytes.set(stored.usedBytes)
        lastNativeTotal.set(-1L)
        recomputeBlock(activatedKeyStore.nowMillis())
    }

    /**
     * Raises the counter to a value seen elsewhere (the distributor's gist);
     * used to resume a friend's usage after logout or a reinstall. Monotonic.
     */
    fun ingestExternalUsed(bytes: Long) {
        if (key == null || bytes <= 0L) return
        val current = usedBytes.get()
        if (bytes <= current) return
        usedBytes.set(bytes)
        store?.ingestExternalUsage(bytes)
        recomputeBlock(System.currentTimeMillis())
    }

    /**
     * Fire-and-forget: pull the usage this device last reported to the
     * distributor's gist and raise the local counter to it, so a friend who
     * signs out (or reinstalls the app) continues from where they were
     * instead of getting their volume from zero.
     */
    fun seedFromGistAsync() {
        val ctx = reporterContext ?: return
        scope.launch {
            runCatching { GistReporter.fetchReportedUsage(ctx) }
                .getOrNull()
                ?.let { ingestExternalUsed(it) }
        }
    }

    /**
     * One combined round trip against the registry that works even while the
     * VPN is off: learns about revocations (or re-activations), reports the
     * local usage and restores the counter from whatever the gist last saw.
     * Runs at app start, after key activation and whenever the UI returns to
     * the foreground — so a revoked key shows its banner immediately instead
     * of "working" until the next connect.
     */
    fun refreshFromRegistryAsync() {
        val ctx = reporterContext ?: return
        if (store == null) return
        scope.launch {
            val sync = runCatching {
                GistReporter.sync(
                    ctx = ctx,
                    usedBytes = usedBytes.get(),
                    limitBytes = limit,
                    expired = blockReason == BlockReason.EXPIRED,
                )
            }.getOrNull()
            lastRegistrySyncAtMs = System.currentTimeMillis()
            if (sync == null) {
                lastRegistrySyncOk = false
                return@launch
            }
            lastRegistrySyncOk = true
            when {
                sync.revoked || !sync.present -> {
                    if (!sync.present) {
                        AppLogger.w("UsageAccountant", "registry no longer lists this key; treating as revoked")
                    }
                    markRevoked()
                }
                sync.present -> {
                    clearRevocation()
                    if (sync.reportedUsedBytes > usedBytes.get()) {
                        ingestExternalUsed(sync.reportedUsedBytes)
                    }
                    if (sync.resetAtEpochSeconds > 0L) {
                        noteQuotaReset(sync.resetAtEpochSeconds)
                    }
                }
            }
        }
    }

    /** Called by the VPN service after each supervision tick. */
    fun noteRegistrySync(success: Boolean) {
        lastRegistrySyncOk = success
        lastRegistrySyncAtMs = System.currentTimeMillis()
    }

    fun reset() {
        store = null
        key = null
        reporterContext = null
        lastNativeTotal.set(-1L)
        usedBytes.set(0L)
        blockReason = BlockReason.NONE
        lastRegistrySyncOk = false
        lastRegistrySyncAtMs = 0L
    }

    fun keyAttached(): Boolean = key != null

    fun reporterContext(): GistReporter.ReportContext? = reporterContext

    val used: Long get() = usedBytes.get()
    val limit: Long get() = key?.payload?.limitBytes ?: 0L
    val expiresAt: Long get() = key?.payload?.exp ?: 0L

    /** Feed the current native session total (tx + rx). */
    fun observe(nativeTotalBytes: Long) {
        val current = key ?: return
        if (blockReason != BlockReason.NONE) return
        val prev = lastNativeTotal.getAndSet(nativeTotalBytes)
        val delta = when {
            prev < 0 -> nativeTotalBytes
            nativeTotalBytes >= prev -> nativeTotalBytes - prev
            else -> nativeTotalBytes // native counters reset: this is a fresh session
        }
        if (delta <= 0L) return
        val total = usedBytes.addAndGet(delta)
        val now = System.currentTimeMillis()
        val s = store ?: return
        if (now - lastPersistAt.get() > PERSIST_INTERVAL_MS) {
            lastPersistAt.set(now)
            s.saveUsage(total, now)
        }
        recomputeBlock(s.nowMillis())
        if (blockReason != BlockReason.NONE) {
            s.saveUsage(total, now)
            pushFinalStatus()
        }
    }

    fun recomputeBlock(nowMillis: Long) {
        val current = key ?: return
        // a key the registry once reported as revoked stays revoked forever,
        // even when the gist cannot be reached again
        if (store != null && current.keyId.isNotBlank() && store!!.isKeyRevoked(current.keyId)) {
            blockReason = BlockReason.REVOKED
            return
        }
        val limit = current.payload.limitBytes
        val exp = current.payload.exp
        blockReason = when {
            limit in 1..usedBytes.get() -> BlockReason.QUOTA
            exp in 1..(nowMillis / 1000L) -> BlockReason.EXPIRED
            else -> BlockReason.NONE
        }
    }

    fun markRevoked() {
        if (key == null) return
        blockReason = BlockReason.REVOKED
        // persist the verdict so restarts and offline reconnects honour it
        val id = key?.keyId
        if (!id.isNullOrBlank()) store?.markKeyRevoked(id)
        store?.saveUsage(usedBytes.get())
        pushFinalStatus()
    }

    /**
     * The registry now lists the key as active again (the distributor pressed
     * "فعال‌سازی دوباره") — drop the local revocation verdict.
     */
    fun clearRevocation() {
        val id = key?.keyId ?: return
        val s = store ?: return
        if (s.isKeyRevoked(id)) {
            s.clearKeyRevoked(id)
            if (blockReason == BlockReason.REVOKED) {
                blockReason = BlockReason.NONE
                recomputeBlock(System.currentTimeMillis())
            }
        }
    }

    /** Remembers when the account's monthly volume is re-granted. */
    fun noteQuotaReset(resetAtEpochSeconds: Long) {
        val id = key?.keyId ?: return
        if (resetAtEpochSeconds > 0L) store?.saveQuotaReset(id, resetAtEpochSeconds)
    }

    fun quotaResetAt(): Long {
        val id = key?.keyId ?: return 0L
        return store?.quotaResetEpochSeconds(id) ?: 0L
    }

    /** Best-effort live report for the distributor; never throws. */
    suspend fun reportNow(finalStatus: String? = null): Boolean {
        val ctx = reporterContext ?: return false
        val s = store ?: return false
        return GistReporter.reportUsage(
            ctx = ctx,
            usedBytes = usedBytes.get(),
            limitBytes = limit,
            expired = blockReason == BlockReason.EXPIRED,
            statusOverride = finalStatus,
        )
    }

    private fun pushFinalStatus() {
        val ctx = reporterContext ?: return
        val status = when (blockReason) {
            BlockReason.QUOTA -> "exhausted"
            BlockReason.EXPIRED -> "expired"
            BlockReason.REVOKED -> "revoked"
            else -> return
        }
        val used = usedBytes.get()
        val s = store
        scope.launch {
            runCatching {
                GistReporter.reportUsage(
                    ctx = ctx,
                    usedBytes = used,
                    limitBytes = limit,
                    expired = blockReason == BlockReason.EXPIRED,
                    statusOverride = status,
                )
            }
            s?.saveUsage(used)
        }
    }

    private const val PERSIST_INTERVAL_MS = 4_000L
}
