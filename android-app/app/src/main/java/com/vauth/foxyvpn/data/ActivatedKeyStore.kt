package com.vauth.foxyvpn.data

import android.content.Context
import org.json.JSONObject

/**
 * Persists the activated quota key and the cumulative usage counter.
 *
 * Usage survives logout and re-activation: every counter is written to a
 * per-key ledger (`foxyvpn_usage_ledger`, keyed by key id) that no sign-out
 * ever touches, plus the two historic mirror files for the active key. On
 * load the largest value wins, so deleting or editing one of them does not
 * reset the counter. A revocation tombstone and the monthly quota-reset
 * timestamp are kept in the ledger file as well, so a key that the
 * distributor has revoked stays revoked even when the gist cannot be
 * reached, and the client can show the recharge countdown offline.
 */
class ActivatedKeyStore(context: Context) {

    data class UsageState(
        val usedBytes: Long,
        val lastSeenClock: Long,
    )

    private val mainPrefs = context.getSharedPreferences("foxyvpn_key", Context.MODE_PRIVATE)
    private val mirrorPrefs = context.getSharedPreferences("foxyvpn_key_guard", Context.MODE_PRIVATE)
    private val ledgerPrefs = context.getSharedPreferences("foxyvpn_usage_ledger", Context.MODE_PRIVATE)

    var activatedKey: QuotaKey? = null
        private set

    private fun keyId(): String? = try {
        activatedKey?.keyId ?: loadKey()?.keyId
    } catch (e: Exception) {
        null
    }

    fun saveKey(key: QuotaKey) {
        val obj = JSONObject()
            .put("raw", key.raw)
            .put("payload", key.payload.id.let { QuotaKeyJson.encode(key) })
        val text = obj.toString()
        mainPrefs.edit().putString(KEY_BLOB, text).apply()
        mirrorPrefs.edit().putString(KEY_BLOB, text).apply()
        activatedKey = key
    }

    fun loadKey(): QuotaKey? {
        activatedKey = loadFrom(mainPrefs) ?: loadFrom(mirrorPrefs)
        return activatedKey
    }

    private fun loadFrom(prefs: android.content.SharedPreferences): QuotaKey? {
        val text = prefs.getString(KEY_BLOB, null) ?: return null
        return runCatching {
            val obj = JSONObject(text)
            val raw = obj.getString("raw")
            QuotaKeyCodec.parse(raw)
        }.onFailure { AppLogger.w(TAG, "stored key unreadable", it) }.getOrNull()
    }

    /**
     * Forgets the active key only. The per-key usage ledger, the revocation
     * tombstones and the reset timestamps deliberately survive, so re-adding
     * the same key resumes the counter instead of starting from zero.
     */
    fun clear() {
        mainPrefs.edit().clear().apply()
        mirrorPrefs.edit().clear().apply()
        activatedKey = null
    }

    // ---------- usage (per-key ledger + legacy mirrors) ----------

    fun loadUsage(): UsageState {
        val currentId = keyId()
        val mirror = loadMirrorUsage()
        if (currentId == null) return mirror
        val ledger = ledgerUsage(currentId)
        val best = if (mirror.usedBytes >= ledger.usedBytes) mirror else ledger
        return UsageState(best.usedBytes, maxOf(best.lastSeenClock, ledger.lastSeenClock, mirror.lastSeenClock))
    }

    private fun loadMirrorUsage(): UsageState {
        val a = readUsage(mainPrefs)
        val b = readUsage(mirrorPrefs)
        val best = if (a.usedBytes >= b.usedBytes) a else b
        return UsageState(best.usedBytes, maxOf(a.lastSeenClock, b.lastSeenClock))
    }

    private fun readUsage(prefs: android.content.SharedPreferences): UsageState = UsageState(
        usedBytes = prefs.getLong(KEY_USED, 0L).coerceAtLeast(0L),
        lastSeenClock = prefs.getLong(KEY_LAST_SEEN, 0L),
    )

    fun saveUsage(usedBytes: Long, nowMillis: Long = System.currentTimeMillis()) {
        val current = loadUsage()
        val used = maxOf(usedBytes, current.usedBytes)
        val clock = maxOf(nowMillis, current.lastSeenClock)
        writeUsage(mainPrefs, used, clock)
        writeUsage(mirrorPrefs, used, clock)
        keyId()?.let { saveLedgerUsage(it, used, clock) }
    }

    private fun writeUsage(prefs: android.content.SharedPreferences, used: Long, clock: Long) {
        prefs.edit().putLong(KEY_USED, used).putLong(KEY_LAST_SEEN, clock).apply()
    }

    private fun ledgerUsage(keyId: String): UsageState = UsageState(
        usedBytes = ledgerPrefs.getLong(KEY_LEDGER_USED + keyId, 0L).coerceAtLeast(0L),
        lastSeenClock = ledgerPrefs.getLong(KEY_LEDGER_CLOCK + keyId, 0L),
    )

    /** Monotonic: the ledger never goes backwards for a given key. */
    private fun saveLedgerUsage(keyId: String, usedBytes: Long, nowMillis: Long) {
        val current = ledgerUsage(keyId)
        val used = maxOf(usedBytes, current.usedBytes)
        val clock = maxOf(nowMillis, current.lastSeenClock)
        ledgerPrefs.edit()
            .putLong(KEY_LEDGER_USED + keyId, used)
            .putLong(KEY_LEDGER_CLOCK + keyId, clock)
            .apply()
    }

    /**
     * The monthly volume was re-granted: force every copy of the counter
     * (ledger + both mirrors) back to zero. Unlike [saveUsage] this is NOT
     * monotonic — a new period legitimately starts from 0 — and it stamps
     * [periodStart] so any stale previous-period number that shows up later
     * (a queued gist answer, an older device) can be recognised and dropped.
     */
    fun resetUsage(keyId: String, periodStartEpochSeconds: Long, nowMillis: Long = System.currentTimeMillis()) {
        writeUsage(mainPrefs, 0L, nowMillis)
        writeUsage(mirrorPrefs, 0L, nowMillis)
        ledgerPrefs.edit()
            .putLong(KEY_LEDGER_USED + keyId, 0L)
            .putLong(KEY_LEDGER_CLOCK + keyId, nowMillis)
            .putLong(KEY_PERIOD_START + keyId, periodStartEpochSeconds)
            .apply()
    }

    /** Epoch seconds of the monthly boundary this counter belongs to (0 = unknown). */
    fun periodStartEpochSeconds(keyId: String): Long =
        ledgerPrefs.getLong(KEY_PERIOD_START + keyId, 0L)

    /** Raises the stored counter for the active key (gist seeding). */
    fun ingestExternalUsage(usedBytes: Long) {
        val id = keyId() ?: return
        saveLedgerUsage(id, usedBytes, System.currentTimeMillis())
        if (id == keyId()) {
            val mirror = loadMirrorUsage()
            if (usedBytes > mirror.usedBytes) {
                writeUsage(mainPrefs, usedBytes, mirror.lastSeenClock)
                writeUsage(mirrorPrefs, usedBytes, mirror.lastSeenClock)
            }
        }
    }

    // ---------- revocation tombstone ----------

    /** A key the registry once reported as revoked stays dead — even offline. */
    fun markKeyRevoked(keyId: String) {
        ledgerPrefs.edit().putBoolean(KEY_REVOKED + keyId, true).apply()
    }

    fun isKeyRevoked(keyId: String): Boolean =
        ledgerPrefs.getBoolean(KEY_REVOKED + keyId, false)

    /** The distributor re-enabled the key — drop the tombstone. */
    fun clearKeyRevoked(keyId: String) {
        ledgerPrefs.edit().remove(KEY_REVOKED + keyId).apply()
    }

    // ---------- monthly quota reset timestamp ----------

    fun saveQuotaReset(keyId: String, resetAtEpochSeconds: Long) {
        if (resetAtEpochSeconds <= 0L) return
        ledgerPrefs.edit().putLong(KEY_RESET + keyId, resetAtEpochSeconds).apply()
    }

    fun quotaResetEpochSeconds(keyId: String): Long =
        ledgerPrefs.getLong(KEY_RESET + keyId, 0L)

    /** Effective "now", resistant to backwards clock changes. */
    fun nowMillis(): Long = maxOf(System.currentTimeMillis(), loadUsage().lastSeenClock)

    companion object {
        private const val TAG = "ActivatedKeyStore"
        private const val KEY_BLOB = "key_blob"
        private const val KEY_USED = "used_bytes"
        private const val KEY_LAST_SEEN = "last_seen_clock"
        private const val KEY_LEDGER_USED = "used_"
        private const val KEY_LEDGER_CLOCK = "clock_"
        private const val KEY_REVOKED = "revoked_"
        private const val KEY_RESET = "reset_"
        private const val KEY_PERIOD_START = "pstart_"
    }
}

private object QuotaKeyJson {
    fun encode(key: QuotaKey): String {
        val p = key.payload
        return org.json.JSONObject()
            .put("v", p.v)
            .put("name", p.name)
            .put("gb", p.gb)
            .put("mb", p.mb)
            .put("exp", p.exp)
            .put("id", p.id)
            .put("rt", "") // never persist the refresh token outside the encrypted TokenStore
            .put("gist", p.gist)
            .put("gt", "")
            .toString()
    }
}
