package com.foxy.keygen.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.foxy.keygen.data.model.RuntimeAuth
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "AccountVault"

/**
 * Stores several Firefox accounts so the distributor can mint keys from any
 * of them — every key then consumes the quota of the account it was minted
 * from. The tokens live in an encrypted preference file; the account that is
 * currently "active" is mirrored into [TokenStore] because FxaAuthRepository,
 * GuardianClient and the mint flow all operate on the active session.
 *
 * Concurrency contract (this is what kept the previous release broken):
 *  - while a *new* login is in flight the live TokenStore belongs to the
 *    account being signed in, NOT to the vault's active account — so
 *    [syncActiveFrom] must stay silent ([beginNewLogin]/[endNewLogin]).
 *  - the vault is the single source of truth; accounts are keyed by their
 *    real e-mail and never duplicated.
 */
class AccountVault(context: Context) {

    data class StoredAccount(
        val email: String,
        val accessToken: String,
        val refreshToken: String?,
        val expiresAtEpochSeconds: Long,
        val addedAtEpochSeconds: Long = 0L,
        /** True while the real e-mail could not be resolved yet. */
        val pendingIdentity: Boolean = false,
        /**
         * This account's Firefox session token, when the keygen signed in to
         * it — lets every key minted from this account get a FRESH dedicated
         * refresh token instead of sharing the account's own one.
         */
        val sessionToken: String? = null,
    )

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "foxykeygen_vault",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    /** True while a fresh (add-account) login owns the live TokenStore. */
    @Volatile
    var loginInProgress: Boolean = false
        private set

    /** E-mails whose FxA refresh was permanently rejected this session. */
    val brokenEmails = mutableSetOf<String>()

    val accounts: List<StoredAccount>
        get() = runCatching {
            val arr = JSONArray(prefs.getString(KEY_ACCOUNTS, "[]").orEmpty())
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                StoredAccount(
                    email = o.optString("email"),
                    accessToken = o.optString("access"),
                    refreshToken = o.optString("refresh").takeIf { it.isNotBlank() },
                    expiresAtEpochSeconds = o.optLong("expires"),
                    addedAtEpochSeconds = o.optLong("added"),
                    pendingIdentity = o.optBoolean("pending", false),
                    sessionToken = o.optString("session").takeIf { it.isNotBlank() },
                )
            }.let(::dedupe)
        }.getOrElse { emptyList() }

    var activeEmail: String
        get() = prefs.getString(KEY_ACTIVE, null).orEmpty()
        private set(value) { prefs.edit().putString(KEY_ACTIVE, value).apply() }

    fun activeAccount(): StoredAccount? =
        accounts.firstOrNull { it.email == activeEmail } ?: accounts.firstOrNull()

    val isEmpty: Boolean get() = accounts.isEmpty()

    fun beginNewLogin() { loginInProgress = true }
    fun endNewLogin() { loginInProgress = false }

    /**
     * Adds (or replaces) an account and makes it the active one. Replaces an
     * existing row with the same identity, so re-adding an account never
     * duplicates it.
     */
    fun upsert(account: StoredAccount) {
        val email = account.email.trim().lowercase()
        if (email.isBlank()) return
        val rest = accounts.filterNot { it.email == email }
        val updated = listOf(account.copy(email = email)) + rest
        persist(updated)
        if (email in brokenEmails) brokenEmails.remove(email)
        activeEmail = email
    }

    /** Replaces the stored tokens of [email] (e.g. after a refresh grant). */
    fun updateTokens(email: String, auth: RuntimeAuth, sessionToken: String? = null) {
        val email = email.trim().lowercase()
        val updated = accounts.map {
            if (it.email == email) it.copy(
                accessToken = auth.accessToken,
                refreshToken = auth.refreshToken ?: it.refreshToken,
                expiresAtEpochSeconds = auth.expiresAtEpochSeconds,
                sessionToken = sessionToken ?: it.sessionToken,
            ) else it
        }
        persist(updated)
    }

    fun setActive(email: String): Boolean {
        val email = email.trim().lowercase()
        if (accounts.none { it.email == email }) return false
        activeEmail = email
        return true
    }

    // ---------- per-account quota snapshots ----------

    data class QuotaSnapshot(
        val maxBytes: Long,
        val remainingBytes: Long,
        val resetAtEpochSeconds: Long,
        val updatedAtEpochSeconds: Long,
    )

    /**
     * Last quota numbers seen for [email]. The switcher shows this snapshot
     * the instant an account becomes active — so the card visibly changes with
     * the account — and refreshes it from Guardian in the background.
     */
    fun quotaSnapshot(email: String): QuotaSnapshot? {
        val e = email.trim().lowercase()
        val max = prefs.getLong("qs_max_$e", -1L)
        if (max < 0L) return null
        return QuotaSnapshot(
            maxBytes = max,
            remainingBytes = prefs.getLong("qs_rem_$e", 0L),
            resetAtEpochSeconds = prefs.getLong("qs_reset_$e", 0L),
            updatedAtEpochSeconds = prefs.getLong("qs_time_$e", 0L),
        )
    }

    fun saveQuotaSnapshot(email: String, maxBytes: Long, remainingBytes: Long, resetAtEpochSeconds: Long) {
        val e = email.trim().lowercase()
        if (e.isBlank() || maxBytes <= 0L) return
        prefs.edit()
            .putLong("qs_max_$e", maxBytes)
            .putLong("qs_rem_$e", remainingBytes.coerceAtLeast(0L))
            .putLong("qs_reset_$e", resetAtEpochSeconds)
            .putLong("qs_time_$e", System.currentTimeMillis() / 1000L)
            .apply()
    }

    fun remove(email: String) {
        val email = email.trim().lowercase()
        val rest = accounts.filterNot { it.email == email }
        persist(rest)
        brokenEmails.remove(email)
        if (activeEmail == email) {
            activeEmail = rest.firstOrNull()?.email.orEmpty()
        }
    }

    /**
     * The freshly fetched real e-mail for the account currently labelled
     * [currentEmail]: renames the row, merges it with any duplicate and keeps
     * the active pointer consistent.
     */
    fun applyRealEmail(currentEmail: String, realEmail: String) {
        val real = realEmail.trim().lowercase()
        if (real.isBlank()) return
        val current = currentEmail.trim().lowercase()
        val list = accounts
        val row = list.firstOrNull { it.email == current } ?: return
        if (row.email == real && !row.pendingIdentity) return
        val merged = row.copy(email = real, pendingIdentity = false)
        val updated = listOf(merged) + list.filterNot {
            it.email == current || it.email == real
        }
        persist(updated)
        if (activeEmail == current) activeEmail = real
    }

    /**
     * Finds which row owns [refreshToken]. Firefox rotates refresh tokens on
     * every grant, and a renewal that lands after the user switched accounts
     * used to be written into the *active* row — silently cross-wiring two
     * accounts so switching only changed the label. Token writes are now
     * identity-safe: renewed tokens always go back to the row whose refresh
     * token produced the grant.
     */
    fun rowEmailForRefreshToken(refreshToken: String?): String? {
        val rt = refreshToken?.trim().orEmpty()
        if (rt.isBlank()) return null
        return accounts.firstOrNull { it.refreshToken == rt }?.email
    }

    /**
     * Persists the live [TokenStore] session back into the row that actually
     * owns it (matched by the refresh token the grant was made with).
     * [usedRefreshToken] == null means a fresh interactive login, whose row is
     * created by the login flow itself — nothing to do here.
     */
    fun syncRefreshedTokens(usedRefreshToken: String?, tokenStore: TokenStore) {
        if (loginInProgress) return
        val owner = rowEmailForRefreshToken(usedRefreshToken) ?: return
        val auth = tokenStore.loadAuth() ?: return
        updateTokens(owner, auth)
    }

    fun markBroken(email: String) {
        val email = email.trim().lowercase()
        if (email.isNotBlank()) brokenEmails.add(email)
    }

    fun clearBroken(email: String) { brokenEmails.remove(email.trim().lowercase()) }

    fun isBroken(email: String): Boolean = brokenEmails.contains(email.trim().lowercase())

    /** Copies the tokens of [email] into the live [TokenStore]. */
    fun activateInto(tokenStore: TokenStore, email: String): Boolean {
        val account = accounts.firstOrNull { it.email == email.trim().lowercase() } ?: return false
        tokenStore.saveAuth(
            RuntimeAuth(
                accessToken = account.accessToken,
                refreshToken = account.refreshToken,
                expiresAtEpochSeconds = account.expiresAtEpochSeconds,
            ),
        )
        // the live session token must follow the account: a stale token of
        // another account must never mint keys for this one
        tokenStore.sessionToken = account.sessionToken
        activeEmail = account.email
        return true
    }

    /** Persists the (possibly refreshed) live session back into the vault. */
    fun syncActiveFrom(tokenStore: TokenStore) {
        if (loginInProgress) return // the live session belongs to a brand-new login
        val auth = tokenStore.loadAuth() ?: return
        val email = activeEmail.ifBlank { return }
        updateTokens(email, auth, tokenStore.sessionToken)
    }

    /**
     * One-time migration from the previous single-session storage so users of
     * the previous release keep their signed-in account without re-logging in.
     */
    fun migrateLegacySession(tokenStore: TokenStore) {
        if (accounts.isNotEmpty()) return
        val auth = tokenStore.loadAuth() ?: return
        if (auth.refreshToken.isNullOrBlank()) return
        upsert(
            StoredAccount(
                email = LEGACY_LABEL,
                accessToken = auth.accessToken,
                refreshToken = auth.refreshToken,
                expiresAtEpochSeconds = auth.expiresAtEpochSeconds,
                addedAtEpochSeconds = System.currentTimeMillis() / 1000,
                pendingIdentity = true,
            ),
        )
        AppLogger.i(TAG, "migrated the legacy single session into the vault")
    }

    /** Two rows pointing at the same identity keep the fresher tokens. */
    private fun dedupe(list: List<StoredAccount>): List<StoredAccount> {
        val seen = LinkedHashMap<String, StoredAccount>()
        list.forEach { row ->
            val prev = seen[row.email]
            if (prev == null || row.expiresAtEpochSeconds >= prev.expiresAtEpochSeconds) {
                seen[row.email] = row
            }
        }
        return seen.values.toList()
    }

    private fun persist(list: List<StoredAccount>) {
        val arr = JSONArray()
        list.forEach { a ->
            arr.put(
                JSONObject()
                    .put("email", a.email)
                    .put("access", a.accessToken)
                    .put("refresh", a.refreshToken.orEmpty())
                    .put("expires", a.expiresAtEpochSeconds)
                    .put("added", a.addedAtEpochSeconds)
                    .put("pending", a.pendingIdentity)
                    .put("session", a.sessionToken.orEmpty()),
            )
        }
        prefs.edit().putString(KEY_ACCOUNTS, arr.toString()).apply()
    }

    companion object {
        private const val KEY_ACCOUNTS = "accounts"
        private const val KEY_ACTIVE = "active_email"
        const val LEGACY_LABEL = "اکانت اصلی"
    }
}
