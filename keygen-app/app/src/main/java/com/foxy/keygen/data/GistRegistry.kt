package com.foxy.keygen.data

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject

/**
 * Owner-side registry living in a private GitHub gist:
 *   registry.json -> written by this keygen (keys + revocations)
 *   usage.json    -> written by the FoxyVPN clients (live consumption)
 *
 * The two files are patched independently so keygen and clients never
 * overwrite each other.
 */
class GistRegistry(context: Context) {

    data class KeyRow(
        val id: String,
        val name: String,
        val gb: Long,
        val mb: Long = 0L,
        val exp: Long,
        val issuedAt: Long,
        val revoked: Boolean,
        val usedBytes: Long = 0L,
        val status: String = "",
        val updatedAt: Long = 0L,
        /** E-mail of the Firefox account whose quota this key consumes. */
        val acct: String = "",
        /** Next monthly volume re-grant (unix seconds) stamped by the keygen. */
        val reset: Long = 0L,
    ) {
        /** Total plan bytes: GB entries win, otherwise MB, otherwise unlimited (0). */
        val planBytes: Long
            get() = when {
                gb > 0L -> gb * 1_000_000_000L
                mb > 0L -> mb * 1_000_000L
                else -> 0L
            }
    }

    private val prefs = context.getSharedPreferences("foxykeygen_settings", Context.MODE_PRIVATE)

    var githubToken: String
        get() = prefs.getString(KEY_GH_TOKEN, null).orEmpty()
        set(value) = prefs.edit().putString(KEY_GH_TOKEN, value).apply()

    var gistId: String
        get() = prefs.getString(KEY_GIST_ID, null).orEmpty()
        set(value) = prefs.edit().putString(KEY_GIST_ID, value).apply()

    val isReady: Boolean get() = githubToken.isNotBlank() && gistId.isNotBlank()

    // ---------- lifecycle ----------

    /** Creates the private registry gist. Returns the gist id. */
    suspend fun createRegistry(): String = withContext(Dispatchers.IO) {
        val registry = JSONObject().put("keys", JSONArray())
        val usage = JSONObject().put("usages", JSONObject())
        val body = JSONObject()
            .put("description", "FoxyVPN key registry (private)")
            .put("public", false)
            .put(
                "files",
                JSONObject()
                    .put("registry.json", JSONObject().put("content", registry.toString()))
                    .put("usage.json", JSONObject().put("content", usage.toString())),
            )
        val request = Request.Builder()
            .url("https://api.github.com/gists")
            .header("Authorization", "Bearer $githubToken")
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "FoxyKeygen")
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .build()
        ControlPlaneHttp.client.newCall(request).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            if (resp.code !in 200..299) {
                throw Exception("ساخت مخزن گیت‌هاب ناموفق بود (HTTP ${resp.code}): ${text.take(300)}")
            }
            val id = JSONObject(text).optString("id")
            if (id.isBlank()) throw Exception("پاسخ گیت‌هاب فاقد شناسه بود")
            gistId = id
            id
        }
    }

    suspend fun validateToken(): Boolean = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("https://api.github.com/user")
            .header("Authorization", "Bearer $githubToken")
            .header("User-Agent", "FoxyKeygen")
            .get()
            .build()
        ControlPlaneHttp.client.newCall(request).execute().use { it.code == 200 }
    }

    // ---------- registry ----------

    suspend fun fetchRows(): List<KeyRow> = withContext(Dispatchers.IO) {
        if (!isReady) return@withContext emptyList()
        val gist = fetchGist(gistId, githubToken) ?: return@withContext emptyList()
        val registry = gist.first.optJSONArray("keys") ?: JSONArray()
        val usages = gist.second.optJSONObject("usages") ?: JSONObject()
        val rows = mutableListOf<KeyRow>()
        for (i in 0 until registry.length()) {
            val entry = registry.optJSONObject(i) ?: continue
            val id = entry.optString("id")
            val usage = usages.optJSONObject(id)
            rows.add(
                KeyRow(
                    id = id,
                    name = entry.optString("name"),
                    gb = entry.optLong("gb"),
                    mb = entry.optLong("mb"),
                    exp = entry.optLong("exp"),
                    issuedAt = entry.optLong("issued"),
                    revoked = entry.optBoolean("revoked", false),
                    usedBytes = usage?.optLong("used") ?: 0L,
                    status = usage?.optString("status").orEmpty(),
                    updatedAt = usage?.optLong("updated") ?: 0L,
                    acct = entry.optString("acct"),
                    reset = entry.optLong("reset", 0L),
                ),
            )
        }
        rows.sortedByDescending { it.issuedAt }
    }

    suspend fun addKey(row: KeyRow, mintingAccount: String = "", resetAtEpochSeconds: Long = 0L) = withContext(Dispatchers.IO) {
        val gist = fetchGist(gistId, githubToken) ?: throw Exception("خواندن مخزن ناموفق بود")
        val registry = gist.first
        val keys = registry.optJSONArray("keys") ?: JSONArray().also { registry.put("keys", it) }
        keys.put(
            JSONObject()
                .put("id", row.id)
                .put("name", row.name)
                .put("gb", row.gb)
                .put("mb", row.mb)
                .put("exp", row.exp)
                .put("issued", row.issuedAt)
                .put("revoked", false)
                .put("acct", mintingAccount)
                .put("reset", resetAtEpochSeconds),
        )
        patchFile("registry.json", registry.toString())
    }

    /**
     * Stamps the account's current monthly reset timestamp on every key minted
     * from [email]. The FoxyVPN client reads it during its gist sync and shows
     * «N روز تا شارژ دوبارهٔ حجم» even when the VPN has never been connected.
     * Called only when the value actually changes, so the gist is not hammered.
     */
    suspend fun updateResetsForAccount(email: String, resetAtEpochSeconds: Long) = withContext(Dispatchers.IO) {
        if (email.isBlank() || resetAtEpochSeconds <= 0L) return@withContext
        val gist = fetchGist(gistId, githubToken) ?: return@withContext
        val registry = gist.first
        val keys = registry.optJSONArray("keys") ?: JSONArray()
        var changed = false
        for (i in 0 until keys.length()) {
            val entry = keys.optJSONObject(i) ?: continue
            if (entry.optString("acct") == email && entry.optLong("reset", 0L) != resetAtEpochSeconds) {
                entry.put("reset", resetAtEpochSeconds)
                changed = true
            }
        }
        if (changed) patchFile("registry.json", registry.toString())
    }

    suspend fun setRevoked(keyId: String, revoked: Boolean) = withContext(Dispatchers.IO) {
        val gist = fetchGist(gistId, githubToken) ?: throw Exception("خواندن مخزن ناموفق بود")
        val registry = gist.first
        val keys = registry.optJSONArray("keys") ?: JSONArray()
        for (i in 0 until keys.length()) {
            val entry = keys.optJSONObject(i) ?: continue
            if (entry.optString("id") == keyId) {
                entry.put("revoked", revoked)
            }
        }
        patchFile("registry.json", registry.toString())
    }

    /**
     * Removes the key from the registry and its usage entry from usage.json,
     * so the row disappears from both the keygen and the client dashboards.
     */
    suspend fun deleteKey(keyId: String) = withContext(Dispatchers.IO) {
        val gist = fetchGist(gistId, githubToken) ?: throw Exception("خواندن مخزن ناموفق بود")
        // 1) drop the row from registry.json
        val registry = gist.first
        val keys = registry.optJSONArray("keys") ?: JSONArray()
        val kept = JSONArray()
        for (i in 0 until keys.length()) {
            val entry = keys.optJSONObject(i) ?: continue
            if (entry.optString("id") != keyId) kept.put(entry)
        }
        registry.put("keys", kept)
        if (!patchFile("registry.json", registry.toString())) {
            throw Exception("حذف کلید از مخزن ناموفق بود")
        }
        // 2) drop the usage entry (best effort)
        runCatching {
            val usage = gist.second
            val usages = usage.optJSONObject("usages") ?: JSONObject()
            if (usages.has(keyId)) {
                usages.remove(keyId)
                usage.put("usages", usages)
                patchFile("usage.json", usage.toString())
            }
        }
        Unit
    }

    private fun fetchGist(id: String, token: String): Pair<JSONObject, JSONObject>? =
        fetchGistDetailed(id, token).pair

    data class GistRead(val pair: Pair<JSONObject, JSONObject>?, val httpCode: Int)

    private fun fetchGistDetailed(id: String, token: String): GistRead {
        val request = Request.Builder()
            .url("https://api.github.com/gists/$id")
            .header("Authorization", "Bearer $token")
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "FoxyKeygen")
            .get()
            .build()
        ControlPlaneHttp.client.newCall(request).execute().use { resp ->
            if (resp.code != 200) return GistRead(null, resp.code)
            val body = runCatching { JSONObject(resp.body?.string().orEmpty()) }.getOrNull() ?: return GistRead(null, resp.code)
            val files = body.optJSONObject("files") ?: return GistRead(null, resp.code)
            val registry = readFile(files, "registry.json", token)?.let {
                runCatching { JSONObject(it) }.getOrNull()
            } ?: JSONObject().put("keys", JSONArray())
            val usage = readFile(files, "usage.json", token)?.let {
                runCatching { JSONObject(it) }.getOrNull()
            } ?: JSONObject().put("usages", JSONObject())
            return GistRead(Pair(registry, usage), resp.code)
        }
    }

    data class ConnectionCheck(
        /** GitHub login owning the token (null when the token itself is bad). */
        val login: String?,
        /** Whether the stored gist was actually readable just now. */
        val gistReadable: Boolean,
        /** Persian, display-ready failure reason (null = everything fine). */
        val error: String?,
        /** True ONLY when the gist read definitively failed with 404 (gist
         *  deleted / belongs to another account) — the only case where wiping
         *  the stored gist id and rebuilding the registry is safe. Network
         *  flakes and permission problems must NEVER trigger a rebuild. */
        val gistDead: Boolean = false,
    )

    /**
     * REAL end-to-end check of the reporting channel: token → identity → the
     * actual gist. The old setup flow only validated /user, so a token from a
     * different GitHub account, a token without gist permission or a deleted
     * gist all looked «متصل ✓» — and keys minted afterwards could never
     * report usage. This check refuses to say OK before a real gist read.
     */
    suspend fun checkConnection(): ConnectionCheck = withContext(Dispatchers.IO) {
        if (githubToken.isBlank()) {
            return@withContext ConnectionCheck(null, false, "اول توکن گیت‌هاب را وارد کنید")
        }
        // 1) token identity (catches expired/revoked tokens and rate limits)
        val login = runCatching {
            val request = Request.Builder()
                .url("https://api.github.com/user")
                .header("Authorization", "Bearer $githubToken")
                .header("User-Agent", "FoxyKeygen")
                .get()
                .build()
            ControlPlaneHttp.client.newCall(request).execute().use { resp ->
                when (resp.code) {
                    401 -> throw Exception("توکن گیت‌هاب نامعتبر است (منقضی یا باطل‌شده) — توکن جدید بسازید")
                    403 -> throw Exception("سقف درخواست گیت‌هاب پر شده؛ چند دقیقه بعد تلاش کنید")
                    !in 200..299 -> throw Exception("گیت‌هاب پاسخ ${resp.code} داد")
                }
                JSONObject(resp.body?.string().orEmpty()).optString("login").takeIf { it.isNotBlank() }
            }
        }.getOrElse { return@withContext ConnectionCheck(null, false, it.message ?: "اتصال به گیت‌هاب نشد") }
        if (login == null) {
            return@withContext ConnectionCheck(null, false, "پاسخ گیت‌هاب فاقد نام کاربری بود")
        }
        // 2) the gist itself (catches deleted gists and missing gist scope)
        if (gistId.isBlank()) {
            // nothing stored yet — token is fine, the setup flow will create the gist
            return@withContext ConnectionCheck(login, false, null)
        }
        val read = runCatching { fetchGistDetailed(gistId, githubToken) }.getOrElse {
            return@withContext ConnectionCheck(login, false, "خواندن مخزن ناموفق بود؛ اتصال اینترنت را بررسی کنید")
        }
        when {
            read.pair != null -> ConnectionCheck(login, true, null)
            read.httpCode == 404 -> ConnectionCheck(
                login, false,
                "مخزن گزارش پیدا نشد (حذف شده یا متعلق به حساب دیگری است) — «تست/بازسازی اتصال» را بزنید تا مخزن تازه ساخته شود",
                gistDead = true,
            )
            read.httpCode == 401 -> ConnectionCheck(login, false, "توکن گیت‌هاب نامعتبر است — توکن جدید بسازید")
            read.httpCode == 403 -> ConnectionCheck(
                login, false,
                "این توکن اجازهٔ خواندن Gist ندارد — موقع ساخت توکن، دسترسی gist را بدهید",
            )
            else -> ConnectionCheck(login, false, "گیت‌هاب پاسخ ${read.httpCode} داد")
        }
    }

    private fun readFile(files: JSONObject, name: String, token: String): String? {
        val file = files.optJSONObject(name) ?: return null
        return runCatching {
            // the gist API response already carries small file contents inline —
            // use that first; gist.githubusercontent.com (a different CDN that
            // some networks cannot reach) is only a fallback
            val inline = file.optString("content").orEmpty()
            if (inline.isNotBlank() && !file.optBoolean("truncated", false)) return@runCatching inline
            val url = file.optString("raw_url")
            if (url.isNotBlank()) {
                val req = Request.Builder().url(url)
                    .header("Authorization", "Bearer $token")
                    .header("User-Agent", "FoxyKeygen")
                    .get().build()
                ControlPlaneHttp.client.newCall(req).execute().use { r ->
                    if (r.code == 200) r.body?.string() else null
                }
            } else {
                inline.takeIf { it.isNotBlank() }
            }
        }.getOrNull()
    }

    private fun patchFile(fileName: String, content: String): Boolean {
        val payload = JSONObject().put(
            "files",
            JSONObject().put(fileName, JSONObject().put("content", content)),
        )
        val request = Request.Builder()
            .url("https://api.github.com/gists/$gistId")
            .header("Authorization", "Bearer $githubToken")
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "FoxyKeygen")
            .patch(payload.toString().toRequestBody("application/json".toMediaType()))
            .build()
        ControlPlaneHttp.client.newCall(request).execute().use { resp ->
            if (resp.code !in 200..299) throw Exception("به‌روزرسانی مخزن ناموفق بود (HTTP ${resp.code})")
            return true
        }
    }

    companion object {
        private const val KEY_GH_TOKEN = "github_token"
        private const val KEY_GIST_ID = "gist_id"
    }
}
