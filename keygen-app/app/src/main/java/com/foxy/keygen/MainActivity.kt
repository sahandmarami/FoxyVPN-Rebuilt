package com.foxy.keygen

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Logout
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.foxy.keygen.BuildConfig
import com.foxy.keygen.data.AccountVault
import com.foxy.keygen.data.ControlPlaneHttp
import com.foxy.keygen.data.FaFormat
import com.foxy.keygen.data.FxaApiError
import com.foxy.keygen.data.FxaAuthRepository
import com.foxy.keygen.data.GistRegistry
import com.foxy.keygen.data.QuotaKeyCodec
import com.foxy.keygen.data.formatBytesBinary
import com.foxy.keygen.ui.KeygenTheme
import com.foxy.keygen.ui.fieldColors
import com.foxy.keygen.ui.rememberKeygenAccent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val app = application as KeygenApp
        setContent {
            KeygenTheme {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    KeygenRoot(app)
                }
            }
        }
    }
}

@Composable
fun KeygenRoot(app: KeygenApp) {
    var loggedIn by remember { mutableStateOf(app.tokenStore.hasStoredSession()) }
    var loginModeIsAdd by remember { mutableStateOf(false) }
    var accountsVersion by remember { mutableIntStateOf(0) }
    if (!loggedIn) {
        LoginScreen(app, addMode = loginModeIsAdd, onSignedIn = { loggedIn = true; accountsVersion++ })
    } else {
        HomeScreen(
            app,
            accountsVersion,
            onAccountsChanged = { accountsVersion++ },
            onAddAccount = { loginModeIsAdd = true; loggedIn = false },
            onSignOutActive = {
                val active = app.accountVault.activeAccount()
                if (active != null) app.accountVault.remove(active.email)
                app.tokenStore.clear()
                val next = app.accountVault.activeAccount()
                if (next != null) {
                    app.accountVault.activateInto(app.tokenStore, next.email)
                } else {
                    loginModeIsAdd = false
                    loggedIn = false
                }
                accountsVersion++
            },
        )
    }
}

// ---------------- login ----------------

/**
 * Persian, actionable mapping of the FxA failure classes — errno numbers are
 * Firefox Accounts' own codes (api.accounts.firefox.com responses).
 */
private fun fxaLoginErrorFa(e: Throwable): String {
    if (e is FxaApiError) {
        return when {
            e.errno == 102 -> "با این ایمیل حسابی در Mozilla ثبت نشده — اول در accounts.firefox.com اکانت بساز، بعد وارد شو"
            e.errno == 103 -> "رمز عبور اشتباه است"
            e.errno == 104 -> "ایمیل این اکانت هنوز تأیید نشده — ایمیل Mozilla را باز کن و لینک «تأیید حساب» را بزن، بعد دوباره وارد شو"
            e.errno == 114 || e.statusCode == 429 -> "تلاش‌های ورود زیاد بوده — چند دقیقه صبر کن و دوباره امتحان کن"
            e.errno == 125 -> "Mozilla این درخواست را به دلایل امنیتی بلاک کرد — کمی بعد، یا با اینترنت دیگری امتحان کن"
            e.errno == 201 -> "سرور Mozilla در دسترس نیست — کمی بعد دوباره"
            e.statusCode != null -> "خطای سرور Mozilla (HTTP ${e.statusCode}): ${e.message?.take(140)}"
            else -> "ورود ناموفق بود: ${e.message?.take(140)}"
        }
    }
    val msg = e.message.orEmpty()
    return when {
        msg.contains("timeout", true) || msg.contains("Unable to resolve", true) || msg.contains("Failed to connect", true) || msg.contains("Network", true) ->
            "اتصال به سرور Mozilla برقرار نشد — اینترنت را بررسی کنید"
        else -> msg.take(240).ifBlank { "ورود ناموفق بود" }
    }
}

@Composable
private fun LoginScreen(app: KeygenApp, addMode: Boolean = false, onSignedIn: () -> Unit) {
    val accent = rememberKeygenAccent()
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var needCode by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var resending by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFFF6F8FB))
            .verticalScroll(rememberScrollState())
            .imePadding()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            modifier = Modifier
                .size(76.dp)
                .clip(CircleShape)
                .background(accent),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Filled.VpnKey, contentDescription = null, tint = Color.White, modifier = Modifier.size(36.dp))
        }
        Spacer(Modifier.height(16.dp))
        Text("FoxyKeygen", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Color(0xFF17222C))
        Text(
            if (addMode) "اکانت فایرفاکس دیگری را برای ساخت کلید با سهمیهٔ آن وارد کنید"
            else "برای ساخت کلید، با حساب فایرفاکس خود وارد شوید",
            fontSize = 13.sp,
            color = Color(0xFF67737F),
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))

        OutlinedTextField(
            value = email, onValueChange = { email = it; error = null },
            label = { Text("ایمیل فایرفاکس") },
            modifier = Modifier.fillMaxWidth(), singleLine = true,
            shape = RoundedCornerShape(14.dp),
            colors = fieldColors(accent), enabled = !busy,
        )
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(
            value = password, onValueChange = { password = it; error = null },
            label = { Text("رمز عبور") },
            modifier = Modifier.fillMaxWidth(), singleLine = true,
            shape = RoundedCornerShape(14.dp),
            colors = fieldColors(accent), enabled = !busy,
        )
        if (needCode) {
            Spacer(Modifier.height(10.dp))
            val unverifiedAccount = app.authRepository.lastVerificationReason == "account"
            Text(
                if (unverifiedAccount)
                    "ایمیل اکانتت را باز کن — Mozilla ایمیل «تأیید حساب» فرستاده؛ لینک داخلش را بزن و برگرد، یا کدش را همین‌جا وارد کن"
                else
                    "کد تایید ارسال‌شده به ایمیل را وارد کن",
                fontSize = 12.sp,
                color = Color(0xFF67737F),
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = code, onValueChange = { code = it; error = null },
                label = { Text("کد تایید ارسال‌شده به ایمیل") },
                modifier = Modifier.fillMaxWidth(), singleLine = true,
                shape = RoundedCornerShape(14.dp),
                colors = fieldColors(accent), enabled = !busy,
            )
            TextButton(onClick = {
                if (resending) return@TextButton
                resending = true
                scope.launch {
                    val r = app.authRepository.resendVerificationEmail()
                    resending = false
                    r.onSuccess { error = "ایمیل دوباره فرستاده شد — صندوق دریافتی (و پوشهٔ Spam) را چک کن" }
                        .onFailure { error = "ارسال دوباره ناموفق بود: ${it.message?.take(120)}" }
                }
            }, enabled = !resending) {
                Text(if (resending) "در حال ارسال…" else "ایمیل نرسید؟ ارسال دوباره", fontSize = 12.sp)
            }
        }
        error?.let {
            Spacer(Modifier.height(10.dp))
            Text(it, color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
        }
        Spacer(Modifier.height(18.dp))
        Button(
            onClick = {
                busy = true; error = null
                scope.launch {
                    // while the fresh login owns the live TokenStore, the vault
                    // must NOT mirror it into the previously active account —
                    // that is what swapped the two accounts' tokens in v1.2.0
                    app.accountVault.beginNewLogin()
                    try {
                        if (needCode) {
                            app.authRepository.submitTwoFactorCode(code).getOrThrow()
                        } else {
                            val needsTwoFactor = app.authRepository.startLogin(email, password).getOrThrow()
                            if (needsTwoFactor) {
                                needCode = true
                                busy = false
                                app.accountVault.endNewLogin()
                                return@launch
                            }
                        }
                        // record the account in the multi-account vault
                        val auth = app.tokenStore.loadAuth()
                        // brand-new accounts are provisioned by the main app's
                        // connect path; an account added straight into the
                        // keygen never went through that step — activate its
                        // Guardian entitlement here so the quota card works
                        if (auth?.accessToken?.isNotBlank() == true) {
                            runCatching {
                                app.guardianClient.activateGuardian(KeygenApp.GUARDIAN_ENDPOINT, auth.accessToken)
                            }
                        }
                        val realEmail = auth?.let { fetchFxaProfileEmail(it.accessToken) }
                        val identity = realEmail
                            ?: FxaAuthRepository.normalizeEmail(email).takeIf { it.isNotBlank() }
                        val label = identity
                            ?: "اکانت ${app.accountVault.accounts.size + 1}"
                        app.accountVault.upsert(
                            AccountVault.StoredAccount(
                                email = label,
                                accessToken = auth?.accessToken.orEmpty(),
                                refreshToken = auth?.refreshToken,
                                expiresAtEpochSeconds = auth?.expiresAtEpochSeconds ?: 0L,
                                addedAtEpochSeconds = System.currentTimeMillis() / 1000L,
                                pendingIdentity = identity == null,
                                // the new account's Firefox session travels with
                                // it, so keys minted from it get fresh tokens
                                sessionToken = app.tokenStore.sessionToken,
                            ),
                        )
                        app.accountVault.endNewLogin()
                        onSignedIn()
                    } catch (c: CancellationException) {
                        app.accountVault.endNewLogin()
                        throw c
                    } catch (e: Exception) {
                        app.accountVault.endNewLogin()
                        error = fxaLoginErrorFa(e)
                    } finally {
                        busy = false
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = accent),
            enabled = !busy,
        ) {
            if (busy) CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = Color.White)
            else Text("ورود", fontSize = 16.sp, fontWeight = FontWeight.Bold)
        }
    }
}

/**
 * Activates [email] in the vault and revives its stored FxA session before
 * any screen keeps using it. Returns null on success or a Persian error.
 */
suspend fun switchAccount(app: KeygenApp, email: String): String? {
    return withContext(Dispatchers.IO) {
        if (!app.accountVault.activateInto(app.tokenStore, email)) {
            return@withContext "این اکانت در لیست نیست"
        }
        val status = try {
            app.authRepository.restoreSession()
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            com.foxy.keygen.data.AppLogger.w("AccountSwitch", "restore failed for $email", e)
            null
        }
        when (status) {
            // ok: the live session belongs to this account now
            com.foxy.keygen.data.SessionStatus.ACTIVE -> {
                app.accountVault.clearBroken(email)
                app.accountVault.syncActiveFrom(app.tokenStore)
                null
            }
            com.foxy.keygen.data.SessionStatus.UNREACHABLE -> null // keep the account; tokens may still work
            else -> {
                // the stored session of this account is dead — the user must
                // sign in to it again; stay on it so the fresh login lands here
                app.accountVault.markBroken(email)
                "نشست این اکانت باطل شده است؛ دوباره واردش شوید"
            }
        }
    }
}

// ---------------- home ----------------

@Composable
private fun HomeScreen(
    app: KeygenApp,
    accountsVersion: Int,
    onAccountsChanged: () -> Unit,
    onAddAccount: () -> Unit,
    onSignOutActive: () -> Unit,
) {
    val accent = rememberKeygenAccent()
    val scope = rememberCoroutineScope()
    var tab by remember { mutableIntStateOf(0) }
    var menuOpen by remember { mutableStateOf(false) }
    var switching by remember { mutableStateOf(false) }
    var switchError by remember { mutableStateOf<String?>(null) }

    val accounts = remember(accountsVersion) { app.accountVault.accounts }
    val activeEmail = remember(accountsVersion) { app.accountVault.activeAccount()?.email.orEmpty() }

    Scaffold(
        containerColor = Color(0xFFF6F8FB),
        topBar = {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.VpnKey, contentDescription = null, tint = accent, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(10.dp))
                Column {
                    Text("FoxyKeygen", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = Color(0xFF17222C))
                    // visible version so «کدام نسخه نصب است؟» همیشه روی صفحه جواب دارد
                    Text("v" + BuildConfig.VERSION_NAME, fontSize = 10.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF97A1AC))
                }
                Spacer(Modifier.weight(1f))
                // ---- account switcher ----
                Box {
                    OutlinedButton(
                        onClick = { menuOpen = true },
                        shape = RoundedCornerShape(50),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF17222C)),
                        enabled = !switching,
                    ) {
                        if (switching) {
                            CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp, color = accent)
                        } else {
                            Icon(Icons.Filled.People, contentDescription = null, modifier = Modifier.size(16.dp), tint = accent)
                            Spacer(Modifier.width(6.dp))
                            Text(
                                // the vault is deduped now, so this count is honest
                                if (accounts.size > 1) "${FaFormat.faDigits(accounts.size)} اکانت"
                                else (activeEmail.ifBlank { "اکانت" }).take(22),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        accounts.forEach { account ->
                            DropdownMenuItem(
                                text = {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Column {
                                            Text(
                                                account.email,
                                                fontSize = 12.sp,
                                                fontWeight = if (account.email == activeEmail) FontWeight.Bold else FontWeight.Normal,
                                            )
                                            if (app.accountVault.isBroken(account.email)) {
                                                Text(
                                                    "نشست باطل شده — دوباره وارد شوید",
                                                    fontSize = 10.sp,
                                                    color = Color(0xFFB72749),
                                                )
                                            }
                                        }
                                        Spacer(Modifier.weight(1f))
                                        if (account.email == activeEmail) {
                                            Icon(Icons.Filled.Check, contentDescription = "فعال", tint = accent, modifier = Modifier.size(16.dp))
                                        }
                                    }
                                },
                                onClick = {
                                    menuOpen = false
                                    if (account.email != activeEmail && !switching) {
                                        switching = true
                                        switchError = null
                                        scope.launch {
                                            switchError = switchAccount(app, account.email)
                                            switching = false
                                            onAccountsChanged()
                                        }
                                    }
                                },
                            )
                        }
                        HorizontalDivider()
                        DropdownMenuItem(
                            text = { Text("افزودن اکانت جدید", fontSize = 12.sp) },
                            leadingIcon = { Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(16.dp), tint = accent) },
                            onClick = { menuOpen = false; onAddAccount() },
                        )
                        DropdownMenuItem(
                            text = { Text("خروج از اکانت فعال", fontSize = 12.sp) },
                            leadingIcon = { Icon(Icons.Filled.Logout, contentDescription = null, modifier = Modifier.size(16.dp), tint = Color(0xFFB72749)) },
                            onClick = { menuOpen = false; onSignOutActive() },
                        )
                    }
                }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding)) {
            AccountQuotaCard(app, accountsVersion, switchError)
            TabRow(
                selectedTabIndex = tab,
                containerColor = Color.Transparent,
                modifier = Modifier.padding(horizontal = 16.dp),
            ) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("ساخت کلید") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("کلیدهای من") })
            }
            when (tab) {
                0 -> IssueTab(app, accountsVersion)
                else -> KeysTab(app, accountsVersion)
            }
        }
    }
}

/**
 * One honest Persian line per failure class — including what Mozilla itself
 * answered (status code + its own message), so a blocked/refused fresh
 * account is never mistaken for «اینترنت نداری».
 */
private fun describeQuotaFailure(failure: Throwable): String {
    val status = (failure as? com.foxy.keygen.data.GuardianHttpError)?.statusCode
    val raw = failure.message?.take(160).orEmpty()
    return when {
        failure is com.foxy.keygen.data.TokenInvalidError ->
            "نشست این اکانت را Mozilla قبول نکرد — اکانت را حذف و دوباره وارد کنید"
        failure is com.foxy.keygen.data.QuotaExceededError ->
            "سهمیهٔ این اکانت توسط Mozilla مسدود شده — کمی بعد دوباره"
        status == 401 ->
            "نشست اکانت منقضی شده (۴۰۱) — اکانت را دوباره وارد کنید"
        status == 402 ->
            "Mozilla برای این اکانت سهمیه‌ای ثبت نکرده (۴۰۲) — اکانت تازه‌ساخت است؛ یک‌بار در اپ اصلی وصل شوید تا فعال شود"
        status == 403 ->
            "Mozilla این درخواست را نپذیرفت (۴۰۳) — اکانت تازه است یا موقتاً محدود شده: $raw"
        status == 404 ->
            "سرویس سهمیهٔ Mozilla برای این اکانت پیدا نشد (۴۰۴): $raw"
        status == 429 ->
            "درخواست‌های زیاد (۴۲۹) — چند دقیقه بعد خودش دوباره تلاش می‌کند"
        status != null ->
            "خطای سرویس Mozilla (HTTP $status): $raw"
        else ->
            "اتصال به سرویس Mozilla برقرار نشد — اینترنت را بررسی کنید"
    }
}

/**
 * Does this usage report belong to the CURRENT monthly period?
 *
 * The registry's `reset` field carries the NEXT quota-reset moment (v2.4.x
 * stamps Mozilla's future X-Quota-Reset on every key of the account). The
 * previous release compared updatedAt < reset directly — with a future
 * boundary that is true for EVERY current report, so the per-key usage
 * always displayed as 0 B. A report counts as previous-period only when it
 * was written a whole period before the boundary (Mozilla re-grants
 * calendar-monthly; the clients pave a 30-day cycle, hence 31 days of
 * tolerance). Rows still carrying an older past-timestamped boundary keep
 * the classic comparison.
 */
private fun isReportStale(row: GistRegistry.KeyRow, nowEpochSeconds: Long): Boolean {
    if (row.reset <= 0L || row.updatedAt <= 0L) return false
    val periodStart = if (row.reset > nowEpochSeconds) row.reset - 31L * 86_400L else row.reset
    return row.updatedAt < periodStart
}

@Composable
private fun AccountQuotaCard(app: KeygenApp, accountsVersion: Int, switchError: String?) {
    val accent = rememberKeygenAccent()
    val activeEmail = remember(accountsVersion) { app.accountVault.activeAccount()?.email.orEmpty() }
    var maxBytes by remember { mutableStateOf<Long?>(null) }
    var remaining by remember { mutableStateOf<Long?>(null) }
    // the REAL reason of the last failure — never a blanket «اتصال را بررسی کنید»
    var errText by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(activeEmail) {
        // this loop belongs to ONE account: if the user switches away, the
        // loop exits instead of writing the old account's numbers over the
        // new account's card
        val myEmail = activeEmail
        // 1) show this account's last-known numbers IMMEDIATELY so switching
        //    visibly swaps the card before the network answers
        app.accountVault.quotaSnapshot(myEmail)?.let { snap ->
            maxBytes = snap.maxBytes
            remaining = snap.remainingBytes
        } ?: run {
            maxBytes = null
            remaining = null
        }
        errText = null
        var first = true
        // a monthly-reset stamp GitHub refused earlier is retried on later
        // cycles (every ~5 min) until it finally lands in the registry
        var pendingResetStamp = 0L
        var stampSkip = 0
        while (true) {
            if (app.accountVault.activeAccount()?.email != myEmail) break
            if (pendingResetStamp > 0L) {
                if (stampSkip > 0) {
                    stampSkip--
                } else {
                    runCatching { app.gistRegistry.updateResetsForAccount(myEmail, pendingResetStamp) }
                        .onSuccess { pendingResetStamp = 0L }
                        .onFailure { stampSkip = 5 }
                }
            }
            app.accountVault.syncActiveFrom(app.tokenStore)
            val token = runCatching { app.authRepository.currentAccessToken() }.getOrNull()
            if (token != null) {
                runCatching { app.guardianClient.fetchAccountOverview(KeygenApp.GUARDIAN_ENDPOINT, token) }
                    .onSuccess { info ->
                        if (app.accountVault.activeAccount()?.email != myEmail) return@onSuccess
                        maxBytes = info.maxBytes
                        remaining = info.quotaRemaining
                        errText = null
                        // remember per-account numbers: the next switch shows
                        // them instantly, and the reset date reaches the keys
                        val previousReset = app.accountVault.quotaSnapshot(myEmail)?.resetAtEpochSeconds ?: 0L
                        val newReset = info.quotaReset ?: 0L
                        app.accountVault.saveQuotaSnapshot(
                            myEmail,
                            info.maxBytes ?: 0L,
                            info.quotaRemaining ?: 0L,
                            newReset,
                        )
                        if (newReset > 0L && newReset != previousReset) {
                            // new monthly cycle — stamp the fresh reset date on
                            // this account's keys so clients see the new date
                            pendingResetStamp = newReset
                            runCatching { app.gistRegistry.updateResetsForAccount(myEmail, newReset) }
                                .onSuccess { pendingResetStamp = 0L }
                        }
                        // the active row may still carry a placeholder label —
                        // resolve its real e-mail once and merge duplicates
                        val active = app.accountVault.activeAccount()
                        if (active != null && active.email == myEmail && active.pendingIdentity) {
                            val real = fetchFxaProfileEmail(token)
                            if (!real.isNullOrBlank()) {
                                app.accountVault.applyRealEmail(active.email, real)
                            }
                        }
                    }
                    .onFailure { failure ->
                        // a dead session means this account must be re-added;
                        // anything else is reported WITH ITS REAL REASON so the
                        // user sees exactly what Mozilla answered
                        if (app.accountVault.activeAccount()?.email == myEmail) {
                            errText = describeQuotaFailure(failure)
                        }
                    }
            } else if (first) {
                errText = "نشست فعالی برای این اکانت نیست — دوباره واردش شوید"
            }
            first = false
            delay(60_000L)
        }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
    ) {
        // compact card: used + progress — nothing else. No reset date, no
        // duplicated remaining, no un-accounted footnote: the user asked for
        // exactly this («تاریخ انقضای اون ۵۰ گیگ رو نمیخواد بزنی» + «اضافه‌ها رو حذف کن»)
        Column(Modifier.padding(14.dp)) {
            // Mozilla's counter is the authority for the REAL drained quota:
            // used = max - remaining. Leading with it answers «حجم رو حساب نمی‌کنه»
            val usedBytes = if (remaining != null && maxBytes != null) {
                (maxBytes!! - remaining!!).coerceAtLeast(0L)
            } else null
            Text(
                text = errText
                    ?: when {
                        usedBytes != null -> "مصرف‌شده: ${formatBytesBinary(usedBytes)} از ${formatBytesBinary(maxBytes!!)}"
                        remaining != null -> "باقی‌مانده: ${formatBytesBinary(remaining!!)}"
                        else -> "…"
                    },
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
                color = if (errText != null) Color(0xFFB72749) else Color(0xFF17222C),
            )
            if (usedBytes != null && maxBytes != null && maxBytes!! > 0) {
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(
                    progress = { (usedBytes.toFloat() / maxBytes!!.toFloat()).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                    color = accent,
                    trackColor = Color(0xFFEDF1F5),
                )
            }
            switchError?.let { message ->
                Spacer(Modifier.height(6.dp))
                Text(message, fontSize = 11.sp, color = Color(0xFFB72749), fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

// ---------------- issue tab ----------------

@Composable
private fun IssueTab(app: KeygenApp, accountsVersion: Int) {
    val accent = rememberKeygenAccent()
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val activeAccountEmail = remember(accountsVersion) { app.accountVault.activeAccount()?.email.orEmpty() }

    var ghToken by remember { mutableStateOf(app.gistRegistry.githubToken) }
    var ghStatus by remember { mutableStateOf(if (app.gistRegistry.isReady) "مخزن گزارش متصل است ✓" else "") }
    var ghBusy by remember { mutableStateOf(false) }
    var rebuiltGist by remember { mutableStateOf(false) }

    var name by remember { mutableStateOf("") }
    var sizeText by remember { mutableStateOf("5") }
    var sizeUnit by remember { mutableStateOf("گیگابایت") }
    var unlimited by remember { mutableStateOf(false) }
    var durationValue by remember { mutableStateOf("1") }
    var durationUnit by remember { mutableStateOf("ماه") }
    var noExpiry by remember { mutableStateOf(false) }

    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var issuedKey by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp)
            .imePadding(),
    ) {
        // GitHub setup
        Card(
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(14.dp)) {
                Text("۱) اتصال گزارش زنده (گیت‌هاب)", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = Color(0xFF17222C))
                Spacer(Modifier.height(4.dp))
                Text(
                    "توکن GitHub (با دسترسی Gist) را وارد کنید تا مصرف کاربران زنده دیده شود.",
                    fontSize = 11.sp,
                    color = Color(0xFF67737F),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = ghToken,
                    onValueChange = { ghToken = it; ghStatus = "" },
                    label = { Text("توکن GitHub (فقط دسترسی Gist کافی است)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = fieldColors(accent),
                )
                if (ghStatus.isNotBlank()) {
                    Spacer(Modifier.height(6.dp))
                    Text(ghStatus, fontSize = 12.sp, color = accent, fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = {
                        ghBusy = true; ghStatus = ""
                        scope.launch {
                            try {
                                app.gistRegistry.githubToken = ghToken.trim()
                                var check = app.gistRegistry.checkConnection()
                                // token works but the stored gist is definitively
                                // gone (HTTP 404): rebuild the registry instead of
                                // staying broken forever. Network flakes and
                                // permission problems never trigger this.
                                if (check.error != null && check.gistDead) {
                                    app.gistRegistry.gistId = ""
                                    check = app.gistRegistry.checkConnection()
                                    rebuiltGist = true
                                }
                                if (check.error != null) throw Exception(check.error ?: "اتصال برقرار نشد")
                                if (app.gistRegistry.gistId.isBlank()) {
                                    app.gistRegistry.createRegistry()
                                    // verify the fresh gist really reads back
                                    val verify = app.gistRegistry.checkConnection()
                                    if (verify.error != null) throw Exception(verify.error ?: "مخزن تازه خوانده نشد")
                                    check = verify
                                    rebuiltGist = true
                                }
                                ghStatus = "مخزن گزارش متصل است ✓ — حساب گیت‌هاب: ${check.login}" +
                                    if (rebuiltGist) " (مخزن تازه ساخته شد؛ برای هر کاربر کلید جدید بسازید)" else ""
                            } catch (c: CancellationException) {
                                throw c
                            } catch (e: Exception) {
                                ghStatus = e.message ?: "خطا"
                            } finally {
                                ghBusy = false
                                rebuiltGist = false
                            }
                        }
                    },
                    enabled = !ghBusy && ghToken.isNotBlank(),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = accent),
                ) {
                    Text(if (app.gistRegistry.isReady) "تست/بازسازی اتصال" else "اتصال و ساخت مخزن")
                }
            }
        }

        Spacer(Modifier.height(14.dp))

        // issue form
        Card(
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(14.dp)) {
                Text("۲) ساخت کلید جدید", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = Color(0xFF17222C))
                Spacer(Modifier.height(10.dp))

                OutlinedTextField(
                    value = name, onValueChange = { name = it; error = null },
                    label = { Text("نام شخص") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                    shape = RoundedCornerShape(12.dp), colors = fieldColors(accent),
                )
                Spacer(Modifier.height(10.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = sizeText,
                        onValueChange = { sizeText = it.filter { ch -> ch.isDigit() }.take(6) },
                        label = { Text(if (sizeUnit == "گیگابایت") "حجم (گیگابایت)" else "حجم (مگابایت)") },
                        modifier = Modifier.weight(1f), singleLine = true,
                        enabled = !unlimited,
                        shape = RoundedCornerShape(12.dp), colors = fieldColors(accent),
                    )
                    Spacer(Modifier.width(10.dp))
                    FilterChip(
                        selected = unlimited,
                        onClick = { unlimited = !unlimited },
                        label = { Text("نامحدود") },
                    )
                }
                if (!unlimited) {
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("واحد:", fontSize = 12.sp, color = Color(0xFF67737F))
                        Spacer(Modifier.width(8.dp))
                        FilterChip(
                            selected = sizeUnit == "گیگابایت",
                            onClick = { sizeUnit = "گیگابایت" },
                            label = { Text("گیگابایت") },
                        )
                        Spacer(Modifier.width(8.dp))
                        FilterChip(
                            selected = sizeUnit == "مگابایت",
                            onClick = { sizeUnit = "مگابایت" },
                            label = { Text("مگابایت") },
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = durationValue,
                        onValueChange = { durationValue = it.filter { ch -> ch.isDigit() }.take(4) },
                        label = { Text("مدت") },
                        modifier = Modifier.weight(1f), singleLine = true,
                        enabled = !noExpiry,
                        shape = RoundedCornerShape(12.dp), colors = fieldColors(accent),
                    )
                    Spacer(Modifier.width(8.dp))
                    listOf("ساعت", "روز", "ماه").forEach { unit ->
                        FilterChip(
                            selected = durationUnit == unit,
                            onClick = { durationUnit = unit; noExpiry = false },
                            label = { Text(unit) },
                            modifier = Modifier.padding(start = 4.dp),
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    FilterChip(
                        selected = noExpiry,
                        onClick = { noExpiry = !noExpiry },
                        label = { Text("بی‌نهایت") },
                    )
                }

                error?.let {
                    Spacer(Modifier.height(10.dp))
                    Text(it, color = MaterialTheme.colorScheme.error, fontSize = 12.sp)
                }

                Spacer(Modifier.height(14.dp))
                Button(
                    onClick = {
                        busy = true; error = null; issuedKey = null
                        scope.launch {
                            try {
                                // keys minted without a connected registry carry no
                                // gist coordinates: they can never report usage and
                                // can never be revoked — refuse to make them
                                if (!app.gistRegistry.isReady) {
                                    throw Exception(
                                        "اول «اتصال گزارش زنده (گیت‌هاب)» را انجام دهید؛ " +
                                            "بدون آن باطل‌کردن کلید و گزارش مصرف کار نمی‌کند",
                                    )
                                }
                                // a REAL read of the gist right before minting: a
                                // token that only passes /user but cannot touch the
                                // gist would bake a dead key (no reports, no revoke)
                                val preflight = app.gistRegistry.checkConnection()
                                if (preflight.error != null) {
                                    throw Exception("مخزن گزارش در دسترس نیست: ${preflight.error}")
                                }
                                app.accountVault.syncActiveFrom(app.tokenStore)
                                // prefer a FRESH refresh token minted from the
                                // Firefox session: the key then keeps working
                                // even after the keygen's own token rotates
                                val refreshToken = app.authRepository.freshKeyRefreshToken()
                                    ?: app.tokenStore.loadAuth()?.refreshToken
                                    ?: app.accountVault.activeAccount()?.refreshToken
                                    ?: throw Exception("نشست فایرفاکس یافت نشد؛ دوباره وارد شوید")
                                val sizeValue = sizeText.toLongOrNull()?.coerceAtLeast(1L)
                                if (!unlimited && sizeValue == null) throw Exception("حجم را درست وارد کنید")
                                val gb = if (unlimited || sizeUnit == "مگابایت") 0L else sizeValue ?: 0L
                                val mb = if (unlimited || sizeUnit == "گیگابایت") 0L else sizeValue ?: 0L
                                val unitSeconds = when (durationUnit) {
                                    "ساعت" -> 3600L
                                    "روز" -> 86400L
                                    else -> 30L * 86400L
                                }
                                val duration = unitSeconds * (durationValue.toLongOrNull()?.coerceAtLeast(1L) ?: 1L)
                                val exp = if (noExpiry) 0L else System.currentTimeMillis() / 1000L + duration

                                val key = QuotaKeyCodec.mint(
                                    name = name.trim().ifBlank { "کاربر" },
                                    gb = gb,
                                    mb = mb,
                                    expiresAtEpochSeconds = exp,
                                    refreshToken = refreshToken,
                                    gistId = app.gistRegistry.gistId,
                                    githubToken = app.gistRegistry.githubToken,
                                    privateKeyB64 = BuildConfig.FOXY_PRIVATE_KEY,
                                )
                                if (!QuotaKeyCodec.verifySelf(key)) {
                                    throw Exception(
                                        "خودآزمایی امضا ناموفق بود — کلید امضای این نسخه با کلید عمومی " +
                                            "برنامهٔ اصلی هم‌خوانی ندارد",
                                    )
                                }
                                app.gistRegistry.addKey(
                                    GistRegistry.KeyRow(
                                        id = extractId(key), name = name.trim().ifBlank { "کاربر" },
                                        gb = gb, mb = mb, exp = exp,
                                        issuedAt = System.currentTimeMillis() / 1000L,
                                        revoked = false,
                                    ),
                                    mintingAccount = activeAccountEmail,
                                    resetAtEpochSeconds = app.accountVault
                                        .quotaSnapshot(activeAccountEmail)?.resetAtEpochSeconds ?: 0L,
                                )
                                issuedKey = key
                            } catch (c: CancellationException) {
                                throw c
                            } catch (e: Exception) {
                                error = e.message ?: "ساخت کلید ناموفق بود"
                            } finally {
                                busy = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(50.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = accent),
                    enabled = !busy,
                ) {
                    if (busy) CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = Color.White)
                    else Text("ساخت کلید", fontSize = 15.sp, fontWeight = FontWeight.Bold)
                }

                issuedKey?.let { key ->
                    Spacer(Modifier.height(12.dp))
                    Card(
                        shape = RoundedCornerShape(14.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFEFF7F1)),
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Text("کلید آماده است — برای دوستتان بفرستید:", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF128A56))
                            Spacer(Modifier.height(6.dp))
                            Text(key, fontSize = 10.sp, color = Color(0xFF37505F), maxLines = 6)
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(
                                onClick = {
                                    clipboard.setText(AnnotatedString(key))
                                    Toast.makeText(app, "کلید کپی شد", Toast.LENGTH_SHORT).show()
                                },
                                shape = RoundedCornerShape(10.dp),
                            ) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("کپی کلید")
                            }
                        }
                    }
                }
                Spacer(Modifier.height(20.dp))
            }
        }
    }
}

private fun extractId(key: String): String = QuotaKeyCodec.randomId().let {
    // id is inside the payload; simplest is to regenerate consistency is not
    // critical for the registry, but we want the real one: decode payload
    runCatching {
        val payloadB64 = key.split(".")[1]
        var b64 = payloadB64
        while (b64.length % 4 != 0) b64 += "="
        val jsonText = String(
            android.util.Base64.decode(b64, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP),
            Charsets.UTF_8,
        )
        org.json.JSONObject(jsonText).optString("id")
    }.getOrDefault(it)
}

/** Resolves the real e-mail of the freshly signed-in account (best effort). */
private suspend fun fetchFxaProfileEmail(accessToken: String): String? = withContext(Dispatchers.IO) {
    runCatching {
        val request = okhttp3.Request.Builder()
            .url("https://profile.accounts.firefox.com/v1/profile")
            .header("Authorization", "Bearer $accessToken")
            .header("User-Agent", "FoxyKeygen")
            .get()
            .build()
        ControlPlaneHttp.client.newCall(request).execute().use { resp ->
            if (!resp.isSuccessful) return@use null
            val body = resp.body?.string().orEmpty()
            val email = org.json.JSONObject(body).optString("email")
            email.takeIf { it.isNotBlank() }
        }
    }.getOrNull()
}

// ---------------- keys tab ----------------

@Composable
private fun KeysTab(app: KeygenApp, accountsVersion: Int) {
    val accent = rememberKeygenAccent()
    val scope = rememberCoroutineScope()
    var rows by remember { mutableStateOf<List<GistRegistry.KeyRow>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    var busyId by remember { mutableStateOf<String?>(null) }
    var deleteTarget by remember { mutableStateOf<GistRegistry.KeyRow?>(null) }
    var repoOk by remember { mutableStateOf<Boolean?>(null) }
    var repoText by remember { mutableStateOf("") }
    var reissuedKey by remember { mutableStateOf<String?>(null) }
    val clipboard = LocalClipboardManager.current
    val activeEmail = remember(accountsVersion) { app.accountVault.activeAccount()?.email.orEmpty() }

    fun refresh() {
        scope.launch {
            loading = true; err = null
            try {
                rows = app.gistRegistry.fetchRows()
                if (app.gistRegistry.isReady) {
                    val check = app.gistRegistry.checkConnection()
                    repoOk = check.error == null
                    repoText = when {
                        check.error != null -> check.error
                        else -> "مخزن متصل است ✓ · حساب گیت‌هاب: ${check.login ?: "—"}"
                    }
                } else {
                    repoOk = false
                    repoText = "مخزن گزارش وصل نیست — در تب «ساخت کلید» اتصال گیت‌هاب را انجام دهید"
                }
            } catch (c: CancellationException) {
                throw c
            } catch (e: Exception) {
                err = e.message
            } finally {
                loading = false
            }
        }
    }

    /**
     * Re-mints a replacement key with the SAME plan (size/expiry/account) —
     * the escape hatch when the registry moves to a fresh gist and old keys
     * keep pointing at the dead one.
     */
    fun reissue(row: GistRegistry.KeyRow) {
        busyId = row.id
        err = null
        scope.launch {
            try {
                if (!app.gistRegistry.isReady) {
                    throw Exception("اول اتصال گیت‌هاب را در تب «ساخت کلید» انجام دهید")
                }
                val vaultAccount = app.accountVault.accounts.firstOrNull { it.email == row.acct }
                // the active account gets a fresh dedicated token too; other
                // accounts have no stored session, so their stored token is used
                val freshToken = if (row.acct.equals(app.accountVault.activeAccount()?.email, ignoreCase = true)) {
                    app.authRepository.freshKeyRefreshToken()
                } else {
                    null
                }
                val refreshToken = freshToken ?: vaultAccount?.refreshToken?.takeIf { it.isNotBlank() }
                    ?: throw Exception(
                        "اکانت «${row.acct}» در کلیدساز در دسترس نیست — اول از منوی بالا واردش کنید، بعد کلید جایگزین بسازید",
                    )
                val key = QuotaKeyCodec.mint(
                    name = row.name,
                    gb = row.gb,
                    mb = row.mb,
                    expiresAtEpochSeconds = row.exp,
                    refreshToken = refreshToken,
                    gistId = app.gistRegistry.gistId,
                    githubToken = app.gistRegistry.githubToken,
                    privateKeyB64 = BuildConfig.FOXY_PRIVATE_KEY,
                )
                if (!QuotaKeyCodec.verifySelf(key)) {
                    throw Exception("خودآزمایی امضا ناموفق بود — کلید امضای این نسخه با کلید عمومی برنامهٔ اصلی هم‌خوانی ندارد")
                }
                app.gistRegistry.addKey(
                    GistRegistry.KeyRow(
                        id = extractId(key),
                        name = row.name,
                        gb = row.gb,
                        mb = row.mb,
                        exp = row.exp,
                        issuedAt = System.currentTimeMillis() / 1000L,
                        revoked = false,
                    ),
                    mintingAccount = row.acct,
                    resetAtEpochSeconds = row.reset,
                )
                reissuedKey = key
            } catch (c: CancellationException) {
                throw c
            } catch (e: Exception) {
                err = e.message
            } finally {
                busyId = null
            }
        }
    }

    LaunchedEffect(Unit) {
        refresh()
        while (true) {
            delay(30_000L)
            runCatching { rows = app.gistRegistry.fetchRows() }
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("مصرف زندهٔ کاربران", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFF17222C))
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { refresh() }) {
                Icon(Icons.Filled.Refresh, contentDescription = "بازخوانی", tint = accent)
            }
        }
        if (repoOk == false && repoText.isNotBlank()) {
            // silence when healthy — the green «مخزن متصل است ✓» line was clutter
            Text(
                repoText,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFFB57A00),
            )
            Spacer(Modifier.height(4.dp))
        }
        Spacer(Modifier.height(8.dp))
        if (loading && rows.isEmpty()) {
            Box(Modifier.fillMaxWidth().padding(30.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = accent, modifier = Modifier.size(26.dp), strokeWidth = 2.dp)
            }
        }
        err?.let { Text(it, color = MaterialTheme.colorScheme.error, fontSize = 12.sp) }
        if (!loading && rows.isEmpty() && err == null) {
            Text(
                "هنوز کلیدی صادر نشده است",
                modifier = Modifier.fillMaxWidth().padding(24.dp),
                textAlign = TextAlign.Center,
                color = Color(0xFF67737F),
                fontSize = 13.sp,
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            rows.forEach { row ->
                KeyRowCard(
                    row = row,
                    activeEmail = activeEmail,
                    busy = busyId == row.id,
                    onToggle = {
                        busyId = row.id
                        scope.launch {
                            try {
                                app.gistRegistry.setRevoked(row.id, !row.revoked)
                                refresh()
                            } catch (c: CancellationException) {
                                throw c
                            } catch (e: Exception) {
                                err = e.message
                            } finally {
                                busyId = null
                            }
                        }
                    },
                    onDelete = { deleteTarget = row },
                    onReissue = { reissue(row) },
                )
            }
        }
        Spacer(Modifier.height(20.dp))
    }

    reissuedKey?.let { key ->
        AlertDialog(
            onDismissRequest = { reissuedKey = null },
            title = { Text("کلید جایگزین آماده است", fontSize = 16.sp, fontWeight = FontWeight.Bold) },
            text = {
                Text(
                    "همان حجم و مهلت قبلی را دارد و از سهمیهٔ همان اکانت کسر می‌شود. کلید تازه را جای کلید قبلی به کاربر بدهید و بعد کلید قبلی را باطل یا حذف کنید.\n\n$key",
                    fontSize = 12.sp,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    clipboard.setText(AnnotatedString(key))
                    Toast.makeText(app, "کلید کپی شد", Toast.LENGTH_SHORT).show()
                }) { Text("کپی کلید") }
            },
            dismissButton = {
                TextButton(onClick = { reissuedKey = null }) { Text("بستن") }
            },
        )
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("حذف کامل کاربر", fontSize = 16.sp, fontWeight = FontWeight.Bold) },
            text = {
                Text(
                    "کلید «${target.name}» به‌طور کامل حذف می‌شود؛ نه در فهرست کلیدها می‌ماند و نه مصرفش دیده می‌شود. این کار برگشت‌پذیر نیست.",
                    fontSize = 13.sp,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val row = target
                        deleteTarget = null
                        busyId = row.id
                        scope.launch {
                            try {
                                app.gistRegistry.deleteKey(row.id)
                                refresh()
                            } catch (c: CancellationException) {
                                throw c
                            } catch (e: Exception) {
                                err = e.message
                            } finally {
                                busyId = null
                            }
                        }
                    },
                ) {
                    Text("حذف کن", color = Color(0xFFB72749), fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text("بی‌خیال") }
            },
        )
    }
}

@Composable
private fun KeyRowCard(
    row: GistRegistry.KeyRow,
    activeEmail: String,
    busy: Boolean,
    onToggle: () -> Unit,
    onReissue: () -> Unit,
    onDelete: () -> Unit,
) {
    val accent = rememberKeygenAccent()
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(30_000L)
            nowMs = System.currentTimeMillis()
        }
    }
    val statusColor = when {
        row.revoked -> Color(0xFFB72749)
        row.status == "exhausted" -> Color(0xFFB72749)
        row.status == "expired" -> Color(0xFFB57A00)
        else -> Color(0xFF128A56)
    }
    val statusText = when {
        row.revoked -> "باطل‌شده"
        row.status == "exhausted" -> "حجم تمام"
        row.status == "expired" -> "منقضی"
        row.status == "active" -> "فعال"
        else -> "بدون گزارش"
    }
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(row.name, fontWeight = FontWeight.Bold, fontSize = 14.sp, color = Color(0xFF17222C))
                Spacer(Modifier.width(8.dp))
                Text("#${row.id}", fontSize = 10.sp, color = Color(0xFF97A1AC))
                Spacer(Modifier.weight(1f))
                Surface(shape = RoundedCornerShape(50), color = statusColor.copy(alpha = 0.13f)) {
                    Text(statusText, modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp), fontSize = 11.sp, color = statusColor, fontWeight = FontWeight.SemiBold)
                }
            }
            Spacer(Modifier.height(6.dp))
            Text(
                buildString {
                    append(
                        when {
                            row.gb > 0 -> "${FaFormat.faDigits(row.gb)} گیگ"
                            row.mb > 0 -> "${FaFormat.faDigits(row.mb)} مگ"
                            else -> "نامحدود"
                        },
                    )
                    if (row.exp > 0) {
                        append("  ·  تا " + FaFormat.formatJalaliDate(row.exp))
                        if (row.exp * 1000L > nowMs) {
                            append("  ·  " + FaFormat.remainingLabel(row.exp, nowMs) + " مانده")
                        } else {
                            append("  ·  منقضی شده")
                        }
                    }
                },
                fontSize = 11.sp,
                color = Color(0xFF67737F),
            )
            Spacer(Modifier.height(6.dp))
            // Usage belongs to the CURRENT monthly period: a report written a
            // whole period before the next reset boundary is previous-month
            // data (isReportStale) — current reports must always show.
            val stalePeriod = isReportStale(row, nowMs / 1000L)
            if (row.updatedAt == 0L && !row.revoked) {
                // no client has EVER reported for this key: one short line
                Text(
                    "مصرف: —",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF97A1AC),
                )
            } else if (stalePeriod) {
                Text(
                    "مصرف ماه قبل: ${formatBytesBinary(row.usedBytes)}",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF97A1AC),
                )
            } else {
                Text(
                    "مصرف: ${formatBytesBinary(row.usedBytes)}" +
                        (if (row.updatedAt > 0)
                            "  ·  " + FaFormat.relativeAgoLabel(row.updatedAt, nowMs)
                        else ""),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF17222C),
                )
            }
            if (row.planBytes > 0) {
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(
                    progress = { ((if (stalePeriod) 0L else row.usedBytes).toFloat() / row.planBytes.toFloat()).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().height(5.dp).clip(RoundedCornerShape(3.dp)),
                    color = if (row.revoked) Color(0xFFB72749) else accent,
                    trackColor = Color(0xFFEDF1F5),
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(
                    onClick = onToggle,
                    enabled = !busy,
                    shape = RoundedCornerShape(10.dp),
                ) {
                    Text(if (row.revoked) "فعال‌سازی دوباره" else "باطل‌کردن کلید", fontSize = 12.sp)
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = onReissue,
                    enabled = !busy,
                    shape = RoundedCornerShape(10.dp),
                ) {
                    Text("کلید جایگزین", fontSize = 12.sp)
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = onDelete,
                    enabled = !busy,
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFB72749)),
                ) {
                    Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("حذف کاربر", fontSize = 12.sp)
                }
            }
        }
    }
}

