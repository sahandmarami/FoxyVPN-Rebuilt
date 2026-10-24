package com.vauth.foxyvpn.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Power
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vauth.foxyvpn.BuildConfig
import com.vauth.foxyvpn.FoxyVpnApp
import com.vauth.foxyvpn.data.FaFormat
import com.vauth.foxyvpn.data.QuotaKeyPayload
import com.vauth.foxyvpn.data.GistReporter
import com.vauth.foxyvpn.data.UsageAccountant
import com.vauth.foxyvpn.data.formatBytes
import com.vauth.foxyvpn.data.model.ConnectionState
import com.vauth.foxyvpn.data.model.emojiFlag
import com.vauth.foxyvpn.ui.theme.LocalFoxyPalette
import com.vauth.foxyvpn.vpn.FoxyVpnService
import com.vauth.foxyvpn.vpn.PingUtil
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

@Composable
fun HomeScreen(
    app: FoxyVpnApp,
    themeController: Any?,
    onRequestConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onOpenServers: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        val palette = LocalFoxyPalette.current
        val state by FoxyVpnService.state.collectAsState()
        val lastError by FoxyVpnService.lastError.collectAsState()
        val liveStats by FoxyVpnService.vpnLiveStats.collectAsState()
        val connectedAtEpochMs by FoxyVpnService.connectedAtEpochMs.collectAsState()
        val pingLatency by FoxyVpnService.pingLatencyMs.collectAsState()
        val vpnEdgeIp by FoxyVpnService.vpnEdgeIp.collectAsState()
        val selectedProxy by app.proxyStateStore.selectedProxyFlow.collectAsState()

        val haptics = LocalHapticFeedback.current
        val scope = rememberCoroutineScope()

        val key = remember { app.activatedKeyStore.loadKey() }
        var usedBytes by remember { mutableLongStateOf(UsageAccountant.used) }
        var elapsedSeconds by remember { mutableLongStateOf(0L) }

        // keep the usage counter fresh
        LaunchedEffect(state) {
            while (isActive) {
                usedBytes = UsageAccountant.used
                delay(1000L)
            }
        }

        LaunchedEffect(state, connectedAtEpochMs) {
            if (state == ConnectionState.CONNECTED && connectedAtEpochMs != null) {
                while (isActive) {
                    val now = System.currentTimeMillis()
                    elapsedSeconds = ((now - connectedAtEpochMs!!) / 1000L).coerceAtLeast(0L)
                    delay(1000L)
                }
            } else {
                elapsedSeconds = 0L
            }
        }

        val targetScale = if (state == ConnectionState.CONNECTED) 1f else 0.94f
        val scale by animateFloatAsState(
            targetValue = targetScale,
            animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy),
            label = "power-scale",
        )
        val ringColor by animateColorAsState(
            targetValue = when (state) {
                ConnectionState.CONNECTED -> palette.accent
                ConnectionState.CONNECTING -> Color(0xFFB57A00)
                ConnectionState.DISCONNECTED -> Color(0xFF98A2AE)
            },
            label = "power-ring",
        )

        // ping-all state
        var pingAllRunning by remember { mutableStateOf(false) }
        var bestPingMs by remember { mutableIntStateOf(-1) }
        var bestPingWhere by remember { mutableStateOf("") }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(Brush.verticalGradient(listOf(palette.gradientTop, palette.gradientBottom))),
        ) {
            // ---------- header ----------
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 22.dp, vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "FoxyVPN",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF20303C),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "اینترنت آزاد",
                    fontSize = 12.sp,
                    color = Color(0xFF7A8794),
                )
                // visible version so «کدام نسخه نصب است؟» همیشه روی صفحه جواب دارد
                Text(
                    "v" + BuildConfig.VERSION_NAME,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color(0xFF98A2AE),
                    modifier = Modifier.padding(start = 6.dp),
                )
                Spacer(Modifier.weight(1f))
                Icon(
                    Icons.Filled.Bolt,
                    contentDescription = null,
                    tint = palette.accent,
                    modifier = Modifier.size(22.dp),
                )
            }

            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                // ---------- account card ----------
                AccountCard(
                    appName = key?.personName ?: "کاربر",
                    planGb = key?.payload?.gb ?: 0L,
                    planMb = key?.payload?.mb ?: 0L,
                    expiresAt = key?.payload?.exp ?: 0L,
                    usedBytes = usedBytes,
                    accent = palette.accent,
                    accentDeep = palette.accentDeep,
                )

                Spacer(Modifier.height(8.dp))

                UsageAccountant.blockReason.let { reason ->
                    if (reason != UsageAccountant.BlockReason.NONE) {
                        BlockBanner(reason)
                        Spacer(Modifier.height(8.dp))
                    }
                }

                // ---------- power button ----------
                Spacer(Modifier.height(6.dp))
                Box(
                    modifier = Modifier
                        .size(196.dp)
                        .scale(scale)
                        .clip(CircleShape)
                        .background(ringColor.copy(alpha = 0.10f))
                        .clickable {
                            haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                            if (state == ConnectionState.DISCONNECTED) onRequestConnect() else onDisconnect()
                        },
                    contentAlignment = Alignment.Center,
                ) {
                    Box(
                        modifier = Modifier
                            .size(164.dp)
                            .clip(CircleShape)
                            .background(ringColor.copy(alpha = 0.18f)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(138.dp)
                                .clip(CircleShape)
                                .background(Brush.verticalGradient(listOf(Color(0xFF1D2B3A), Color(0xFF101C28)))),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Power,
                                contentDescription = if (state == ConnectionState.DISCONNECTED) "اتصال" else "قطع",
                                tint = ringColor,
                                modifier = Modifier.size(58.dp),
                            )
                        }
                    }
                }

                Spacer(Modifier.height(14.dp))

                Text(
                    text = when (state) {
                        ConnectionState.CONNECTED -> "وصل است ✓"
                        ConnectionState.CONNECTING -> "در حال اتصال…"
                        ConnectionState.DISCONNECTED -> "قطع است"
                    },
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF20303C),
                )
                Text(
                    text = if (state == ConnectionState.CONNECTED) formatDuration(elapsedSeconds) else "00:00:00",
                    fontSize = 13.sp,
                    color = Color(0xFF7A8794),
                )

                lastError?.let { err ->
                    if (state != ConnectionState.CONNECTING) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            err,
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.error,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = 12.dp),
                        )
                    }
                }

                Spacer(Modifier.height(14.dp))

                // ---------- ping-all pill ----------
                Surface(
                    shape = RoundedCornerShape(50),
                    color = Color.White,
                    shadowElevation = 2.dp,
                    modifier = Modifier.clickable {
                        if (pingAllRunning) return@clickable
                        pingAllRunning = true
                        haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                        scope.launch {
                            val result = pingAllCountriesImpl(app)
                            bestPingMs = result?.first ?: -1
                            bestPingWhere = result?.second ?: ""
                            pingAllRunning = false
                        }
                    },
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (pingAllRunning) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = palette.accent)
                        } else {
                            Icon(Icons.Filled.Bolt, contentDescription = null, tint = palette.accent, modifier = Modifier.size(18.dp))
                        }
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = when {
                                pingAllRunning -> "در حال تست پینگ…"
                                bestPingMs > 0 -> "بهترین پینگ: $bestPingMs ms (${bestPingWhere})"
                                else -> "تست پینگ همه"
                            },
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Color(0xFF20303C),
                        )
                    }
                }

                Spacer(Modifier.height(16.dp))

                // ---------- stats row ----------
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    StatCard(
                        modifier = Modifier.weight(1f),
                        label = "پینگ",
                        value = when {
                            pingAllRunning -> "…"
                            pingLatency != null -> "$pingLatency ms"
                            bestPingMs > 0 -> "$bestPingMs ms"
                            else -> "—"
                        },
                        valueColor = palette.accent,
                    )
                    StatCard(
                        modifier = Modifier.weight(1f),
                        label = "زمان اتصال",
                        value = if (state == ConnectionState.CONNECTED) shortDuration(elapsedSeconds) else "—",
                        valueColor = Color(0xFF20303C),
                    )
                    StatCard(
                        modifier = Modifier.weight(1f),
                        label = "مصرف این جلسه",
                        value = if (state == ConnectionState.CONNECTED) formatBytes(liveStats.sessionBytes) else "0 MB",
                        valueColor = Color(0xFF20303C),
                    )
                }

                Spacer(Modifier.height(14.dp))

                // ---------- server card ----------
                Card(
                    onClick = onOpenServers,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            selectedProxy?.emojiFlag ?: "🌍",
                            fontSize = 30.sp,
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                selectedProxy?.let { it.countryName.ifBlank { it.countryCode } } ?: "خودکار (پیشنهادی)",
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF20303C),
                            )
                            val ipText = vpnEdgeIp?.ip ?: selectedProxy?.host
                            if (ipText != null) {
                                Text(
                                    ipText,
                                    fontSize = 12.sp,
                                    color = Color(0xFF7A8794),
                                )
                            }
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            Icon(
                                Icons.Filled.Public,
                                contentDescription = null,
                                tint = palette.accent,
                                modifier = Modifier.size(18.dp),
                            )
                            val remain = remainingBytes(usedBytes)
                            if (remain != null) {
                                Text(
                                    "⚡ ${formatBytes(remain)}",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = palette.accentDeep,
                                )
                            }
                        }
                    }
                }

                Spacer(Modifier.height(16.dp))
            }

            // ---------- bottom navigation ----------
            BottomNav(
                accent = palette.accent,
                accentDeep = palette.accentDeep,
                onServers = onOpenServers,
                onSettings = onOpenSettings,
            )
        }
    }
}

@Composable
private fun AccountCard(
    appName: String,
    planGb: Long,
    planMb: Long,
    expiresAt: Long,
    usedBytes: Long,
    accent: Color,
    accentDeep: Color,
) {
    // live clock so the remaining-days label falls on its own, day after day
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(30_000L)
            nowMs = System.currentTimeMillis()
        }
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(Brush.linearGradient(listOf(accent, accentDeep))),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        appName.take(1),
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 17.sp,
                    )
                }
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(appName, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFF20303C))
                    Text(
                        when {
                            planGb > 0 -> "اشتراک $planGb گیگابایتی فعال است ✓"
                            planMb > 0 -> "اشتراک $planMb مگابایتی فعال است ✓"
                            else -> "اشتراک نامحدود فعال است ✓"
                        },
                        fontSize = 12.sp,
                        color = accentDeep,
                    )
                    if (expiresAt > 0) {
                        val expired = expiresAt * 1000L <= nowMs
                        Text(
                            if (expired) "اعتبار تمام شده"
                            else FaFormat.remainingLabel(expiresAt, nowMs) + " باقی‌مانده",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = if (expiresAt * 1000L > nowMs) accentDeep else Color(0xFFB72749),
                        )
                    }
                }
                if (expiresAt > 0) {
                    Text(
                        "تا " + FaFormat.formatJalaliDate(expiresAt),
                        fontSize = 11.sp,
                        color = Color(0xFF7A8794),
                    )
                }
            }

            val resetAt = remember(nowMs) { UsageAccountant.quotaResetAt() }
            if (resetAt > 0) {
                Spacer(Modifier.height(8.dp))
                Text(
                    FaFormat.quotaResetLabel(resetAt, nowMs),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color(0xFF67737F),
                )
            }

            // registry heartbeat: makes the revocation/usage channel visible
            // instead of silently failing somewhere in the background. The
            // label carries the REAL failure class (token / gist / rate limit
            // / network) so a broken channel is never disguised as «اینترنت».
            if (UsageAccountant.reporterContext() != null) {
                var heartbeat by remember { mutableStateOf<Pair<String?, String?>?>(null) }
                LaunchedEffect(Unit) {
                    while (true) {
                        heartbeat = if (GistReporter.lastSyncAttemptAtMs == 0L) {
                            null
                        } else {
                            GistReporter.lastSyncOkAtMs to GistReporter.lastSyncIssueLabel
                        }
                        delay(5_000L)
                    }
                }
                Spacer(Modifier.height(6.dp))
                val okAt = heartbeat?.first
                val issueLabel = heartbeat?.second
                val heartbeatText = when {
                    heartbeat == null -> "بررسی وضعیت کلید: در انتظار اولین همگام‌سازی…"
                    okAt != null && issueLabel.isNullOrBlank() ->
                        "گزارش مصرف: فعال ✓ (ارسال زنده به کلیدساز)"
                    issueLabel != null && issueLabel.isNotBlank() ->
                        "گزارش مصرف قطع است — $issueLabel"
                    else -> "بررسی وضعیت کلید: در انتظار همگام‌سازی…"
                }
                Text(
                    heartbeatText,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = when {
                        heartbeat == null -> Color(0xFF97A1AC)
                        okAt != null && issueLabel.isNullOrBlank() -> Color(0xFF128A56)
                        else -> Color(0xFFB57A00)
                    },
                )
            }

            val planBytes = planGb * QuotaKeyPayload.BYTES_PER_GB + planMb * QuotaKeyPayload.BYTES_PER_MB
            if (planBytes > 0) {
                Spacer(Modifier.height(12.dp))
                val limitBytes = planBytes
                val fraction = (usedBytes.toFloat() / limitBytes.toFloat()).coerceIn(0f, 1f)
                LinearProgressIndicator(
                    progress = { fraction },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(7.dp)
                        .clip(RoundedCornerShape(4.dp)),
                    color = accent,
                    trackColor = Color(0xFFEDF1F5),
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    "${formatBytes(usedBytes)} از ${formatBytes(planBytes)} مصرف شده",
                    fontSize = 11.sp,
                    color = Color(0xFF7A8794),
                )
            } else {
                Spacer(Modifier.height(12.dp))
                Text(
                    "مصرف تاکنون: ${formatBytes(usedBytes)}",
                    fontSize = 11.sp,
                    color = Color(0xFF7A8794),
                )
            }
        }
    }
}

@Composable
private fun BlockBanner(reason: UsageAccountant.BlockReason) {
    val (text, color) = when (reason) {
        UsageAccountant.BlockReason.QUOTA -> "حجم کلید شما تمام شده است" to Color(0xFFB72749)
        UsageAccountant.BlockReason.EXPIRED -> "مهلت کلید شما به پایان رسیده است" to Color(0xFFB57A00)
        UsageAccountant.BlockReason.REVOKED -> "این کلید غیرفعال شده است" to Color(0xFFB72749)
        UsageAccountant.BlockReason.NONE -> return
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)),
    ) {
        Text(
            "$text — برای کلید جدید با پشتیبان خود تماس بگیرید",
            modifier = Modifier.padding(14.dp),
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = color,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun StatCard(
    modifier: Modifier,
    label: String,
    value: String,
    valueColor: Color,
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
    ) {
        Column(
            modifier = Modifier.padding(vertical = 14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(value, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = valueColor)
            Spacer(Modifier.height(4.dp))
            Text(label, fontSize = 11.sp, color = Color(0xFF7A8794))
        }
    }
}

private data class BottomNavItem(val label: String, val icon: ImageVector)

@Composable
private fun BottomNav(
    accent: Color,
    accentDeep: Color,
    onServers: () -> Unit,
    onSettings: () -> Unit,
) {
    Surface(color = Color.White, shadowElevation = 8.dp) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 18.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // home (active)
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(50))
                    .background(Brush.horizontalGradient(listOf(accent, accentDeep)))
                    .padding(vertical = 12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Home, contentDescription = null, tint = Color.White, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("خانه", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
            }
            Spacer(Modifier.width(10.dp))
            NavItem(Icons.Filled.Public, "سرورها", Modifier.weight(1f).clickable { onServers() })
            Spacer(Modifier.width(10.dp))
            NavItem(Icons.Filled.Settings, "تنظیمات", Modifier.weight(1f).clickable { onSettings() })
        }
    }
}

@Composable
private fun NavItem(icon: ImageVector, label: String, modifier: Modifier = Modifier) {
    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(icon, contentDescription = label, tint = Color(0xFF7A8794), modifier = Modifier.size(22.dp))
        Spacer(Modifier.height(2.dp))
        Text(label, fontSize = 12.sp, color = Color(0xFF7A8794))
    }
}

// ---------- helpers ----------

private fun remainingBytes(used: Long): Long? {
    val limit = UsageAccountant.limit
    if (limit <= 0L) return null
    return (limit - used).coerceAtLeast(0L)
}

private suspend fun pingAllCountriesImpl(app: FoxyVpnApp): Pair<Int, String>? =
    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val cached = app.serverListClient.loadCachedCountries()
        if (cached.isEmpty()) return@withContext null
        val targets = cached.take(12).mapNotNull { country ->
            com.vauth.foxyvpn.data.ServerListClient.candidatesForCountry(cached, country.code)
                .firstOrNull()
                ?.let { country.code to it }
        }
        val results = targets.map { (code, candidate) ->
            async { PingUtil.measureTcpLatencyMs(candidate.host, candidate.port)?.let { ms -> Triple(ms, code, candidate.countryName) } }
        }.awaitAll().filterNotNull()
        results.minByOrNull { it.first }?.let { (ms, _, name) -> ms to name }
    }

private fun formatDuration(seconds: Long): String {
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    return String.format(Locale.US, "%02d:%02d:%02d", h, m, s)
}

private fun shortDuration(seconds: Long): String {
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    return if (h > 0) "${h}h ${m}m" else "${m}m"
}

