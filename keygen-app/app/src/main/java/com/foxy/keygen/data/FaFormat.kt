package com.foxy.keygen.data

import java.time.Instant
import java.time.ZoneId

/**
 * Persian (Jalali) calendar conversion — classic div/mod algorithm — plus the
 * human time helpers used across the keygen UI. The previous release showed
 * Gregorian months with Persian names, which read as a wrong date to most
 * users; every date in the UI now comes from here.
 */
object FaFormat {

    private val JALALI_MONTHS = listOf(
        "فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
        "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند",
    )

    fun faDigits(n: Long): String = buildString {
        for (ch in n.toString()) {
            append(if (ch in '0'..'9') ('۰'.code + (ch - '0')).toChar() else ch)
        }
    }

    fun faDigits(n: Int): String = faDigits(n.toLong())

    /** Gregorian → Jalali. Returns (jy, jm, jd). */
    fun toJalali(gy: Int, gm: Int, gd: Int): Triple<Int, Int, Int> {
        val gDaysInMonth = intArrayOf(0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334)
        var jy = if (gy <= 1600) 0 else 979
        val gy2 = if (gy <= 1600) gy - 621 else gy - 1600
        val gy3 = if (gm > 2) gy2 + 1 else gy2
        var days = 365L * gy2 + (gy3 + 3) / 4 - (gy3 + 99) / 100 + (gy3 + 399) / 400 -
            80 + gDaysInMonth[gm - 1] + gd
        jy += 33 * (days / 12053).toInt()
        days %= 12053
        jy += 4 * ((days / 1461).toInt())
        days %= 1461
        if (days > 365) {
            jy += ((days - 1) / 365).toInt()
            days = (days - 1) % 365
        }
        val jm = if (days < 186) 1 + (days / 31).toInt() else 7 + ((days - 186) / 30).toInt()
        val jd = if (days < 186) 1 + (days % 31).toInt() else 1 + ((days - 186) % 30).toInt()
        return Triple(jy, jm, jd)
    }

    /** "۲۹ آبان ۱۴۰۵" for a unix-seconds timestamp, in the device timezone. */
    fun formatJalaliDate(epochSeconds: Long): String = runCatching {
        val date = Instant.ofEpochSecond(epochSeconds).atZone(ZoneId.systemDefault())
        val (jy, jm, jd) = toJalali(date.year, date.monthValue, date.dayOfMonth)
        "${faDigits(jd)} ${JALALI_MONTHS[jm - 1]} ${faDigits(jy)}"
    }.getOrDefault("")

    /**
     * Human "time left" label with the granularity the user asked for:
     * days while days remain, hours while hours remain, minutes at the end —
     * never the mixed "X روز و Y ساعت" shape.
     */
    fun remainingLabel(expiresAtEpochSec: Long, nowMillis: Long): String {
        val remainingMs = expiresAtEpochSec * 1000L - nowMillis
        if (remainingMs <= 0L) return "اعتبار تمام شده"
        val totalMinutes = remainingMs / 60_000L
        val days = totalMinutes / (60L * 24L)
        val hours = (totalMinutes % (60L * 24L)) / 60L
        val minutes = totalMinutes % 60L
        return when {
            days >= 1 -> "${faDigits(days)} روز"
            hours >= 1 -> "${faDigits(hours)} ساعت"
            else -> "${faDigits(minutes.coerceAtLeast(1))} دقیقه"
        }
    }

    /** Only the number of days left until the monthly volume is re-granted. */
    fun quotaResetLabel(resetAtEpochSec: Long, nowMillis: Long): String {
        val remainingMs = resetAtEpochSec * 1000L - nowMillis
        if (remainingMs <= 0L) return "حجم ماهانه تازه شد ✓"
        val days = (remainingMs + DAY_MS - 1L) / DAY_MS // rounded up, at least 1
        return "${faDigits(days)} روز تا شارژ دوبارهٔ حجم"
    }

    private const val DAY_MS = 86_400_000L
}
