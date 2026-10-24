package com.foxy.keygen.data

import java.util.Locale

/**
 * Decimal (1000-based) byte formatting: 1 GB = 1,000,000,000 bytes.
 * Volume plans are minted in decimal units (5 GB = 5e9 bytes), so displaying
 * them with binary units made every plan look ~7% smaller ("5 GB" -> "4.7 GB").
 * Both apps format bytes the same decimal way now.
 */
private const val UNIT = 1000.0
private val UNITS = listOf("KB", "MB", "GB", "TB", "PB")

fun formatBytes(bytes: Long): String {
    if (bytes < 0) return "\u2014"
    if (bytes < 1000) return "$bytes B"
    var value = bytes / UNIT
    var index = 0
    while (value >= UNIT && index < UNITS.lastIndex) {
        value /= UNIT
        index++
    }
    val pattern = if (value >= 100) "%.0f %s" else "%.1f %s"
    return String.format(Locale.US, pattern, value, UNITS[index])
}

fun formatBytesPerSecond(bytesPerSecond: Long): String =
    "${formatBytes(bytesPerSecond.coerceAtLeast(0))}/s"

/**
 * Binary (1024-based) formatting for the numbers that Mozilla's Guardian
 * backend reports. The account quota arrives in binary bytes — a 50 GB
 * account is really 50 GiB = 53,687,091,200 bytes — so formatting it with
 * the decimal helper inflated the card to «۵۳ گیگابایت». Quota numbers from
 * Guardian (maxBytes / X-Quota-*) go through here and show as 50 again.
 * Key plans stay decimal: they are minted as gb * 1e9 and the clients count
 * real TUN bytes against that decimal limit.
 */
private const val BIN_UNIT = 1024.0
private val BIN_UNITS = listOf("KB", "MB", "GB", "TB", "PB")

fun formatBytesBinary(bytes: Long): String {
    if (bytes < 0) return "\u2014"
    if (bytes < BIN_UNIT) return "$bytes B"
    var value = bytes / BIN_UNIT
    var index = 0
    while (value >= BIN_UNIT && index < BIN_UNITS.lastIndex) {
        value /= BIN_UNIT
        index++
    }
    val pattern = if (value >= 100) "%.0f %s" else "%.1f %s"
    return String.format(Locale.US, pattern, value, BIN_UNITS[index])
}
