package com.foxy.keygen.data

import android.util.Base64
import java.net.URLEncoder
import java.security.MessageDigest
import org.json.JSONObject

/**
 * درِ دوم iOS — پل بین کلیدساز و لبهٔ ابری (Cloudflare Worker «foxy-edge-main»).
 *
 * هر کلید FV1 به یک هویت VLESS اختصاصی تبدیل می‌شود، فقط با ریاضیات — بدون هیچ
 * ثبت‌نامی سمت سرور:
 *
 *     pk   = SHA-256(کلید، بدون فضای ابتدا/انتها)            → ۶۴ کاراکتر هِکس
 *     UUID = SHA-256("foxyvpn-ios-v1|" + pk)[0..16]           → فرمت UUID نسخهٔ ۵
 *
 * ⚠️ این فرمول باید «عیناً» با ورکر یکی بماند؛ اگر روزی عوض شد، هر دو طرف باید
 * با هم عوض شوند وگرنه همهٔ QRهای قبلی می‌شکنند. ورکر مرجع:
 * /home/z/my-project/foxyvpn-ios/worker.js (UUID_PREFIX + deriveUUID).
 *
 * کلید کاربر هیچ‌جا ذخیره نمی‌شود — فقط در حافظهٔ همین صفحه زندگی می‌کند
 * (کلید شامل توکن گیت‌هاب و رفرش‌توکن است؛ ذخیره‌سازی جدید ممنوع).
 */
object IoSPortal {

    /** دامنهٔ اختصاصی iOS روی کلادفلر (ورکر foxy-edge-main). */
    const val HOST = "ios.foxyv.kdns.fr"

    /** باید با UUID_PREFIX در ورکر یکی باشد. */
    const val UUID_PREFIX = "foxyvpn-ios-v1|"

    /** پاک‌سازی ورودی کاربر: فقط trim — کلید باید حرف‌به‌حرف همان باشد که صادر شده. */
    fun normalizeKey(raw: String): String = raw.trim()

    /** فقط شکل کلید: FV1.<payload>.<signature> */
    fun isValidKeyShape(raw: String): Boolean {
        val parts = normalizeKey(raw).split(".")
        return parts.size == 3 &&
            parts[0] == "FV1" &&
            parts[1].length in 24..4096 &&
            parts[2].length in 40..512
    }

    /**
     * pk عمومیِ این کلید برای مسیر ولتس: SHA-256 هِکسِ کلید.
     * کلید مخفی است (توکن گیت‌هاب داخلش است) → pk بدون کلید قابل حدس نیست و
     * هر کلید = یک مسیر + یک UUID یکتا.
     */
    fun portalKey(raw: String): String =
        sha256Hex(normalizeKey(raw).toByteArray(Charsets.UTF_8))

    /** UUID ولتس — عین فرمول deriveUUID در ورکر. */
    fun deriveUUID(pk: String): String {
        val digest = sha256((UUID_PREFIX + pk).toByteArray(Charsets.UTF_8)).copyOf(16)
        digest[6] = ((digest[6].toInt() and 0x0F) or 0x50).toByte() // نسخهٔ ۵
        digest[8] = ((digest[8].toInt() and 0x3F) or 0x80).toByte() // واریانت RFC 4122
        val hex = digest.joinToString("") { "%02x".format(it) }
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-" +
            "${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}"
    }

    /**
     * لینک VLESS — دقیقاً همان ساختاری که /sub در ورکر می‌سازد
     * (Happ/Streisand/Hiddify با اسکن یا باز کردنش وصل می‌شوند).
     */
    fun vlessLink(raw: String, name: String): String {
        val pk = portalKey(raw)
        val uuid = deriveUUID(pk)
        val label = name.trim().ifBlank { "FoxyVPN" }
        val path = jsUrlEncode("/$pk")
        val fragment = jsUrlEncode("$label iOS")
        return "vless://$uuid@$HOST:443" +
            "?encryption=none&security=tls&sni=$HOST&alpn=h2,http/1.1&fp=chrome" +
            "&type=ws&host=$HOST&path=$path#$fragment"
    }

    /**
     * لینک ساب‌اسکریپشن: ورکر خودش لینک ولتس تازه می‌سازد — اگر روزی پارامترها
     * عوض شد، QRهای «ساب» بدون ساخت نسخهٔ جدید درست می‌مانند.
     */
    fun subLink(raw: String, name: String): String {
        val pk = portalKey(raw)
        val label = name.trim().ifBlank { "FoxyVPN" }
        return "https://$HOST/sub?pk=$pk&name=${jsUrlEncode(label)}"
    }

    /** نام داخل خود کلید (برای پیش‌فرض‌گذاشتن برچسب کانفیگ). */
    fun keyPayloadName(raw: String): String? = runCatching {
        var b64 = normalizeKey(raw).split(".")[1]
            .replace('-', '+').replace('_', '/')
        while (b64.length % 4 != 0) b64 += "="
        val json = String(
            Base64.decode(b64, Base64.NO_WRAP),
            Charsets.UTF_8,
        )
        JSONObject(json).optString("name").takeIf { it.isNotBlank() }
    }.getOrNull()

    /**
     * مثل encodeURIComponent جاوااسکریپت: فاصله → %20 (نه +) تا رفتار مرورگر/اپ‌ها
     * با ورکر یکی بماند.
     */
    private fun jsUrlEncode(s: String): String =
        URLEncoder.encode(s, "UTF-8").replace("+", "%20")

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun sha256Hex(bytes: ByteArray): String =
        sha256(bytes).joinToString("") { "%02x".format(it) }
}
