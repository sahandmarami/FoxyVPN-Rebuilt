package com.vauth.foxyvpn.data

import android.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Quota key format:  FV1.<b64url(payloadJson)>.<b64url(ed25519Signature)>
 *
 * The payload carries the person's display name, the volume plan (gb, 0 =
 * unlimited), an absolute expiry (unix seconds, 0 = never), a short key id,
 * the Firefox refresh token that grants direct access to the distributor's
 * account, and (optionally) the GitHub gist coordinates used for live usage
 * reporting. The signature is produced by the distributor's FoxyKeygen app;
 * this app only embeds the matching public key, so a key that was not signed
 * by the distributor is rejected.
 */
@Serializable
data class QuotaKeyPayload(
    val v: Int = 1,
    val name: String = "",
    val gb: Long = 0L,
    val mb: Long = 0L,
    val exp: Long = 0L,
    val id: String = "",
    val rt: String = "",
    val gist: String = "",
    val gt: String = "",
) {
    val isUnlimited: Boolean get() = gb <= 0L && mb <= 0L
    val limitBytes: Long
        get() = when {
            gb > 0L -> gb * BYTES_PER_GB
            mb > 0L -> mb * BYTES_PER_MB
            else -> 0L
        }

    companion object {
        const val BYTES_PER_GB: Long = 1_000_000_000L
        const val BYTES_PER_MB: Long = 1_000_000L
    }
}

data class QuotaKey(val payload: QuotaKeyPayload, val raw: String) {
    val keyId: String get() = payload.id
    val personName: String get() = payload.name.ifBlank { "کاربر" }
}

object QuotaKeyCodec {

    /** Ed25519 public key of the current FoxyKeygen release (base64, 32 bytes). */
    const val PUB_B64 =
        "7TLb/pjKRJ2vBHqQt8Y5kZ8XTs7uUj9ThtkRu/C8YGI="

    /**
     * Every signing public key this build accepts: the current one first,
     * then the earlier release keys — so keys already in our friends' hands
     * keep working after an update and nobody has to re-issue them.
     */
    val PUB_B64_LIST = listOf(
        PUB_B64,
        "hA5+kmj6X7JrqYWraZQY+q09q72mNUJx2aLPNnX/Ntw=", // v2.3.0 era
        "XxKVqJEz37vADD0ctmZSGPgvnS/o+1FCFf7CB1J3++E=", // v2.1.0 era
        "8b705IT0MNKJEXm+zwlKjlGiFazvWIkIoIYLR12cAvE=", // original era
    )

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    fun sign(payloadB64: String, privateKeyB64: String): String {
        val priv = Base64.decode(privateKeyB64, Base64.NO_WRAP)
        val signer = Ed25519Signer()
        signer.init(true, org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(priv, 0))
        signer.update(payloadB64.toByteArray(Charsets.US_ASCII), 0, payloadB64.length)
        return b64urlEncode(signer.generateSignature())
    }

    fun verify(payloadB64: String, signatureB64: String): Boolean =
        PUB_B64_LIST.any { pubB64 ->
            runCatching {
                val pub = Base64.decode(pubB64, Base64.NO_WRAP)
                val sig = b64urlDecode(signatureB64)
                val verifier = Ed25519Signer()
                verifier.init(false, Ed25519PublicKeyParameters(pub, 0))
                verifier.update(payloadB64.toByteArray(Charsets.US_ASCII), 0, payloadB64.length)
                verifier.verifySignature(sig)
            }.getOrDefault(false)
        }

    fun encode(payload: QuotaKeyPayload, privateKeyB64: String): String {
        val payloadJson = json.encodeToString(QuotaKeyPayload.serializer(), payload)
        val payloadB64 = b64urlEncode(payloadJson.toByteArray(Charsets.UTF_8))
        val sig = sign(payloadB64, privateKeyB64)
        return "FV1.$payloadB64.$sig"
    }

    /** Parses and verifies a user-pasted key. Throws [InvalidKeyException] with a Persian message. */
    fun parse(input: String): QuotaKey {
        val cleaned = input
            .replace(Regex("[\\p{Z}\\u200B-\\u200D\\uFEFF\\u00A0\\s]+"), "")
            .trim()
        val parts = cleaned.split(".")
        if (parts.size != 3 || parts[0] != "FV1") {
            throw InvalidKeyException("کلید واردشده معتبر نیست (قالب FV1 نیست)")
        }
        if (!verify(parts[1], parts[2])) {
            throw InvalidKeyException("امضای کلید تأیید نشد؛ کلید را از سازندهٔ کلید بگیرید")
        }
        val payloadJson = runCatching {
            String(b64urlDecode(parts[1]), Charsets.UTF_8)
        }.getOrNull() ?: throw InvalidKeyException("محتوای کلید قابل خواندن نیست")
        val payload = runCatching {
            json.decodeFromString(QuotaKeyPayload.serializer(), payloadJson)
        }.getOrNull() ?: throw InvalidKeyException("محتوای کلید نامعتبر است")
        if (payload.rt.isBlank()) {
            throw InvalidKeyException("کلید فاقد اعتبارنامهٔ اتصال است")
        }
        if (payload.exp in 1..(System.currentTimeMillis() / 1000L)) {
            throw InvalidKeyException("این کلید منقضی شده است")
        }
        return QuotaKey(payload, cleaned)
    }

    fun b64urlEncode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    fun b64urlDecode(text: String): ByteArray {
        var b64 = text.trim()
        while (b64.length % 4 != 0) b64 += "="
        return Base64.decode(b64, Base64.URL_SAFE or Base64.NO_WRAP)
    }
}

class InvalidKeyException(message: String) : Exception(message)
