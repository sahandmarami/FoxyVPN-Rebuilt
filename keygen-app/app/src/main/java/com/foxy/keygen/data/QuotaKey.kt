package com.foxy.keygen.data

import android.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/** Same wire format as the FoxyVPN client expects — see QuotaKey.kt there. */
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
}

object QuotaKeyCodec {

    /** Must match the public key embedded in the FoxyVPN client. */
    const val PUB_B64 = "7TLb/pjKRJ2vBHqQt8Y5kZ8XTs7uUj9ThtkRu/C8YGI="

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    fun b64urlEncode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    fun mint(
        name: String,
        gb: Long,
        mb: Long = 0L,
        expiresAtEpochSeconds: Long,
        refreshToken: String,
        gistId: String,
        githubToken: String,
        privateKeyB64: String,
    ): String {
        require(privateKeyB64.isNotBlank()) { "کلید امضا در این نسخه تعبیه نشده است" }
        val priv = Base64.decode(privateKeyB64, Base64.NO_WRAP)
        // fail early with a clear reason when the embedded signing key does
        // not match the public key the FoxyVPN client verifies with — the old
        // generic "self-check failed" gave no hint about the real cause
        val derivedPublic = Ed25519PrivateKeyParameters(priv, 0).generatePublicKey()
        val expectedPublic = Ed25519PublicKeyParameters(Base64.decode(PUB_B64, Base64.NO_WRAP), 0)
        if (!derivedPublic.getEncoded().contentEquals(expectedPublic.getEncoded())) {
            throw IllegalStateException(
                "کلید امضای این نسخه با کلید عمومی برنامهٔ اصلی هم‌خوانی ندارد (signing-key.sec را بررسی کنید)",
            )
        }
        val payload = QuotaKeyPayload(
            v = 1,
            name = name,
            gb = gb,
            mb = mb,
            exp = expiresAtEpochSeconds,
            id = randomId(),
            rt = refreshToken,
            gist = gistId,
            gt = githubToken,
        )
        val payloadJson = json.encodeToString(QuotaKeyPayload.serializer(), payload)
        val payloadB64 = b64urlEncode(payloadJson.toByteArray(Charsets.UTF_8))
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(priv, 0))
        signer.update(payloadB64.toByteArray(Charsets.US_ASCII), 0, payloadB64.length)
        val sig = b64urlEncode(signer.generateSignature())
        return "FV1.$payloadB64.$sig"
    }

    /** Verifies a minted key against the embedded public key (self-check). */
    fun verifySelf(key: String): Boolean = runCatching {
        val parts = key.split(".")
        if (parts.size != 3 || parts[0] != "FV1") return false
        val pub = Base64.decode(PUB_B64, Base64.NO_WRAP)
        val sig = runCatching {
            var b64 = parts[2]
            while (b64.length % 4 != 0) b64 += "="
            Base64.decode(b64, Base64.URL_SAFE or Base64.NO_WRAP)
        }.getOrNull() ?: return false
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(pub, 0))
        verifier.update(parts[1].toByteArray(Charsets.US_ASCII), 0, parts[1].length)
        verifier.verifySignature(sig)
    }.getOrDefault(false)

    fun randomId(): String {
        val bytes = ByteArray(4)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
