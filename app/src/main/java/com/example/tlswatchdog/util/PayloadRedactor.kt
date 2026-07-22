package com.example.tlswatchdog.util

/**
 * Best-effort redaction of secret-bearing HTTP headers before any captured payload
 * is persisted. This is a defence-in-depth measure layered on top of blocked backups
 * (android:allowBackup="false") — it is heuristic, not a guarantee: it only recognises
 * well-formed cleartext HTTP header lines and does nothing for binary or non-HTTP flows.
 */
object PayloadRedactor {
    // Header lines whose values commonly carry credentials/session secrets.
    // Case-insensitive, multi-line; a value never spans lines in HTTP/1.x.
    private val SENSITIVE = Regex(
        "(?im)^(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)([ \\t]*:[ \\t]*).*$",
    )
    private const val MASK = "[REDACTED]"

    /** Replace the value of any sensitive header line, keeping the header name. */
    fun redactText(s: String): String =
        SENSITIVE.replace(s) { m -> m.groupValues[1] + m.groupValues[2] + MASK }

    /**
     * Redact over a byte payload via a lossless 1:1 (ISO-8859-1) view, so binary
     * handshakes (which never match the header regex) round-trip unchanged and only
     * genuine cleartext header values are masked.
     */
    fun redactBytes(b: ByteArray): ByteArray =
        redactText(String(b, Charsets.ISO_8859_1)).toByteArray(Charsets.ISO_8859_1)
}
