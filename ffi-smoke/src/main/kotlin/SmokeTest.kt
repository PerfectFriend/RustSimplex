package smoke

import uniffi.smp_rs.*

/**
 * The FFI facade must be callable from Kotlin — this is the only way to prove
 * it (a Rust-only test would prove nothing about the bindings).
 *
 * The check is deliberately offline: `createContact` validates the key hash
 * BEFORE it touches the network, so a bad key hash must come back as an
 * ordinary error value, not as a crash and not as a silent success.
 */
fun main() {
    val badKeyHash = "00" // valid hex, but not 32 bytes

    var thrown: Throwable? = null
    try {
        createContact("127.0.0.1", 5222.toUShort(), badKeyHash, "smoke")
        System.err.println("FAIL: createContact accepted a 1-byte key hash")
        kotlin.system.exitProcess(1)
    } catch (e: Throwable) {
        thrown = e
    }

    val message = thrown?.message ?: ""
    check(message.contains("keyhash")) {
        "FAIL: expected a keyhash error, got: $thrown"
    }
    check(thrown is FfiErrorKind) {
        "FAIL: expected the uniffi error type, got: ${thrown!!::class.java.name}"
    }
    println("OK: the Kotlin caller got a typed error: $message")
}
