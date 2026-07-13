package com.example.tlswatchdog.vpn

/**
 * JNI bridge to the native zdtun forwarding engine (see native_bridge.c).
 * Only one capture session may run at a time.
 */
object NativeBridge {
    init {
        System.loadLibrary("tlswatchdog")
    }

    /**
     * Take ownership of [tunFd] and start forwarding on a native thread.
     * [callbacks] receives socket-protect requests and per-flow reports,
     * invoked on the native capture thread.
     */
    external fun nativeStartCapture(tunFd: Int, mtu: Int, sampleBytes: Int, callbacks: VpnCallbacks)

    /** Stop the capture loop, join the thread and close the TUN fd. */
    external fun nativeStopCapture()
}

/** Implemented by the VpnService. Methods are called from the native thread. */
interface VpnCallbacks {
    /** Must call VpnService.protect(fd) so the outbound socket bypasses the tunnel. */
    fun protectSocket(fd: Int): Boolean

    /**
     * First client->server payload of a new flow. [flowId] uniquely identifies the
     * connection for this capture session and is echoed by [onFlowClose].
     * IPs are raw network-order address bytes (4 for IPv4, 16 for IPv6).
     */
    fun onFlow(
        flowId: Long,
        ipver: Int,
        proto: Int,
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        firstBytes: ByteArray,
    )

    /** Final stats for a previously reported flow, emitted when the connection closes. */
    fun onFlowClose(
        flowId: Long,
        bytesOut: Long,
        bytesIn: Long,
        packets: Int,
        durationMs: Long,
    )
}
