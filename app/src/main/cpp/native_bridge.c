/*
 * native_bridge.c — JNI glue between the Kotlin VpnService and the zdtun
 * userspace TCP/UDP forwarding engine.
 *
 * Responsibilities:
 *   - own the TUN fd and run zdtun's select() loop on a dedicated thread
 *   - write reply packets back into the TUN (send_client)
 *   - VpnService.protect() every outbound socket zdtun opens (on_socket_open),
 *     so forwarded traffic bypasses the tunnel instead of looping
 *   - snapshot the first client->server payload of each TCP flow and hand it
 *     up to Kotlin (onFlow) for TLS/cleartext classification
 */

#include <jni.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <android/log.h>

#include "zdtun.h"

#define TAG "tlswatchdog-native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define READ_BUF_SIZE 65536
#define L7_SNAP_MAX   4096   // upper bound on the per-flow payload sample
#define PURGE_INTERVAL_SEC 5

static JavaVM *g_vm = NULL;

typedef struct {
    int tun_fd;
    int stop_pipe[2];
    int mtu;
    int sample_bytes;       // how many bytes of the first payload to capture
    volatile int running;
    pthread_t thread;
    uint64_t flow_counter;  // assigns a unique id to each connection

    JNIEnv *env;            // valid only on the capture thread
    jobject callbacks;      // global ref to VpnCallbacks
    jmethodID mid_protect;    // boolean protectSocket(int fd)
    jmethodID mid_on_flow;    // void onFlow(long,int,int,byte[],int,byte[],int,byte[])
    jmethodID mid_on_flow_close; // void onFlowClose(long,long,long,int,long)
} capture_ctx;

// Per-connection accounting, hung off the zdtun connection's userdata.
typedef struct {
    uint64_t id;
    int reported;           // first client->server payload already reported
    uint64_t bytes_out;     // client -> server (IP bytes)
    uint64_t bytes_in;      // server -> client (IP bytes)
    uint32_t pkts_out;
    uint32_t pkts_in;
    time_t start;
} conn_state;

// Single active capture session (only one VpnService can run at a time).
static capture_ctx g_ctx;

/* ------------------------------------------------------------------ */
/* zdtun callbacks                                                    */
/* ------------------------------------------------------------------ */

// Send a reply packet from the network back to the apps: write it to the TUN.
static int cb_send_client(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn) {
    capture_ctx *c = (capture_ctx *) zdtun_userdata(tun);
    conn_state *cs = (conn_state *) zdtun_conn_get_userdata(conn);
    if (cs) {
        cs->bytes_in += pkt->len;
        cs->pkts_in++;
    }
    ssize_t n = write(c->tun_fd, pkt->buf, pkt->len);
    if (n != pkt->len) {
        LOGE("tun write failed: %zd/%d (errno=%d)", n, pkt->len, errno);
        return -1;
    }
    return 0;
}

// New connection: attach per-flow accounting state.
static int cb_on_connection_open(zdtun_t *tun, zdtun_conn_t *conn) {
    capture_ctx *c = (capture_ctx *) zdtun_userdata(tun);
    conn_state *cs = calloc(1, sizeof(conn_state));
    if (cs) {
        cs->id = ++c->flow_counter;
        cs->start = time(NULL);
        zdtun_conn_set_userdata(conn, cs);
    }
    return 0; // allow the connection
}

// Connection closed: emit final stats and free the per-flow state.
static void cb_on_connection_close(zdtun_t *tun, const zdtun_conn_t *conn) {
    capture_ctx *c = (capture_ctx *) zdtun_userdata(tun);
    conn_state *cs = (conn_state *) zdtun_conn_get_userdata(conn);
    if (!cs) return;
    if (cs->reported && c->env && c->callbacks) {
        jlong duration_ms = (jlong) (time(NULL) - cs->start) * 1000;
        (*c->env)->CallVoidMethod(c->env, c->callbacks, c->mid_on_flow_close,
                                  (jlong) cs->id,
                                  (jlong) cs->bytes_out,
                                  (jlong) cs->bytes_in,
                                  (jint) (cs->pkts_out + cs->pkts_in),
                                  duration_ms);
    }
    free(cs);
}

// Every outbound socket must be protect()ed or it would route back into us.
static void cb_on_socket_open(zdtun_t *tun, socket_t sock) {
    capture_ctx *c = (capture_ctx *) zdtun_userdata(tun);
    if (!c->env || !c->callbacks) return;
    jboolean ok = (*c->env)->CallBooleanMethod(c->env, c->callbacks, c->mid_protect, (jint) sock);
    if (!ok)
        LOGE("protect(%d) failed", sock);
}

/* ------------------------------------------------------------------ */
/* Flow reporting                                                     */
/* ------------------------------------------------------------------ */

static jbyteArray ip_to_bytes(JNIEnv *env, const zdtun_5tuple_t *t, int is_src) {
    if (t->ipver == 4) {
        jbyteArray arr = (*env)->NewByteArray(env, 4);
        // ip4 is stored in network byte order already.
        u_int32_t v = is_src ? t->src_ip.ip4 : t->dst_ip.ip4;
        (*env)->SetByteArrayRegion(env, arr, 0, 4, (const jbyte *) &v);
        return arr;
    } else {
        jbyteArray arr = (*env)->NewByteArray(env, 16);
        const void *p = is_src ? (const void *) &t->src_ip.ip6 : (const void *) &t->dst_ip.ip6;
        (*env)->SetByteArrayRegion(env, arr, 0, 16, (const jbyte *) p);
        return arr;
    }
}

static void report_flow(capture_ctx *c, uint64_t flow_id, const zdtun_5tuple_t *t,
                        const uint8_t *l7, int l7len) {
    JNIEnv *env = c->env;
    jbyteArray src = ip_to_bytes(env, t, 1);
    jbyteArray dst = ip_to_bytes(env, t, 0);
    jbyteArray first = (*env)->NewByteArray(env, l7len);
    (*env)->SetByteArrayRegion(env, first, 0, l7len, (const jbyte *) l7);

    (*env)->CallVoidMethod(env, c->callbacks, c->mid_on_flow,
                           (jlong) flow_id,
                           (jint) t->ipver,
                           (jint) t->ipproto,
                           src, (jint) ntohs(t->src_port),
                           dst, (jint) ntohs(t->dst_port),
                           first);

    (*env)->DeleteLocalRef(env, src);
    (*env)->DeleteLocalRef(env, dst);
    (*env)->DeleteLocalRef(env, first);
}

/* ------------------------------------------------------------------ */
/* Capture loop                                                       */
/* ------------------------------------------------------------------ */

static void capture_loop(capture_ctx *c) {
    zdtun_callbacks_t callbacks = {
            .send_client = cb_send_client,
            .on_socket_open = cb_on_socket_open,
            .on_connection_open = cb_on_connection_open,
            .on_connection_close = cb_on_connection_close,
    };
    zdtun_t *tun = zdtun_init(&callbacks, c);
    if (!tun) {
        LOGE("zdtun_init failed");
        return;
    }
    zdtun_set_mtu(tun, c->mtu);

    char *buf = malloc(READ_BUF_SIZE);
    time_t last_purge = time(NULL);

    while (c->running) {
        fd_set rd, wr;
        int max_fd = 0;
        zdtun_fds(tun, &max_fd, &rd, &wr);

        FD_SET(c->tun_fd, &rd);
        if (c->tun_fd > max_fd) max_fd = c->tun_fd;
        FD_SET(c->stop_pipe[0], &rd);
        if (c->stop_pipe[0] > max_fd) max_fd = c->stop_pipe[0];

        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int ret = select(max_fd + 1, &rd, &wr, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOGE("select failed: errno=%d", errno);
            break;
        }

        if (FD_ISSET(c->stop_pipe[0], &rd))
            break;

        // Packets coming from the apps (client -> server direction).
        if (FD_ISSET(c->tun_fd, &rd)) {
            ssize_t n = read(c->tun_fd, buf, READ_BUF_SIZE);
            if (n > 0) {
                // Snapshot the first client->server payload BEFORE forwarding,
                // because zdtun may rewrite the buffer in place.
                zdtun_pkt_t pinfo;
                int parsed = zdtun_parse_pkt(tun, buf, (uint16_t) n, &pinfo);
                int is_tcp_data = (parsed == 0 &&
                                   pinfo.tuple.ipproto == IPPROTO_TCP &&
                                   pinfo.l7_len > 0);
                uint8_t snap[L7_SNAP_MAX];
                int snaplen = 0;
                zdtun_5tuple_t tuple;
                if (is_tcp_data) {
                    int cap = c->sample_bytes;
                    snaplen = pinfo.l7_len < cap ? pinfo.l7_len : cap;
                    memcpy(snap, pinfo.l7, snaplen);
                    tuple = pinfo.tuple;  // struct copy, survives forwarding
                }

                zdtun_conn_t *conn = zdtun_easy_forward(tun, buf, (int) n);

                if (conn) {
                    conn_state *cs = (conn_state *) zdtun_conn_get_userdata(conn);
                    if (cs) {
                        // Count every outbound (client->server) packet.
                        cs->bytes_out += (uint64_t) n;
                        cs->pkts_out++;
                        // Report the first data segment of each TCP flow exactly once.
                        if (is_tcp_data && !cs->reported) {
                            cs->reported = 1;
                            report_flow(c, cs->id, &tuple, snap, snaplen);
                        }
                    }
                }
            }
        }

        // Sockets ready: let zdtun read from the network and reply via send_client.
        if (zdtun_handle_fd(tun, &rd, &wr) != 0)
            LOGE("zdtun_handle_fd error");

        time_t now = time(NULL);
        if (now - last_purge >= PURGE_INTERVAL_SEC) {
            zdtun_purge_expired(tun);
            last_purge = now;
        }
    }

    free(buf);
    zdtun_finalize(tun);
}

static void *thread_main(void *arg) {
    capture_ctx *c = (capture_ctx *) arg;
    JNIEnv *env = NULL;
    if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) {
        LOGE("AttachCurrentThread failed");
        return NULL;
    }
    c->env = env;
    LOGI("capture thread started (tun_fd=%d mtu=%d)", c->tun_fd, c->mtu);

    capture_loop(c);

    LOGI("capture thread exiting");
    (*g_vm)->DetachCurrentThread(g_vm);
    c->env = NULL;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* JNI entry points                                                   */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_com_example_tlswatchdog_vpn_NativeBridge_nativeStartCapture(
        JNIEnv *env, jobject thiz, jint tun_fd, jint mtu, jint sample_bytes, jobject callbacks) {
    if (g_ctx.running) {
        LOGE("capture already running");
        return;
    }
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.tun_fd = tun_fd;
    g_ctx.mtu = mtu;
    int sb = sample_bytes;
    if (sb < 16) sb = 16;                 // always enough to classify
    if (sb > L7_SNAP_MAX) sb = L7_SNAP_MAX;
    g_ctx.sample_bytes = sb;
    g_ctx.running = 1;
    if (pipe(g_ctx.stop_pipe) != 0) {
        LOGE("pipe() failed");
        g_ctx.running = 0;
        return;
    }

    g_ctx.callbacks = (*env)->NewGlobalRef(env, callbacks);
    jclass cls = (*env)->GetObjectClass(env, callbacks);
    g_ctx.mid_protect = (*env)->GetMethodID(env, cls, "protectSocket", "(I)Z");
    g_ctx.mid_on_flow = (*env)->GetMethodID(env, cls, "onFlow", "(JII[BI[BI[B)V");
    g_ctx.mid_on_flow_close = (*env)->GetMethodID(env, cls, "onFlowClose", "(JJJIJ)V");
    if (!g_ctx.mid_protect || !g_ctx.mid_on_flow || !g_ctx.mid_on_flow_close) {
        LOGE("failed to resolve callback methods");
        g_ctx.running = 0;
        return;
    }

    if (pthread_create(&g_ctx.thread, NULL, thread_main, &g_ctx) != 0) {
        LOGE("pthread_create failed");
        g_ctx.running = 0;
    }
}

JNIEXPORT void JNICALL
Java_com_example_tlswatchdog_vpn_NativeBridge_nativeStopCapture(
        JNIEnv *env, jobject thiz) {
    if (!g_ctx.running) return;
    g_ctx.running = 0;
    // Wake the select() loop immediately.
    char b = 1;
    if (write(g_ctx.stop_pipe[1], &b, 1) < 0) { /* best effort */ }
    pthread_join(g_ctx.thread, NULL);

    close(g_ctx.stop_pipe[0]);
    close(g_ctx.stop_pipe[1]);
    close(g_ctx.tun_fd);
    if (g_ctx.callbacks) {
        (*env)->DeleteGlobalRef(env, g_ctx.callbacks);
        g_ctx.callbacks = NULL;
    }
    LOGI("capture stopped");
}
