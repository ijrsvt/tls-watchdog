/*
 * native_bridge.c — JNI glue between the Kotlin VpnService and the zdtun
 * userspace TCP/UDP forwarding engine.
 *
 *   - own the TUN fd and run zdtun's select() loop on a dedicated thread
 *   - write reply packets back into the TUN (send_client)
 *   - VpnService.protect() every outbound socket zdtun opens (on_socket_open)
 *   - per connection: assign an id, count bytes/packets, time it, and (for
 *     non-TLS/QUIC flows only) accumulate request/response payload up to a cap
 *   - report the first payload (onFlow), periodic live updates (onFlowUpdate)
 *     and final stats (onFlowClose) up to Kotlin
 */

#include <jni.h>
#include <stdint.h>
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
#define CLASSIFY_SNAP 640        // bytes handed to onFlow (enough for SNI / Host header)
#define SEG_MAX 2048             // one TUN segment fits here
#define RECORD_CAP_MAX (4 * 1024 * 1024)  // hard ceiling on per-direction recording
#define PURGE_INTERVAL_SEC 5
#define LIVE_INTERVAL_SEC 2

static JavaVM *g_vm = NULL;

typedef struct {
    int tun_fd;
    int stop_pipe[2];
    int mtu;
    int record_cap;         // max payload bytes per direction (0 = recording off)
    volatile int running;
    pthread_t thread;
    uint64_t flow_counter;

    JNIEnv *env;            // valid only on the capture thread
    jobject callbacks;
    jmethodID mid_protect;        // boolean protectSocket(int)
    jmethodID mid_on_flow;        // void onFlow(long,int,int,byte[],int,byte[],int,byte[])
    jmethodID mid_on_flow_update; // void onFlowUpdate(long,long,long,int,long,byte[],byte[])
    jmethodID mid_on_flow_close;  // void onFlowClose(long,long,long,int,long,byte[],byte[])
} capture_ctx;

typedef struct {
    uint64_t id;
    int reported;
    int classified;         // decided should_record yet?
    int should_record;      // 1 for cleartext flows we keep payload for
    uint64_t bytes_out;
    uint64_t bytes_in;
    uint32_t pkts_out;
    uint32_t pkts_in;
    int64_t start_ms;
    char *req_buf;  int req_len;  int req_cap;
    char *resp_buf; int resp_len; int resp_cap;
} conn_state;

static capture_ctx g_ctx;

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// TLS record (0x16 0x03) or QUIC long header => encrypted, don't record payload.
static int is_encrypted_start(uint8_t ipproto, const uint8_t *d, int len) {
    if (len < 2) return 0;
    if (ipproto == IPPROTO_TCP)
        return (d[0] == 0x16 && d[0 + 1] == 0x03);
    if (ipproto == IPPROTO_UDP)
        return ((d[0] & 0xc0) == 0xc0); // QUIC long header (Initial)
    return 0;
}

// Append into a buffer that grows geometrically up to `max`.
static void grow_append(char **buf, int *len, int *cap, int max,
                        const char *data, int datalen) {
    if (max <= 0 || *len >= max || datalen <= 0) return;
    int want = *len + datalen;
    if (want > max) want = max;
    if (want > *cap) {
        int newcap = *cap ? *cap : 4096;
        while (newcap < want) newcap <<= 1;
        if (newcap > max) newcap = max;
        char *nb = realloc(*buf, newcap);
        if (!nb) return;
        *buf = nb;
        *cap = newcap;
    }
    int space = max - *len;
    int n = datalen < space ? datalen : space;
    memcpy(*buf + *len, data, n);
    *len += n;
}

/* ------------------------------------------------------------------ */
/* Upcalls                                                            */
/* ------------------------------------------------------------------ */

static jbyteArray ip_to_bytes(JNIEnv *env, const zdtun_5tuple_t *t, int is_src) {
    if (t->ipver == 4) {
        jbyteArray arr = (*env)->NewByteArray(env, 4);
        uint32_t v = is_src ? t->src_ip.ip4 : t->dst_ip.ip4;
        (*env)->SetByteArrayRegion(env, arr, 0, 4, (const jbyte *) &v);
        return arr;
    }
    jbyteArray arr = (*env)->NewByteArray(env, 16);
    const void *p = is_src ? (const void *) &t->src_ip.ip6 : (const void *) &t->dst_ip.ip6;
    (*env)->SetByteArrayRegion(env, arr, 0, 16, (const jbyte *) p);
    return arr;
}

static void report_flow(capture_ctx *c, uint64_t flow_id, const zdtun_5tuple_t *t,
                        const uint8_t *l7, int l7len) {
    JNIEnv *env = c->env;
    jbyteArray src = ip_to_bytes(env, t, 1);
    jbyteArray dst = ip_to_bytes(env, t, 0);
    int clen = l7len < CLASSIFY_SNAP ? l7len : CLASSIFY_SNAP;
    jbyteArray first = (*env)->NewByteArray(env, clen);
    (*env)->SetByteArrayRegion(env, first, 0, clen, (const jbyte *) l7);

    (*env)->CallVoidMethod(env, c->callbacks, c->mid_on_flow,
                           (jlong) flow_id, (jint) t->ipver, (jint) t->ipproto,
                           src, (jint) ntohs(t->src_port),
                           dst, (jint) ntohs(t->dst_port), first);

    (*env)->DeleteLocalRef(env, src);
    (*env)->DeleteLocalRef(env, dst);
    (*env)->DeleteLocalRef(env, first);
}

// Emit accumulated stats + payload via the given method (update or close).
static void emit_flow(capture_ctx *c, conn_state *cs, jmethodID mid) {
    JNIEnv *env = c->env;
    jbyteArray req = (*env)->NewByteArray(env, cs->req_len);
    if (cs->req_len > 0)
        (*env)->SetByteArrayRegion(env, req, 0, cs->req_len, (const jbyte *) cs->req_buf);
    jbyteArray resp = (*env)->NewByteArray(env, cs->resp_len);
    if (cs->resp_len > 0)
        (*env)->SetByteArrayRegion(env, resp, 0, cs->resp_len, (const jbyte *) cs->resp_buf);

    (*env)->CallVoidMethod(env, c->callbacks, mid,
                           (jlong) cs->id,
                           (jlong) cs->bytes_out, (jlong) cs->bytes_in,
                           (jint) (cs->pkts_out + cs->pkts_in),
                           (jlong) (now_ms() - cs->start_ms), req, resp);

    (*env)->DeleteLocalRef(env, req);
    (*env)->DeleteLocalRef(env, resp);
}

// Decide (once) whether this flow's payload should be recorded.
static void maybe_classify(capture_ctx *c, conn_state *cs, uint8_t ipproto,
                           const uint8_t *d, int len) {
    if (cs->classified) return;
    cs->classified = 1;
    cs->should_record = (c->record_cap > 0) && !is_encrypted_start(ipproto, d, len);
}

/* ------------------------------------------------------------------ */
/* zdtun callbacks                                                    */
/* ------------------------------------------------------------------ */

static int cb_send_client(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn) {
    capture_ctx *c = (capture_ctx *) zdtun_userdata(tun);
    conn_state *cs = (conn_state *) zdtun_conn_get_userdata(conn);
    if (cs) {
        cs->bytes_in += pkt->len;
        cs->pkts_in++;
        if (pkt->l7_len > 0) {
            // Server-speaks-first: classify/report from the response if the
            // client hasn't sent anything yet.
            maybe_classify(c, cs, pkt->tuple.ipproto, (const uint8_t *) pkt->l7, pkt->l7_len);
            if (!cs->reported) {
                cs->reported = 1;
                report_flow(c, cs->id, zdtun_conn_get_5tuple(conn),
                            (const uint8_t *) pkt->l7, pkt->l7_len);
            }
            if (cs->should_record)
                grow_append(&cs->resp_buf, &cs->resp_len, &cs->resp_cap,
                            c->record_cap, pkt->l7, pkt->l7_len);
        }
    }
    ssize_t n = write(c->tun_fd, pkt->buf, pkt->len);
    if (n != pkt->len) {
        LOGE("tun write failed: %zd/%d (errno=%d)", n, pkt->len, errno);
        return -1;
    }
    return 0;
}

static void cb_on_socket_open(zdtun_t *tun, socket_t sock) {
    capture_ctx *c = (capture_ctx *) zdtun_userdata(tun);
    if (!c->env || !c->callbacks) return;
    jboolean ok = (*c->env)->CallBooleanMethod(c->env, c->callbacks, c->mid_protect, (jint) sock);
    if (!ok) LOGE("protect(%d) failed", sock);
}

static int cb_on_connection_open(zdtun_t *tun, zdtun_conn_t *conn) {
    capture_ctx *c = (capture_ctx *) zdtun_userdata(tun);
    conn_state *cs = calloc(1, sizeof(conn_state));
    if (cs) {
        cs->id = ++c->flow_counter;
        cs->start_ms = now_ms();
        zdtun_conn_set_userdata(conn, cs);
    }
    return 0;
}

static void cb_on_connection_close(zdtun_t *tun, const zdtun_conn_t *conn) {
    capture_ctx *c = (capture_ctx *) zdtun_userdata(tun);
    conn_state *cs = (conn_state *) zdtun_conn_get_userdata(conn);
    if (!cs) return;
    if (cs->reported && c->env && c->callbacks)
        emit_flow(c, cs, c->mid_on_flow_close);
    free(cs->req_buf);
    free(cs->resp_buf);
    free(cs);
}

// Iterator for periodic live updates of still-open flows.
static int live_iter(zdtun_t *tun, const zdtun_conn_t *conn, void *userdata) {
    capture_ctx *c = (capture_ctx *) userdata;
    conn_state *cs = (conn_state *) zdtun_conn_get_userdata(conn);
    if (cs && cs->reported)
        emit_flow(c, cs, c->mid_on_flow_update);
    return 0;
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
    time_t last_live = time(NULL);

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

        // Packets from the apps (client -> server).
        if (FD_ISSET(c->tun_fd, &rd)) {
            ssize_t n = read(c->tun_fd, buf, READ_BUF_SIZE);
            if (n > 0) {
                zdtun_pkt_t pinfo;
                int parsed = zdtun_parse_pkt(tun, buf, (uint16_t) n, &pinfo);
                int proto = (parsed == 0) ? pinfo.tuple.ipproto : 0;
                int is_data = (parsed == 0 &&
                               (proto == IPPROTO_TCP || proto == IPPROTO_UDP) &&
                               pinfo.l7_len > 0);
                uint8_t seg[SEG_MAX];
                int seglen = 0;
                zdtun_5tuple_t tuple;
                if (is_data) {
                    seglen = pinfo.l7_len < SEG_MAX ? pinfo.l7_len : SEG_MAX;
                    memcpy(seg, pinfo.l7, seglen);
                    tuple = pinfo.tuple;
                }

                zdtun_conn_t *conn = zdtun_easy_forward(tun, buf, (int) n);

                if (conn) {
                    conn_state *cs = (conn_state *) zdtun_conn_get_userdata(conn);
                    if (cs) {
                        cs->bytes_out += (uint64_t) n;
                        cs->pkts_out++;
                        if (is_data) {
                            maybe_classify(c, cs, (uint8_t) proto, seg, seglen);
                            if (cs->should_record)
                                grow_append(&cs->req_buf, &cs->req_len, &cs->req_cap,
                                            c->record_cap, (const char *) seg, seglen);
                            if (!cs->reported) {
                                cs->reported = 1;
                                report_flow(c, cs->id, &tuple, seg, seglen);
                            }
                        }
                    }
                }
            }
        }

        if (zdtun_handle_fd(tun, &rd, &wr) != 0)
            LOGE("zdtun_handle_fd error");

        time_t now = time(NULL);
        if (now - last_purge >= PURGE_INTERVAL_SEC) {
            zdtun_purge_expired(tun);
            last_purge = now;
        }
        if (now - last_live >= LIVE_INTERVAL_SEC) {
            zdtun_iter_connections(tun, live_iter, c);
            last_live = now;
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
    LOGI("capture thread started (tun_fd=%d mtu=%d record_cap=%d)", c->tun_fd, c->mtu, c->record_cap);
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
        JNIEnv *env, jobject thiz, jint tun_fd, jint mtu, jint record_cap, jobject callbacks) {
    if (g_ctx.running) {
        LOGE("capture already running");
        return;
    }
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.tun_fd = tun_fd;
    g_ctx.mtu = mtu;
    int rc = record_cap;
    if (rc < 0) rc = 0;
    if (rc > RECORD_CAP_MAX) rc = RECORD_CAP_MAX;
    g_ctx.record_cap = rc;
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
    g_ctx.mid_on_flow_update = (*env)->GetMethodID(env, cls, "onFlowUpdate", "(JJJIJ[B[B)V");
    g_ctx.mid_on_flow_close = (*env)->GetMethodID(env, cls, "onFlowClose", "(JJJIJ[B[B)V");
    if (!g_ctx.mid_protect || !g_ctx.mid_on_flow ||
        !g_ctx.mid_on_flow_update || !g_ctx.mid_on_flow_close) {
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
