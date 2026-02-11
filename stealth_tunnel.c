/*
 * ============================================================================
 * stealth_tunnel.c — تانل اختصاصی نامرئی
 * ============================================================================
 * ترافیک UDP (WireGuard) رو داخل TLS 1.3 مخفی میکنه
 * از بیرون دقیقاً شبیه یک وب‌سرور HTTPS عادی به نظر میاد
 *
 * معماری:
 *   [کلاینت‌ها] ←UDP→ [سرور ایران:cloud-agent] ←TLS→ [سرور خارج:cloud-agent] ←UDP→ [WireGuard]
 *
 * ویژگی‌ها:
 *   - TLS 1.3 transport (شبیه HTTPS)
 *   - HTTP fallback (Active Probe → وب‌سایت واقعی)
 *   - Process masquerade (نام پروسس: cloud-agent)
 *   - Traffic padding (سایز پکت عادی)
 *   - Heartbeat (شبیه HTTP keep-alive)
 *   - هیچ string مربوط به VPN در باینری نیست
 *
 * کامپایل:  make
 * اجرا:     ./cloud-agent -m server -l 443 -t 51820
 *            ./cloud-agent -m client -r SERVER_IP:443 -l 1080
 *
 * License: MIT
 * ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

/* ─── Constants ─── */
#define VERSION             "2.0"
#define MAX_CLIENTS         256
#define BUF_SIZE            65536
#define FRAME_HEADER_SIZE   4
#define MAX_FRAME_SIZE      (BUF_SIZE + 256)
#define TLS_STREAM_BUF_SIZE (MAX_FRAME_SIZE * 2)
#define HEARTBEAT_INTERVAL  15      /* seconds */
#define RECONNECT_DELAY     5
#define PAD_BLOCK_SIZE      128     /* pad to multiples of this */
#define MAX_PAD             200

/* Disguise name — نام پروسس */
#define DISGUISE_NAME       "cloud-agent"
#define DISGUISE_COMM       "cloud-agent"

/* Frame types — پروتکل داخلی */
#define FRAME_DATA          0x01
#define FRAME_HEARTBEAT     0x02
#define FRAME_PADDING       0x03
#define FRAME_HANDSHAKE     0x04

/* ─── HTTP Fallback Response ─── */
static const char HTTP_RESPONSE[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.25.3\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: max-age=3600\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Strict-Transport-Security: max-age=31536000\r\n"
    "Content-Length: 267\r\n"
    "\r\n"
    "<!DOCTYPE html><html><head><title>CloudTech Solutions</title>"
    "<meta charset=\"utf-8\"></head><body style=\"font-family:sans-serif;"
    "display:flex;align-items:center;justify-content:center;height:100vh;"
    "background:#667eea;color:#fff\">"
    "<h1>CloudTech Solutions</h1></body></html>";

static const char HTTP_404[] =
    "HTTP/1.1 404 Not Found\r\n"
    "Server: nginx/1.25.3\r\n"
    "Content-Length: 0\r\n"
    "Connection: close\r\n\r\n";

/* ─── Global State ─── */
static volatile int g_running = 1;

typedef struct {
    int                 mode;           /* 0=server, 1=client */
    char                listen_addr[64];
    int                 listen_port;
    char                remote_host[256];
    int                 remote_port;
    char                sni_host[256];
    char                target_host[64];
    int                 target_port;
    char                cert_file[256];
    char                key_file[256];
    char                psk[65];        /* pre-shared key */
    char                cert_pin[128];  /* SHA256 fingerprint pin (client) */
    int                 padding;        /* enable padding */
    int                 daemon_mode;
    int                 verbose;
} config_t;

typedef struct {
    SSL                *ssl;
    int                 tcp_fd;
    struct sockaddr_in  udp_addr;
    int                 udp_active;
    time_t              last_seen;
} client_t;

typedef struct {
    uint8_t             buf[TLS_STREAM_BUF_SIZE];
    size_t              len;
} tls_stream_t;

/* ─── Utility Functions ─── */

static void log_msg(const char *level, const char *fmt, ...) {
    /* لاگ شبیه nginx */
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm = localtime_r(&now, &tm_buf);
    char timebuf[64];
    if (tm) strftime(timebuf, sizeof(timebuf), "%Y/%m/%d %H:%M:%S", tm);
    else snprintf(timebuf, sizeof(timebuf), "0000/00/00 00:00:00");

    fprintf(stderr, "%s [%s] ", timebuf, level);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

#define LOG_INFO(...)   log_msg("info", __VA_ARGS__)
#define LOG_ERROR(...)  log_msg("error", __VA_ARGS__)
#define LOG_DEBUG(...)  if(g_cfg.verbose) log_msg("debug", __VA_ARGS__)

static config_t g_cfg;

/* ─── TLS Pinning (MITM Defense) ─── */

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int parse_sha256_fingerprint(const char *s, unsigned char out[32]) {
    if (!s) return -1;
    int hi = -1;
    size_t n = 0;
    for (const char *p = s; *p; p++) {
        int v = hex_value(*p);
        if (v < 0) continue; /* skip ':' ' ' '=' etc */
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= 32) return -1;
            out[n++] = (unsigned char)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) return -1;  /* odd number of hex chars */
    return (n == 32) ? 0 : -1;
}

static void format_sha256_fingerprint(const unsigned char in[32], char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    /* "AA:BB:...": 32 bytes => 95 chars + NUL */
    if (out_size < 96) return;
    char *w = out;
    for (int i = 0; i < 32; i++) {
        snprintf(w, out_size - (size_t)(w - out), "%02X%s", in[i], (i == 31) ? "" : ":");
        w += (i == 31) ? 2 : 3;
    }
    *w = '\0';
}

static int get_peer_cert_sha256(SSL *ssl, unsigned char out[32]) {
    if (!ssl) return -1;
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return -1;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int ok = X509_digest(cert, EVP_sha256(), md, &mdlen);
    X509_free(cert);
    if (!ok || mdlen != 32) return -1;
    memcpy(out, md, 32);
    return 0;
}

static int verify_cert_pin(SSL *ssl) {
    if (g_cfg.cert_pin[0] == '\0') return 1; /* no pin */

    unsigned char expected[32];
    if (parse_sha256_fingerprint(g_cfg.cert_pin, expected) != 0) {
        LOG_ERROR("invalid -F pin format (expected SHA256 fingerprint, 32 bytes)");
        return 0;
    }

    unsigned char actual[32];
    if (get_peer_cert_sha256(ssl, actual) != 0) {
        LOG_ERROR("failed to read peer certificate fingerprint");
        return 0;
    }

    if (CRYPTO_memcmp(actual, expected, 32) != 0) {
        char actual_str[96];
        format_sha256_fingerprint(actual, actual_str, sizeof(actual_str));
        LOG_ERROR("TLS cert pin mismatch. peer=%s", actual_str);
        return 0;
    }

    return 1;
}

/* ─── Process Disguise ─── */

static void disguise_process(int argc, char **argv) {
    /* تغییر نام پروسس */
    prctl(PR_SET_NAME, DISGUISE_COMM, 0, 0, 0);

    /* تغییر argv[0] */
    size_t total = 0;
    for (int i = 0; i < argc; i++)
        total += strlen(argv[i]) + 1;

    memset(argv[0], 0, total);
    strncpy(argv[0], DISGUISE_NAME, total - 1);

    /* تغییر /proc/self/comm */
    FILE *f = fopen("/proc/self/comm", "w");
    if (f) {
        fprintf(f, "%s", DISGUISE_COMM);
        fclose(f);
    }
}

/* ─── Crypto / Framing ─── */

/*
 * Frame format:
 *   [type:1][pad_len:1][length:2][payload:N][padding:pad_len]
 *
 * Total = 4 + N + pad_len
 */

static int frame_encode(uint8_t type, const uint8_t *data, int data_len,
                        uint8_t *out, int out_size, int do_pad) {
    if (data_len > 65535) return -1;

    int pad_len = 0;
    if (do_pad) {
        /* pad to PAD_BLOCK_SIZE boundary */
        int total = FRAME_HEADER_SIZE + data_len;
        int rem = total % PAD_BLOCK_SIZE;
        if (rem != 0)
            pad_len = PAD_BLOCK_SIZE - rem;
        if (pad_len > MAX_PAD)
            pad_len = MAX_PAD;
    }

    int total = FRAME_HEADER_SIZE + data_len + pad_len;
    if (total > out_size) return -1;

    out[0] = type;
    out[1] = (uint8_t)pad_len;
    out[2] = (uint8_t)((data_len >> 8) & 0xFF);
    out[3] = (uint8_t)(data_len & 0xFF);

    if (data_len > 0)
        memcpy(out + FRAME_HEADER_SIZE, data, data_len);

    /* Random padding */
    if (pad_len > 0)
        RAND_bytes(out + FRAME_HEADER_SIZE + data_len, pad_len);

    return total;
}

static int tls_stream_read(SSL *ssl, tls_stream_t *s) {
    if (s->len >= sizeof(s->buf)) return -1;
    int n = SSL_read(ssl, s->buf + s->len, (int)(sizeof(s->buf) - s->len));
    if (n > 0) s->len += (size_t)n;
    return n;
}

static int tls_stream_peek_frame(tls_stream_t *s, uint8_t *type,
                                 const uint8_t **payload, int *payload_len,
                                 size_t *frame_total) {
    if (s->len < FRAME_HEADER_SIZE) return 0;

    uint8_t pad_len = s->buf[1];
    int data_len = ((int)s->buf[2] << 8) | s->buf[3];
    if (data_len < 0 || data_len > BUF_SIZE) return -1;

    size_t total = FRAME_HEADER_SIZE + (size_t)data_len + (size_t)pad_len;
    if (total > sizeof(s->buf)) return -1;
    if (s->len < total) return 0;

    *type = s->buf[0];
    *payload = s->buf + FRAME_HEADER_SIZE;
    *payload_len = data_len;
    *frame_total = total;
    return 1;
}

static void tls_stream_consume(tls_stream_t *s, size_t n) {
    if (n >= s->len) {
        s->len = 0;
        return;
    }
    memmove(s->buf, s->buf + n, s->len - n);
    s->len -= n;
}

/* ─── SSL/TLS Setup ─── */

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    static const unsigned char alpn[] = "\x02h2\x08http/1.1";
    if (SSL_select_next_proto((unsigned char**)out, outlen,
                              alpn, sizeof(alpn) - 1,
                              in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX* create_ssl_ctx_server(const char *cert, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        LOG_ERROR("SSL_CTX_new failed");
        return NULL;
    }

    /* TLS 1.3 only */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Cipher suites — شبیه Cloudflare */
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305");

    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:"
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");

    /* ALPN — شبیه وب‌سرور */
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("Failed to load certificate: %s", cert);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("Failed to load private key: %s", key);
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Session tickets — شبیه سرور واقعی */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_num_tickets(ctx, 2);

    return ctx;
}

static SSL_CTX* create_ssl_ctx_client(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    /* Don't verify server cert (self-signed) */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* ALPN */
    const unsigned char alpn[] = "\x02h2\x08http/1.1";
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn) - 1);

    return ctx;
}

/* ─── Socket Helpers ─── */

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_tcp_listener(const char *addr, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    /* TCP settings شبیه nginx */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (addr && strlen(addr) > 0)
        inet_pton(AF_INET, addr, &sa.sin_addr);
    else
        sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 128) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int create_udp_socket(const char *addr, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Buffer sizes */
    int bufsize = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    if (port > 0) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        if (addr && strlen(addr) > 0)
            inet_pton(AF_INET, addr, &sa.sin_addr);
        else
            sa.sin_addr.s_addr = INADDR_ANY;

        if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
            close(fd);
            return -1;
        }
    }

    return fd;
}

static int wait_fd_ready(int fd, int want_read, int timeout_sec);

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        /* TCP keepalive */
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        /* Non-blocking connect with timeout */
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc == 0) {
            if (flags >= 0) fcntl(fd, F_SETFL, flags);
            break;
        }

        if (errno == EINPROGRESS) {
            int ready = wait_fd_ready(fd, 0, 10);
            if (ready > 0) {
                int so_error = 0;
                socklen_t slen = sizeof(so_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &slen) == 0 && so_error == 0) {
                    if (flags >= 0) fcntl(fd, F_SETFL, flags);
                    break;
                }
            }
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int wait_fd_ready(int fd, int want_read, int timeout_sec) {
    while (1) {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        if (want_read) FD_SET(fd, &rfds);
        else FD_SET(fd, &wfds);

        struct timeval tv;
        struct timeval *ptv = NULL;
        if (timeout_sec >= 0) {
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            ptv = &tv;
        }

        int ret = select(fd + 1, want_read ? &rfds : NULL, want_read ? NULL : &wfds, NULL, ptv);
        if (ret < 0 && errno == EINTR) continue;
        return ret;
    }
}

static int ssl_write_all(SSL *ssl, const uint8_t *buf, size_t len, int timeout_sec) {
    size_t off = 0;
    int fd = SSL_get_fd(ssl);

    while (off < len) {
        int n = SSL_write(ssl, buf + off, (int)(len - off));
        if (n > 0) {
            off += (size_t)n;
            continue;
        }

        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            int want_read = (err == SSL_ERROR_WANT_READ);
            if (wait_fd_ready(fd, want_read, timeout_sec) <= 0) return -1;
            continue;
        }
        return -1;
    }

    return 0;
}

static int ssl_read_all(SSL *ssl, uint8_t *buf, size_t len, int timeout_sec) {
    size_t off = 0;
    int fd = SSL_get_fd(ssl);

    while (off < len) {
        int n = SSL_read(ssl, buf + off, (int)(len - off));
        if (n > 0) {
            off += (size_t)n;
            continue;
        }

        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            int want_read = (err == SSL_ERROR_WANT_READ);
            if (wait_fd_ready(fd, want_read, timeout_sec) <= 0) return -1;
            continue;
        }
        return -1;
    }

    return 0;
}

/* ─── HTTP Detection (Active Probe Defense) ─── */

static int is_http_request(const uint8_t *data, int len) {
    if (len < 4) return 0;

    /* Check for HTTP methods */
    if (memcmp(data, "GET ", 4) == 0) return 1;
    if (memcmp(data, "POST", 4) == 0) return 1;
    if (memcmp(data, "HEAD", 4) == 0) return 1;
    if (memcmp(data, "PUT ", 4) == 0) return 1;
    if (memcmp(data, "PRI ", 4) == 0) return 1; /* HTTP/2 preface */
    if (len >= 7 && memcmp(data, "OPTIONS", 7) == 0) return 1;
    if (len >= 7 && memcmp(data, "CONNECT", 7) == 0) return 1;

    return 0;
}

static int load_psk_file(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size < 2) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;

    buf[n] = '\0';

    char *p = buf;
    while (*p && isspace((unsigned char)*p)) p++;

    char *end = p;
    while (*end && *end != '\n' && *end != '\r') end++;
    *end = '\0';

    if (strlen(p) >= out_size) return -1;
    strncpy(out, p, out_size - 1);
    out[out_size - 1] = '\0';
    return 0;
}

/* ─── PSK Authentication ─── */

static int authenticate_psk(SSL *ssl, const char *psk) {
    if (!psk || strlen(psk) == 0) return 1; /* no PSK = skip */

    uint8_t challenge[32], response[32], expected[32];
    RAND_bytes(challenge, sizeof(challenge));

    /* Server sends challenge */
    if (ssl_write_all(ssl, challenge, 32, 10) != 0) return 0;

    /* Compute expected = SHA256(challenge || psk) */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, challenge, 32);
    EVP_DigestUpdate(ctx, psk, strlen(psk));
    unsigned int elen;
    EVP_DigestFinal_ex(ctx, expected, &elen);
    EVP_MD_CTX_free(ctx);

    /* Read response */
    if (ssl_read_all(ssl, response, 32, 10) != 0) return 0;

    return (memcmp(response, expected, 32) == 0);
}

static int respond_psk(SSL *ssl, const char *psk) {
    if (!psk || strlen(psk) == 0) return 1;

    uint8_t challenge[32], response[32];

    if (ssl_read_all(ssl, challenge, 32, 10) != 0) return 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, challenge, 32);
    EVP_DigestUpdate(ctx, psk, strlen(psk));
    unsigned int elen;
    EVP_DigestFinal_ex(ctx, response, &elen);
    EVP_MD_CTX_free(ctx);

    if (ssl_write_all(ssl, response, 32, 10) != 0) return 0;
    return 1;
}

/* ─── Server Mode ─── */

typedef struct {
    SSL                *ssl;
    int                 tcp_fd;
    int                 udp_fd;
    struct sockaddr_in  last_client_addr;
    int                 has_client;
} server_conn_t;

static void* server_handle_client(void *arg) {
    server_conn_t *conn = (server_conn_t*)arg;
    SSL *ssl = conn->ssl;
    int tcp_fd = conn->tcp_fd;

    /* TLS Handshake */
    if (SSL_accept(ssl) <= 0) {
        /* Maybe it's an HTTP probe — read raw data */
        uint8_t probe[4096];
        int pn = recv(tcp_fd, probe, sizeof(probe), MSG_PEEK);
        if (pn > 0 && is_http_request(probe, pn)) {
            /* Send HTTP response (fallback) */
            send(tcp_fd, HTTP_RESPONSE, strlen(HTTP_RESPONSE), 0);
            LOG_DEBUG("HTTP probe handled");
        }
        goto cleanup;
    }

    LOG_DEBUG("TLS connection established");

    /* PSK Authentication */
    if (strlen(g_cfg.psk) > 0) {
        if (!authenticate_psk(ssl, g_cfg.psk)) {
            /* Failed auth → send HTTP response (looks like web server) */
            const char *msg = HTTP_404;
            ssl_write_all(ssl, (const uint8_t*)msg, strlen(msg), 5);
            LOG_DEBUG("PSK auth failed, sent HTTP 404");
            goto cleanup;
        }
        LOG_DEBUG("PSK authenticated");
    }

    /* Create UDP socket to target (WireGuard) */
    int udp_fd = create_udp_socket(NULL, 0);
    if (udp_fd < 0) goto cleanup;

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(g_cfg.target_port);
    inet_pton(AF_INET, g_cfg.target_host, &target_addr.sin_addr);

    /* Bidirectional forwarding: TLS ↔ UDP */
    tls_stream_t tls_in;
    memset(&tls_in, 0, sizeof(tls_in));
    uint8_t udp_buf[BUF_SIZE];
    uint8_t frame_buf[MAX_FRAME_SIZE];
    int ssl_fd = SSL_get_fd(ssl);
    time_t last_heartbeat = time(NULL);
    int connected = 1;

    set_nonblocking(ssl_fd);
    set_nonblocking(udp_fd);

    while (g_running && connected) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ssl_fd, &rfds);
        FD_SET(udp_fd, &rfds);

        int maxfd = (ssl_fd > udp_fd) ? ssl_fd : udp_fd;

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* TLS → UDP (client data → WireGuard) */
        if (FD_ISSET(ssl_fd, &rfds)) {
            int n = tls_stream_read(ssl, &tls_in);
            if (n <= 0) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    /* try again later */
                } else {
                    connected = 0;
                }
            }
            while (connected) {
                uint8_t ftype;
                const uint8_t *payload;
                int payload_len;
                size_t frame_total;

                int r = tls_stream_peek_frame(&tls_in, &ftype, &payload, &payload_len, &frame_total);
                if (r == 0) break;      /* need more bytes */
                if (r < 0) { connected = 0; break; }  /* invalid */

                if (ftype == FRAME_DATA && payload_len > 0) {
                    sendto(udp_fd, payload, payload_len, 0,
                           (struct sockaddr*)&target_addr, sizeof(target_addr));
                } else if (ftype == FRAME_HEARTBEAT) {
                    /* Echo heartbeat */
                    int flen = frame_encode(FRAME_HEARTBEAT, NULL, 0,
                                            frame_buf, sizeof(frame_buf),
                                            g_cfg.padding);
                    if (flen > 0 && ssl_write_all(ssl, frame_buf, (size_t)flen, 5) != 0)
                        connected = 0;
                }

                tls_stream_consume(&tls_in, frame_total);
            }
        }

        /* UDP → TLS (WireGuard response → client) */
        if (FD_ISSET(udp_fd, &rfds)) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            int n = recvfrom(udp_fd, udp_buf, BUF_SIZE, 0,
                            (struct sockaddr*)&from_addr, &from_len);

            if (n > 0) {
                int flen = frame_encode(FRAME_DATA, udp_buf, n,
                                       frame_buf, sizeof(frame_buf),
                                       g_cfg.padding);
                if (flen > 0 && ssl_write_all(ssl, frame_buf, (size_t)flen, 5) != 0)
                    connected = 0;
            }
        }

        /* Heartbeat */
        time_t now = time(NULL);
        if (now - last_heartbeat >= HEARTBEAT_INTERVAL) {
            int flen = frame_encode(FRAME_HEARTBEAT, NULL, 0,
                                   frame_buf, sizeof(frame_buf), g_cfg.padding);
            if (flen > 0 && ssl_write_all(ssl, frame_buf, (size_t)flen, 5) != 0)
                connected = 0;
            last_heartbeat = now;

            /* Random padding packet (traffic shaping) */
            if (g_cfg.padding && (rand() % 3 == 0)) {
                uint8_t dummy[64];
                RAND_bytes(dummy, sizeof(dummy));
                flen = frame_encode(FRAME_PADDING, dummy, sizeof(dummy),
                                   frame_buf, sizeof(frame_buf), 1);
                if (flen > 0 && ssl_write_all(ssl, frame_buf, (size_t)flen, 5) != 0)
                    connected = 0;
            }
        }
    }

    close(udp_fd);

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(tcp_fd);
    free(conn);
    return NULL;
}

static int run_server(void) {
    LOG_INFO("starting server on :%d → %s:%d",
             g_cfg.listen_port, g_cfg.target_host, g_cfg.target_port);

    SSL_CTX *ctx = create_ssl_ctx_server(g_cfg.cert_file, g_cfg.key_file);
    if (!ctx) return 1;

    int listen_fd = create_tcp_listener(g_cfg.listen_addr, g_cfg.listen_port);
    if (listen_fd < 0) {
        LOG_ERROR("failed to bind port %d: %s", g_cfg.listen_port, strerror(errno));
        SSL_CTX_free(ctx);
        return 1;
    }

    LOG_INFO("listening on :%d", g_cfg.listen_port);

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("accept: %s", strerror(errno));
            continue;
        }

        LOG_DEBUG("connection from %s:%d",
                  inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        /* Active probe / HTTP fallback (avoid consuming bytes via SSL_accept) */
        uint8_t probe[32];
        int pn = recv(client_fd, probe, sizeof(probe), MSG_PEEK);
        if (pn > 0 && is_http_request(probe, pn)) {
            send(client_fd, HTTP_RESPONSE, strlen(HTTP_RESPONSE), 0);
            close(client_fd);
            continue;
        }

        /* TCP keepalive */
        int opt = 1;
        setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
        int idle = 60;
        setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        server_conn_t *conn = calloc(1, sizeof(server_conn_t));
        conn->ssl = ssl;
        conn->tcp_fd = client_fd;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, server_handle_client, conn);
        pthread_attr_destroy(&attr);
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}

/* ─── Client Mode ─── */

static int run_client(void) {
    LOG_INFO("starting client :%d → %s:%d",
             g_cfg.listen_port, g_cfg.remote_host, g_cfg.remote_port);

    SSL_CTX *ctx = create_ssl_ctx_client();
    if (!ctx) return 1;

    if (g_cfg.cert_pin[0] == '\0') {
        LOG_INFO("warning: no TLS cert pin set (-F). MITM ممکنه ترافیک رو بخونه/جایگزین کنه");
    }

    /* Local UDP listener (clients connect here) */
    int udp_fd = create_udp_socket("0.0.0.0", g_cfg.listen_port);
    if (udp_fd < 0) {
        LOG_ERROR("failed to bind UDP :%d", g_cfg.listen_port);
        SSL_CTX_free(ctx);
        return 1;
    }

    LOG_INFO("UDP listening on :%d", g_cfg.listen_port);

    while (g_running) {
        /* Connect to remote server */
        LOG_INFO("connecting to %s:%d", g_cfg.remote_host, g_cfg.remote_port);

        int tcp_fd = tcp_connect(g_cfg.remote_host, g_cfg.remote_port);
        if (tcp_fd < 0) {
            LOG_ERROR("connection failed, retry in %ds", RECONNECT_DELAY);
            sleep(RECONNECT_DELAY);
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, tcp_fd);

        /* SNI — شبیه اتصال به یک سایت واقعی */
        if (strlen(g_cfg.sni_host) > 0)
            SSL_set_tlsext_host_name(ssl, g_cfg.sni_host);

        if (SSL_connect(ssl) <= 0) {
            LOG_ERROR("TLS handshake failed");
            SSL_free(ssl);
            close(tcp_fd);
            sleep(RECONNECT_DELAY);
            continue;
        }

        if (!verify_cert_pin(ssl)) {
            LOG_ERROR("TLS pin verification failed");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(tcp_fd);
            sleep(RECONNECT_DELAY);
            continue;
        }

        LOG_INFO("TLS connected to %s:%d", g_cfg.remote_host, g_cfg.remote_port);

        /* PSK auth */
        if (strlen(g_cfg.psk) > 0) {
            if (!respond_psk(ssl, g_cfg.psk)) {
                LOG_ERROR("PSK authentication failed");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(tcp_fd);
                sleep(RECONNECT_DELAY);
                continue;
            }
            LOG_INFO("PSK authenticated");
        }

        /* Bidirectional: Local UDP ↔ TLS tunnel */
        tls_stream_t tls_in;
        memset(&tls_in, 0, sizeof(tls_in));
        uint8_t udp_buf[BUF_SIZE];
        uint8_t frame_buf[MAX_FRAME_SIZE];
        int ssl_fd = SSL_get_fd(ssl);
        time_t last_heartbeat = time(NULL);
        int connected = 1;

        struct sockaddr_in client_addrs[MAX_CLIENTS];
        int client_count = 0;
        time_t client_times[MAX_CLIENTS];

        set_nonblocking(ssl_fd);
        set_nonblocking(udp_fd);

        while (g_running && connected) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(ssl_fd, &rfds);
            FD_SET(udp_fd, &rfds);

            int maxfd = (ssl_fd > udp_fd) ? ssl_fd : udp_fd;
            struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
            int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);

            if (ret < 0) {
                if (errno == EINTR) continue;
                break;
            }

            /* Local UDP → TLS tunnel */
            if (FD_ISSET(udp_fd, &rfds)) {
                struct sockaddr_in from_addr;
                socklen_t from_len = sizeof(from_addr);
                int n = recvfrom(udp_fd, udp_buf, BUF_SIZE, 0,
                                (struct sockaddr*)&from_addr, &from_len);

                if (n > 0) {
                    /* Track client */
                    int found = -1;
                    for (int i = 0; i < client_count; i++) {
                        if (client_addrs[i].sin_addr.s_addr == from_addr.sin_addr.s_addr &&
                            client_addrs[i].sin_port == from_addr.sin_port) {
                            found = i;
                            client_times[i] = time(NULL);
                            break;
                        }
                    }
                    if (found < 0 && client_count < MAX_CLIENTS) {
                        client_addrs[client_count] = from_addr;
                        client_times[client_count] = time(NULL);
                        client_count++;
                    }

                    int flen = frame_encode(FRAME_DATA, udp_buf, n,
                                           frame_buf, sizeof(frame_buf),
                                           g_cfg.padding);
                    if (flen > 0) {
                        if (ssl_write_all(ssl, frame_buf, (size_t)flen, 5) != 0)
                            connected = 0;
                    }
                }
            }

            /* TLS tunnel → Local UDP */
            if (FD_ISSET(ssl_fd, &rfds)) {
                int n = tls_stream_read(ssl, &tls_in);
                if (n <= 0) {
                    int err = SSL_get_error(ssl, n);
                    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                        /* try again later */
                    } else {
                        connected = 0;
                        break;
                    }
                }
                while (connected) {
                    uint8_t ftype;
                    const uint8_t *payload;
                    int payload_len;
                    size_t frame_total;

                    int r = tls_stream_peek_frame(&tls_in, &ftype, &payload, &payload_len, &frame_total);
                    if (r == 0) break;      /* need more bytes */
                    if (r < 0) { connected = 0; break; }

                    if (ftype == FRAME_DATA && payload_len > 0) {
                        /* Send to all known clients */
                        time_t now = time(NULL);
                        for (int i = 0; i < client_count; i++) {
                            if (now - client_times[i] < 120) {
                                sendto(udp_fd, payload, payload_len, 0,
                                       (struct sockaddr*)&client_addrs[i],
                                       sizeof(client_addrs[i]));
                            }
                        }
                    }

                    tls_stream_consume(&tls_in, frame_total);
                }
            }

            /* Heartbeat */
            time_t now = time(NULL);
            if (now - last_heartbeat >= HEARTBEAT_INTERVAL) {
                int flen = frame_encode(FRAME_HEARTBEAT, NULL, 0,
                                       frame_buf, sizeof(frame_buf), g_cfg.padding);
                if (flen > 0) {
                    if (ssl_write_all(ssl, frame_buf, (size_t)flen, 5) != 0)
                        connected = 0;
                }
                last_heartbeat = now;
            }

            /* Cleanup old clients */
            for (int i = client_count - 1; i >= 0; i--) {
                if (now - client_times[i] > 120) {
                    client_addrs[i] = client_addrs[client_count - 1];
                    client_times[i] = client_times[client_count - 1];
                    client_count--;
                }
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(tcp_fd);

        if (g_running) {
            LOG_INFO("disconnected, reconnecting in %ds...", RECONNECT_DELAY);
            sleep(RECONNECT_DELAY);
        }
    }

    close(udp_fd);
    SSL_CTX_free(ctx);
    return 0;
}

/* ─── Signal Handler ─── */

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ─── Main ─── */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Modes:\n"
        "  -m server    Server mode (foreign server)\n"
        "  -m client    Client mode (relay server)\n"
        "\n"
        "Server options:\n"
        "  -l PORT      Listen port (default: 443)\n"
        "  -t PORT      Target UDP port (default: 51820)\n"
        "  -c FILE      TLS certificate file\n"
        "  -k FILE      TLS private key file\n"
        "\n"
        "Client options:\n"
        "  -r HOST:PORT Remote server address\n"
        "  -l PORT      Local UDP listen port (default: 51820)\n"
        "  -s HOST      SNI host (default: www.google.com)\n"
        "  -F PIN       SHA256 cert fingerprint pin (recommended)\n"
        "\n"
        "Common options:\n"
        "  -p KEY       Pre-shared key for authentication\n"
        "  -f FILE      Load pre-shared key from file (recommended for systemd)\n"
        "  -P           Enable traffic padding\n"
        "  -d           Daemon mode\n"
        "  -v           Verbose output\n"
        "  -h           Show this help\n"
        "\n"
        "Examples:\n"
        "  Server: %s -m server -l 443 -t 51820 -c cert.pem -k key.pem -f /etc/cloud-agent/psk.txt -P\n"
        "  Client: %s -m client -r 1.2.3.4:443 -l 51820 -F <PIN> -f /etc/cloud-agent/psk.txt -P\n"
        "\n",
        prog, prog, prog);
}

int main(int argc, char **argv) {
    /* Default config */
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.mode = -1;
    g_cfg.listen_port = 443;
    g_cfg.target_port = 51820;
    g_cfg.padding = 0;
    strncpy(g_cfg.sni_host, "www.google.com", sizeof(g_cfg.sni_host));
    strncpy(g_cfg.target_host, "127.0.0.1", sizeof(g_cfg.target_host));
    strncpy(g_cfg.cert_file, "/etc/cloud-agent/cert.pem", sizeof(g_cfg.cert_file));
    strncpy(g_cfg.key_file, "/etc/cloud-agent/key.pem", sizeof(g_cfg.key_file));

    int opt;
    while ((opt = getopt(argc, argv, "m:l:t:r:s:F:c:k:p:f:Pdvh")) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "server") == 0) g_cfg.mode = 0;
                else if (strcmp(optarg, "client") == 0) g_cfg.mode = 1;
                else { fprintf(stderr, "Invalid mode\n"); return 1; }
                break;
            case 'l': g_cfg.listen_port = atoi(optarg); break;
            case 't': g_cfg.target_port = atoi(optarg); break;
            case 'r': {
                char *colon = strrchr(optarg, ':');
                if (colon) {
                    *colon = '\0';
                    strncpy(g_cfg.remote_host, optarg, sizeof(g_cfg.remote_host)-1);
                    g_cfg.remote_port = atoi(colon + 1);
                } else {
                    strncpy(g_cfg.remote_host, optarg, sizeof(g_cfg.remote_host)-1);
                    g_cfg.remote_port = 443;
                }
                break;
            }
            case 's': strncpy(g_cfg.sni_host, optarg, sizeof(g_cfg.sni_host)-1); break;
            case 'F': strncpy(g_cfg.cert_pin, optarg, sizeof(g_cfg.cert_pin)-1); break;
            case 'c': strncpy(g_cfg.cert_file, optarg, sizeof(g_cfg.cert_file)-1); break;
            case 'k': strncpy(g_cfg.key_file, optarg, sizeof(g_cfg.key_file)-1); break;
            case 'p': strncpy(g_cfg.psk, optarg, sizeof(g_cfg.psk)-1); break;
            case 'f':
                if (load_psk_file(optarg, g_cfg.psk, sizeof(g_cfg.psk)) != 0) {
                    fprintf(stderr, "Failed to read PSK file: %s\n", optarg);
                    return 1;
                }
                break;
            case 'P': g_cfg.padding = 1; break;
            case 'd': g_cfg.daemon_mode = 1; break;
            case 'v': g_cfg.verbose = 1; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (g_cfg.mode < 0) {
        fprintf(stderr, "Error: mode (-m) is required\n");
        usage(argv[0]);
        return 1;
    }

    /* Disguise process */
    disguise_process(argc, argv);

    /* Signals */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Init OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    srand(time(NULL) ^ getpid());

    /* Daemon mode */
    if (g_cfg.daemon_mode) {
        if (daemon(0, 0) < 0) {
            LOG_ERROR("daemon: %s", strerror(errno));
            return 1;
        }
    }

    /* Run */
    int ret;
    if (g_cfg.mode == 0)
        ret = run_server();
    else
        ret = run_client();

    EVP_cleanup();
    return ret;
}
