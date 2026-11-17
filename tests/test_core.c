/* Embedded regression tests; GPL-2.0-or-later. Host transport is stubbed here. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include "utils.h"
#include "auth.h"
#include "ntlm.h"
#include "xcrypt.h"
#include "config.h"
#include "proxy.h"
#include "pac.h"
#include "globals.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

ssize_t cntlm_io_read(int fd, void *p, size_t n) { return read(fd, p, n); }
ssize_t cntlm_io_write(int fd, const void *p, size_t n) { return write(fd, p, n); }
ssize_t cntlm_io_recv(int fd, void *p, size_t n, int f) { return recv(fd, p, n, f); }
ssize_t cntlm_io_send(int fd, const void *p, size_t n, int f) { return send(fd, p, n, f); }
int cntlm_io_close(int fd) { return close(fd); }
int cntlm_io_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *t) { return select(n, r, w, e, t); }
int cntlm_io_connect(const struct addrinfo *a, const char *name) { (void)a; (void)name; return -1; }
int cntlm_io_tunnel(int a, int b) { (void)a; (void)b; return 0; }
void cntlm_io_auth_timeout(int fd, int seconds) { (void)fd; (void)seconds; }
void cntlm_embed_log(int priority, const char *format, ...) { (void)priority; (void)format; }
void cntlm_embed_fatal(void) { abort(); }
uint64_t cntlm_embed_random(void) {
    uint64_t value;
    FILE *f = fopen("/dev/urandom", "rb");
    CHECK(f && fread(&value, sizeof(value), 1, f) == 1);
    fclose(f);
    return value;
}

static void put16(unsigned char *p, unsigned n) { p[0] = n; p[1] = n >> 8; }
static void put32(unsigned char *p, uint32_t n) { put16(p, n); put16(p+2, n >> 16); }
static void test_des_vector(void) {
    const char key[] = "\x13\x34\x57\x79\x9b\xbc\xdf\xf1";
    const char plain[] = "\x01\x23\x45\x67\x89\xab\xcd\xef";
    const char cipher[] = "\x85\xe8\x13\x54\x0f\x0a\xb4\x05";
    char encrypted[8], decrypted[8];
    gl_des_ctx context;
    gl_des_setkey(&context, key);
    gl_des_ecb_encrypt(&context, plain, encrypted);
    CHECK(!memcmp(encrypted, cipher, 8));
    gl_des_ecb_decrypt(&context, encrypted, decrypted);
    CHECK(!memcmp(decrypted, plain, 8));
}
static void challenge(unsigned char *p) {
    memset(p, 0, 64);
    memcpy(p, "NTLMSSP\0", 8); put32(p+8, 2); put32(p+20, 0x00888201);
    memcpy(p+24, "12345678", 8);
    put16(p+40, 4); put16(p+42, 4); put32(p+44, 48);
}
static void test_challenge_bounds(void) {
    unsigned char storage[65], *data = storage+1; /* deliberately unaligned */
    struct auth_s credentials = {0};
    credentials.hashntlm2 = 1;
    strcpy(credentials.user, "User"); strcpy(credentials.domain, "Domain");
    strcpy(credentials.workstation, "Host");
    challenge(data);
    char *response = NULL;
    CHECK(ntlm_response(&response, (char *)data, 52, &credentials) > 64);
    free(response);
    for (int length = 0; length < 48; ++length)
        CHECK(ntlm_response(&response, (char *)data, length, &credentials) == 0 && !response);
    data[0] = 'X'; CHECK(ntlm_response(&response, (char *)data, 52, &credentials) == 0);
    challenge(data); put32(data+8, 3);
    CHECK(ntlm_response(&response, (char *)data, 52, &credentials) == 0);
    challenge(data); put32(data+44, 0x10030); /* full 32-bit security-buffer offset */
    CHECK(ntlm_response(&response, (char *)data, 52, &credentials) == 0);
    challenge(data); put16(data+40, 5);
    CHECK(ntlm_response(&response, (char *)data, 53, &credentials) == 0);
    challenge(data); put16(data+48, 2); put16(data+50, 100);
    CHECK(ntlm_response(&response, (char *)data, 52, &credentials) == 0);
    challenge(data); put16(data+48, 2); /* missing AV_EOL */
    CHECK(ntlm_response(&response, (char *)data, 52, &credentials) == 0);
}
static config_t parse(const char *text) {
    char path[] = "/tmp/cntlm-core-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    close(fd);
    config_t cf = config_open(path);
    unlink(path);
    return cf;
}
static void test_configuration(void) {
    config_t cf = parse("Password \"a\\\\b\\\"c\"\nUsername Last");
    CHECK(cf && config_count(cf) == 2);
    char *value = config_pop(cf, "Password");
    CHECK(value && !strcmp(value, "a\\b\"c")); free(value);
    value = config_pop(cf, "Username");
    CHECK(value && !strcmp(value, "Last")); free(value);
    config_close(cf);
    CHECK(!parse("Password \"unterminated"));
    CHECK(!parse("Password \"valid\" trailing"));
    char line[8192]; memset(line, 'x', sizeof(line)); line[sizeof(line)-1] = 0;
    CHECK(!parse(line));
}
static void test_parent_reset(void) {
    for (int i = 0; i < 100; ++i) {
        CHECK(!parent_available());
        CHECK(!parent_add("127.0.0.1:0", 0));
        CHECK(!parent_add("127.0.0.1:65536", 0));
        CHECK(!parent_add("127.0.0.1:12junk", 0));
        CHECK(parent_add("proxy.test:3128", 0));
        CHECK(parent_add("[::1]:3128", 0));
        CHECK(parent_available());
        parent_free(); parent_free();
    }
}
static void test_pac_errors(void) {
    for (int i = 0; i < 4; ++i) {
        CHECK(pac_init());
        CHECK(!pac_parse_string("function invalid ("));
        CHECK(pac_parse_string("function FindProxyForURL(u,h) { return u.indexOf('\"') >= 0 ? 'DIRECT' : 'PROXY bad'; }"));
        CHECK(!strcmp(pac_find_proxy("http://target.test/\"", "target.test"), "DIRECT"));
        pac_initialized = 1;
        CHECK(proxy_connect(NULL, "http://target.test/\"", "target.test") == -2);
        CHECK(proxy_connect(NULL, "http://target.test/plain", "target.test") == -1);
        CHECK(pac_parse_string("function FindProxyForURL(u,h) { throw new Error('failure'); }"));
        CHECK(!pac_find_proxy("http://target.test", "target.test"));
        pac_initialized = 0;
        parent_free(); pac_cleanup(); pac_cleanup();
    }
}
int main(void) {
    test_des_vector(); test_challenge_bounds(); test_configuration(); test_parent_reset(); test_pac_errors();
    puts("cntlm embedded core regressions passed");
    return 0;
}
