/* Optional host transport for the embedded build. GPL-2.0-or-later. */
#ifndef CNTLM_EMBEDDED_H
#define CNTLM_EMBEDDED_H

#ifdef CNTLM_EMBEDDED
/* Read libc declarations before substituting only cntlm's own calls. */
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <syslog.h>
#include <netdb.h>
#include <string.h>
#include <stdint.h>

int cntlm_io_connect(const struct addrinfo *, const char *proxy_name);
ssize_t cntlm_io_read(int, void *, size_t);
ssize_t cntlm_io_read_exact(int, void *, size_t);
ssize_t cntlm_io_write(int, const void *, size_t);
ssize_t cntlm_io_recv(int, void *, size_t, int);
ssize_t cntlm_io_send(int, const void *, size_t, int);
int cntlm_io_close(int);
int cntlm_io_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int cntlm_io_tunnel(int, int);
void cntlm_io_auth_timeout(int, int);
uint64_t cntlm_embed_random(void);
void cntlm_embed_fatal(void) __attribute__((noreturn));
void cntlm_embed_log(int, const char *, ...) __attribute__((format(printf, 2, 3)));

#define read cntlm_io_read
#define write cntlm_io_write
#define recv cntlm_io_recv
#define send cntlm_io_send
#define close cntlm_io_close
#define select cntlm_io_select
#define syslog cntlm_embed_log
#endif
#endif
