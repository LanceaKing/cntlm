/*
 * Parsing of pac files
 *
 * CNTLM is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * CNTLM is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Copyright (c) 2022 Francesco MDE aka fralken, David Kubicek
 *
 */

#include <netdb.h>
#include <arpa/inet.h>
#if defined(__ANDROID__) && __ANDROID_API__ < 24
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#else
#include <ifaddrs.h>
#endif

#include "duktape/duktape.h"
#include "pac_utils_js.h"
#include "pac.h"

/*
 * global duktape context
 */
duk_context *pac_ctx = NULL;
static char *pac_result;

static duk_ret_t native_dnsresolve(duk_context *ctx) {
	const char *hostname;
	struct addrinfo hints;
	struct addrinfo *addresses;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	hostname = duk_to_string(ctx, 0);

	int rc = getaddrinfo(hostname, NULL, &hints, &addresses);
	if (rc != 0) {
		duk_push_string(ctx, NULL);
	} else {
    	char s[INET_ADDRSTRLEN] = {0};
		for(struct addrinfo *p = addresses; p != NULL; p = p->ai_next) {
			if (p->ai_family == AF_INET) {
				getnameinfo(p->ai_addr, p->ai_addrlen, s, sizeof(s), NULL, 0, NI_NUMERICHOST);
				break;
			}
		}
		duk_push_string(ctx, s);
		freeaddrinfo(addresses);
	}

	return 1;
}

static duk_ret_t native_myipaddress(duk_context *ctx) {
#if defined(__ANDROID__) && __ANDROID_API__ < 24
	/* getifaddrs() is unavailable on the Android 19/21 minimum targets. */
	char address[INET_ADDRSTRLEN] = "127.0.0.1";
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd >= 0) {
		struct ifreq interfaces[64];
		struct ifconf config = { .ifc_len = sizeof(interfaces), .ifc_req = interfaces };
		if (ioctl(fd, SIOCGIFCONF, &config) == 0) {
			for (size_t i = 0; i < (size_t)config.ifc_len / sizeof(*interfaces); ++i) {
				struct sockaddr_in *sa = (struct sockaddr_in *)&interfaces[i].ifr_addr;
				if (sa->sin_family == AF_INET && (ntohl(sa->sin_addr.s_addr) >> 24) != 127) {
					inet_ntop(AF_INET, &sa->sin_addr, address, sizeof(address));
					break;
				}
			}
		}
		close(fd);
	}
	duk_push_string(ctx, address);
#else
	struct ifaddrs *addrs;

	int rc = getifaddrs(&addrs);
	if (rc != 0) {
		duk_push_string(ctx, "127.0.0.1");
	} else {
    	char s[INET_ADDRSTRLEN] = {0};
		for (struct ifaddrs *p = addrs; p != NULL; p = p->ifa_next) {
			if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET) {
				getnameinfo(p->ifa_addr, sizeof(struct sockaddr_in), s, sizeof(s), NULL, 0, NI_NUMERICHOST);
			}
		}
		duk_push_string(ctx, s);
		freeifaddrs(addrs);
	}
#endif

	return 1;
}

char *read_file(const char* filename) {
    FILE    *fd;
    char    *buf;
    size_t  len;
    size_t  ret;
    
    fd = fopen(filename, "r");
    if(fd == NULL)
        return NULL;
    
    fseek(fd, 0L, SEEK_END);
    len = ftell(fd);
    fseek(fd, 0L, SEEK_SET);	

    buf = (char*)calloc(len+1, sizeof(char));	
    if(buf == NULL) {
        fclose(fd);
        return NULL;
    }

    ret = fread(buf, sizeof(char), len, fd);
    if (ret < len) {
        free(buf);
        buf = NULL;
    } 
    fclose(fd);

    return buf;
}

// returns an escaped string or null if original string
// does not need to be escaped, or it is null, 
// or an allocation error happens
char *escape_string(const char *str) {
    if (!str)
        return NULL;

    int n = 0;
    const char *p = str;
    while (*p) {
        if (*p == '"' || *p == '\\')
            n++;
        p++;
    }
    if (n == 0)
        return NULL;

    char *newstr = (char*)calloc(p - str + n + 1, sizeof(char));
    if (!newstr)
        return NULL;

    char *q = newstr;
    p = str;
    while (*p) {
        if (*p == '"' || *p == '\\')
            *q++ = '\\';
        *q++ = *p++;
    }
    *q = 0;
    return newstr;
}

int pac_init(void) {
    pac_ctx = duk_create_heap_default();

    if (pac_ctx) {
        duk_push_c_function(pac_ctx, native_dnsresolve, 1);
        duk_put_global_string(pac_ctx, "dnsResolve");
        duk_push_c_function(pac_ctx, native_myipaddress, 0);
        duk_put_global_string(pac_ctx, "myIpAddress");

        if (duk_peval_string(pac_ctx, pac_utils_js) != 0) {
            duk_pop(pac_ctx); pac_cleanup(); return 0;
        }
        duk_pop(pac_ctx);
    }

    return pac_ctx != NULL;
}

int pac_parse_file(const char *pacfile) {
    char *pacstring = read_file(pacfile);
    if (!pacstring)
        return 0;

    int rc = pac_parse_string(pacstring);
    free(pacstring);

    return rc;
}

int pac_parse_string(const char *pacstring) {
    if (!pac_ctx)
        return 0;

    int ok = duk_peval_string(pac_ctx, pacstring) == 0;
    duk_pop(pac_ctx);
    return ok;
}

const char *pac_find_proxy(const char *url, const char *host) {
    if (!pac_ctx || !url || !host) return NULL;
    duk_get_global_string(pac_ctx, "FindProxyForURL");
    duk_push_string(pac_ctx, url);
    duk_push_string(pac_ctx, host);
    int ok = duk_pcall(pac_ctx, 2) == 0 && duk_is_string(pac_ctx, -1);
    const char *value = ok ? duk_get_string(pac_ctx, -1) : NULL;
    char *copy = value && strlen(value) <= 8192 ? strdup(value) : NULL;
    duk_pop(pac_ctx);
    free(pac_result);
    pac_result = copy;
    return pac_result;
}

void pac_cleanup(void) {
    free(pac_result); pac_result = NULL;
    if (pac_ctx) {
        duk_destroy_heap(pac_ctx);
        pac_ctx = NULL;
    }
}
