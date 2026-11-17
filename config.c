/*
 * These are very basic config file routines for the main module of CNTLM
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
 * Copyright (c) 2007 David Kubicek
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "globals.h"

config_t config_open(const char *fname) {
	FILE *fp = fopen(fname, "r");
	if (!fp)
		return NULL;
	char *buf = zmalloc(BUFSIZE);
	config_t cf = zmalloc(sizeof(*cf));
	char *key = NULL, *value = NULL;
	while (fgets(buf, BUFSIZE, fp)) {
		size_t length = strlen(buf), pos = 0, start;
		if (length == BUFSIZE - 1 && buf[length - 1] != '\n')
			goto invalid;
		while (pos < length && isspace((unsigned char)buf[pos])) ++pos;
		if (pos == length || buf[pos] == '#' || buf[pos] == ';')
			continue;
		if (buf[pos] == '[') {
			char *end = strchr(buf + pos, ']');
			if (!end) goto invalid;
			pos = end - buf + 1;
			while (pos < length && isspace((unsigned char)buf[pos])) ++pos;
			if (pos < length && buf[pos] != '#' && buf[pos] != ';') goto invalid;
			continue;
		}
		start = pos;
		while (pos < length && isalnum((unsigned char)buf[pos])) ++pos;
		if (pos == start || pos == length || !isspace((unsigned char)buf[pos]))
			goto invalid;
		key = substr(buf, start, pos - start);
		while (pos < length && isspace((unsigned char)buf[pos])) ++pos;
		if (pos == length || buf[pos] == '#' || buf[pos] == ';') {
			free(key); key = NULL;
			continue;
		}
		if (buf[pos] == '"') {
			size_t out = 0;
			int closed = 0;
			value = zmalloc(length + 1);
			for (++pos; pos < length; ++pos) {
				if (buf[pos] == '"') { closed = 1; ++pos; break; }
				if (buf[pos] == '\\' && pos + 1 < length &&
				    (buf[pos + 1] == '\\' || buf[pos + 1] == '"')) ++pos;
				value[out++] = buf[pos];
			}
			value[out] = 0;
			if (!closed) goto invalid;
			while (pos < length && isspace((unsigned char)buf[pos])) ++pos;
			if (pos < length && buf[pos] != '#' && buf[pos] != ';') goto invalid;
		} else {
			value = strdup(buf + pos);
			value[strcspn(value, "#")] = 0;
			trimr(value);
		}
		cf->options = hlist_add(cf->options, key, value, HLIST_NOALLOC, HLIST_NOALLOC);
		key = value = NULL;
	}
	if (ferror(fp)) goto invalid;
	compat_memset_s(buf, BUFSIZE, 0, BUFSIZE);
	free(buf);
	fclose(fp);
	return cf;
invalid:
	free(key);
	if (value) { compat_memset_s(value, strlen(value), 0, strlen(value)); free(value); }
	compat_memset_s(buf, BUFSIZE, 0, BUFSIZE);
	free(buf);
	fclose(fp);
	config_close(cf);
	return NULL;
}

void config_set(config_t cf, char *option, char *value) {
	cf->options = hlist_mod(cf->options, option, value, 1);
}

char *config_pop(config_t cf, const char *option) {
	char *tmp;

	tmp = hlist_get(cf->options, option);
	if (tmp) {
		char *original = tmp;
		tmp = strdup(original);
		compat_memset_s(original, strlen(original), 0, strlen(original));
		cf->options = hlist_del(cf->options, option);
	}

	return tmp;
}

int config_count(config_t cf) {
	return hlist_count(cf->options);
}

void config_close(config_t cf) {
	if (cf == NULL)
		return;

	for (hlist_t item = cf->options; item; item = item->next)
		if (item->value) compat_memset_s(item->value, strlen(item->value), 0, strlen(item->value));
	cf->options = hlist_free(cf->options);
	free(cf);
}
