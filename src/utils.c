// to-do count: 2

#include <openssl/ssl.h>

#include "args.h"
#include "general.h"

int chrcasecmp(char c1, char c2) {
	if (c1 >= 'A' && c1 <= 'Z') c1 += 'a' - 'A';
	if (c2 >= 'A' && c2 <= 'Z') c2 += 'a' - 'A';
	return c2 - c1;
}
#define memxmem_prototype(nm, chr_fn) \
char * nm (char *h, unsigned int h_len, char *s, unsigned int s_len) { \
	unsigned int x; \
	for (; h_len >= s_len; ++h, --h_len) { \
		for (x = 0; x < s_len; ++h, ++x) { \
			if (chr_fn(*h) != chr_fn(s[x])) { \
				h_len -= x; \
				goto s; \
			} \
		} \
		return h - x; \
		s:; \
	} \
	return NULL; \
}
memxmem_prototype(memncasemem, tolower);
memxmem_prototype(memnmem, (char));

unsigned char setuidgid(int uid, int gid, int chkn_uid, int chkn_gid) {
	char r = 1;
	r &= setgid(gid);
	r &= setegid(gid);
	r &= setuid(uid);
	r &= seteuid(uid);
	if (chkn_uid < 0) {
		return r;
	}
	return getuid() != chkn_uid && getgid() != chkn_gid;
}

struct uitos {
	char *str;
	unsigned char str_len;
};
struct uitos uitos(unsigned int i) {
	char r[11];
	r[10] = 0;
	char *p = r + 11;
	while (i) {
		*(--p) = (i % 10) + '0';
		i /= 10;
	}
	struct uitos ret = {
		.str = strdup(p),
		.str_len = r + 11 - p,
	};
	return ret;
}
long unsigned int stoui(char *str, unsigned char max_size, char end_char) {
	if (max_size < 1 || max_size > 8) {
		fputs("warning: invalid max size (in bytes) passed to `stoui`\n", stderr);
		return 0;
	}
	max_size *= 8; // max size in bits on any sane system
	long long unsigned int r = 0, t;
	unsigned char x;
	while (*str == '0') ++str;
	while (*str != end_char) {
		x = *(str++) - '0';
		if (x > 9) {
			fputs("warning: invalid positive base 10 integer (skipped)\n", stderr);
			continue;
		}
		t = r;
		t *= 10;
		t += x;
		if (t <= r) {
			fputs("warning: integer overflow\n", stderr);
			return 0;
		}
		r = t;
	}
	if (max_size != 64 && r >= ((long long unsigned int)1 << max_size)) {
		fprintf(stderr, "warning: %llu cannot be represented in %i bits\n", r, max_size);
		return 0;
	}
	return r;
}

// to-do: optimise
struct http_service *find_service(char *name) {
	for (unsigned int i = 0; i < r_arg(n_http_services); ++i) {
		if (strncmp(name, r_arg(http_services)[i].name, r_arg(http_services)[i].name_len) == 0 &&
			name[r_arg(http_services)[i].name_len] == '\r') {
			return &r_arg(http_services)[i];
		}
	}
	struct http_service *r = &r_arg(default_http_service);
	if (r->name == NULL) {
		r = NULL;
	}
	return r;
}

void skip_space_tab(char **str) {
	skip_space_tab_start:;
	switch (**str) {
		case ' ':
		case '\t': {
			++*str;
			goto skip_space_tab_start;
		}
	}
}
void skip_to_cr(char **str) {
	while (**str != '\r') {
		if (**str == 0) {
			*str = NULL;
			return;
		}
		++*str;
	}
}

void find_headers(char *str, char *str_end, short unsigned int n, ...) {
	if (!n) {
		return;
	}
	--str_end;
	struct entry {
		char **str;
		size_t len;
		struct entry *next;
	};
	struct entry list[n];
	struct entry *head = list;
	struct entry **entry;
	va_list args;
	va_start(args, n);
	for (unsigned int i = 0; i < n; ++i) {
		list[n].str = va_arg(args, char **);
		list[n].len = strlen(*(list[n].str));
		list[n].next = list + i + 1;
	}
	va_end(args);
	list[n - 1].next = NULL;
	while (str < str_end) {
		if (*str == '\r' && *str == '\n') {
			break;
		}
		entry = &head;
		while (*entry != NULL) {
			if ((*entry)->str == NULL || strncasecmp(str, *((*entry)->str), (*entry)->len) != 0) {
				entry = &((*entry)->next);
				continue;
			}
			*((*entry)->str) = str;
			*entry = (*entry)->next;
			break;
		}
		skip_to_cr(&str);
		if (str == NULL) {
			return;
		}
		str += 2;
	}

	entry = &head;
	while (*entry != NULL) {
		*((*entry)->str) = NULL;
		entry = &((*entry)->next);
	}
}

// to-do: consider removing this function
void quick_respond(SSL *ssl, unsigned char protocol_id, char *status, char *resp_body) {
	if (protocol_id != 1) {
		return;
	}
	unsigned int status_len = strlen(status);
	unsigned int resp_body_len = strlen(resp_body);
	unsigned long long len = 50 + status_len + 10 + resp_body_len;
	char str[len];
	char *ptr = str;

	strncpy(ptr, "HTTP/1.1 ", 9);
	ptr += 9;

	strncpy(ptr, status, status_len);
	ptr += status_len;

	strncpy(ptr, "\r\nConnection: close\r\nContent-Length: ", 37);
	ptr += 37;

	struct uitos x = uitos(resp_body_len);
	strncpy(ptr, x.str, x.str_len);
	free(x.str);
	ptr += x.str_len;

	*(ptr++) = '\r';
	*(ptr++) = '\n';
	*(ptr++) = '\r';
	*(ptr++) = '\n';

	strncpy(ptr, resp_body, resp_body_len);

	SSL_write(ssl, str, len);
}