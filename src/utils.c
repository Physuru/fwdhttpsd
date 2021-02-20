// to-do count: 3

#include <stdarg.h>

#include <openssl/ssl.h>

#include "args.h"
#include "general.h"
#include "utils.h"

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

// to-do: this can be improved
// e.g. some strings may begin with the same bytes
struct http_service *regular_find_service(char *name) {
	for (unsigned int i = 0; i < r_arg(n_http_services); ++i) {
		if (strncmp(name, r_arg(http_services)[i].name, r_arg(http_services)[i].name_len) == 0 &&
			name[r_arg(http_services)[i].name_len] == '\r') {
			return r_arg(http_services) + i;
		}
	}
	struct http_service *r = &r_arg(default_http_service);
	if (r->name == NULL) {
		r = NULL;
	}
	return r;
}
// `init_find_service` will probably be used later
struct http_service *init_find_service(char *name) {
	find_service = &regular_find_service;
	return find_service(name);
}
//struct http_service *(*find_service)(char *name) = &init_find_service;
struct http_service *(*find_service)(char *name) = &regular_find_service;

void skip_space_tab(char **str, char *after_str) {
	skip_space_tab_start:;
	if (*str >= after_str) {
		return;
	}
	switch (**str) {
		case ' ':
		case '\t': {
			++*str;
			goto skip_space_tab_start;
		}
	}
}
void skip_to_crlf(char **str, char *after_str) {
	if (str == NULL || *str == NULL) {
		return;
	}
	--after_str;
	while (*str < after_str) {
		if (**str == '\r' && *(*str + 1) == '\n') {
			return;
		} else if (**str == 0) {
			break;
		}
		++*str;
	}
	*str = NULL;
}

// to-do: this can be improved
// e.g. some strings may begin with the same bytes
void find_headers(char *str, char *str_end, unsigned int n, ...) {
	if (!n) {
		return;
	}
	char *passed_str_end = str_end;
	--str_end;
	struct entry {
		char **target;
		char *str;
		size_t len;
		struct entry *next;
	};
	struct entry list[n];
	struct entry *head = list;
	struct entry **entry = &head;
	va_list args;
	va_start(args, n);
	for (unsigned int i = 0; i < n; ++i) {
		(*entry)->str = va_arg(args, char *);
		(*entry)->target = va_arg(args, char **);
		if (*((*entry)->target) != NULL) {
			*entry = list + i + 1;
			continue;
		}
		(*entry)->len = strlen((*entry)->str);
		(*entry)->next = list + i + 1;
		entry = &((*entry)->next);
	}
	char **crlfcrlf = va_arg(args, char **);
	if (*crlfcrlf != NULL) {
		return;
	}
	*entry = NULL;
	va_end(args);
	while (str < str_end) {
		if (*str == '\r' && *(str + 1) == '\n') {
			*crlfcrlf = str - 2;
			break;
		}
		entry = &head;
		while (*entry != NULL) {
			if (strncasecmp(str, (*entry)->str, (*entry)->len) == 0 &&
				str + (*entry)->len < str_end &&
				*(str + (*entry)->len) == ':') {
				*((*entry)->target) = str;
				skip_to_crlf(&str, passed_str_end);
				if (str == NULL) {
					*((*entry)->target) = NULL;
					return;
				}
				*entry = (*entry)->next;
				str += 2;
				goto find_headers__str_while;
			}
			entry = &((*entry)->next);
		}

		skip_to_crlf(&str, passed_str_end);
		if (str == NULL) {
			return;
		}
		str += 2;

		find_headers__str_while:;
	}
}

// to-do: respond with text/html instead of text/plain for `<title>` and css
void quick_respond(SSL *ssl, unsigned char protocol_id, char *status, char *res_body) {
	if (protocol_id != 1) {
		return;
	}
	unsigned int status_len = strlen(status);
	unsigned int res_body_len = strlen(res_body);
	if (status_len < 0 || res_body_len < 0) {
		return;
	}
	unsigned long long len = 9 + status_len + 51 /* 37 + 4 + 10 */ + res_body_len + 1 /* probably unnecessary safety byte */;
	//                                                       ^ the max value of 31 (and 32) bits can be represented in base 10 using 10 digits
	char str[len];
	char *ptr = str;

	strncpy(ptr, "HTTP/1.1 ", 9);
	ptr += 9;

	strncpy(ptr, status, status_len);
	ptr += status_len;

	strncpy(ptr, "\r\nConnection: close\r\nContent-Length: ", 37);
	ptr += 37;

	struct uitos x = uitos(res_body_len);
	strncpy(ptr, x.str, x.str_len);
	free(x.str);
	ptr += x.str_len;

	*(ptr++) = '\r';
	*(ptr++) = '\n';
	*(ptr++) = '\r';
	*(ptr++) = '\n';

	strncpy(ptr, res_body, res_body_len);

	SSL_write(ssl, str, len);
}
void quick_respond_err(SSL *ssl, unsigned char protocol_id, unsigned char err_id) {
	switch (err_id) {
		case (CLIENT_PRTCL_NOT_IMPLEMENTED): {
			quick_respond(ssl, protocol_id, "501 Not Implemented", "Unsupported protocol.");
			return;
		}
		case (REQ_HEADERS_TOO_LONG): {
			quick_respond(ssl, protocol_id, "400 Bad Request", "Request HTTP header section is too long.");
			return;
		}
		case (NO_HOST_HEADER): {
			quick_respond(ssl, protocol_id, "400 Bad Request", "No service specified.");
			return;
		}
		case (INVALID_SERVICE): {
			quick_respond(ssl, protocol_id, "400 Bad Request", "Invalid service.");
			return;
		}
		case (SERVICE_DOWN): {
			quick_respond(ssl, protocol_id, "502 Bad Gateway", "Unable to connect to service.");
			return;
		}
		case (SERVER_PRTCL_NOT_IMPLEMENTED): {
			quick_respond(ssl, protocol_id, "501 Not Implemented", "The service responded using an unsupported protocol.");
			return;
		}
		case (HTTP_VERSION_MISMATCH): {
			quick_respond(ssl, protocol_id, "502 Bad Gateway", "HTTP version mismatch.");
			return;
		}
		case (RES_HEADERS_TOO_LONG): {
			quick_respond(ssl, protocol_id, "502 Bad Gateway", "Response HTTP header section is too long.");
			return;
		}
		case (RES_HEADERS_IMPROPER): {
			quick_respond(ssl, protocol_id, "502 Bad Gateway", "Response HTTP header section is too long.");
			return;
		}
	}
	quick_respond(ssl, protocol_id, "500 Internal Server Error", "Unknown error.");
}