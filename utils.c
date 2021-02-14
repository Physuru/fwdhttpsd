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

long unsigned int stoui(char *str, unsigned char max_size) {
	if (max_size < 1 || max_size > 8) {
		fputs("warning: invalid max size (in bytes) passed to `stoui`\n", stderr);
		return 0;
	}
	max_size *= 8; // max size in bits on any sane system
	long long unsigned int r = 0, t;
	unsigned char x;
	while (*str) {
		t = r;
		t *= 10;
		x = *(str++) - '0';
		t += x;
		if (x > 9) {
			fputs("warning: invalid positive base 10 integer\n", stderr);
			return 0;
		}
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

struct http_service *find_service(char *name) {
	for (unsigned int i = 0; i < r_arg(n_http_services); ++i) {
		if (strncmp(name, r_arg(http_services)[i].name, r_arg(http_services)[i].name_len) == 0 &&
			name[r_arg(http_services)[i].name_len] == '\r') {
			return &r_arg(http_services)[i];
		}
	}
	return NULL;
}