#define args_c
#include "args.h"
#include "general.h"
#include "utils.h"

#define TIMEOUT_DEFAULT 1500
#define THREAD_COUNT_DEFAULT 4
#define BUF_SZ_DEFAULT 0x1000

short unsigned int r_arg(timeout) = TIMEOUT_DEFAULT;
unsigned char r_arg(force_connection_close) = 0;
unsigned char r_arg(use_stack_buf) = 0;
int r_arg(uid);
int r_arg(gid);
char *r_arg(cert_path);
char *r_arg(private_key_path);
short unsigned int r_arg(thread_count) = THREAD_COUNT_DEFAULT, r_arg(buf_sz) = BUF_SZ_DEFAULT;
struct http_service *r_arg(http_services) = NULL;
struct http_service r_arg(default_http_service) = (struct http_service){ .name = NULL, 0 };
unsigned int r_arg(n_http_services) = 0;
// i'm not worried about the performance of this function because it's never called after `serve` is
int parse_args(char *argv[], char *env[]) {
	#define ARG_COMMON(x, y, z) (strcmp(argv[i], x) == 0) { \
		if (argv[i + 1] == NULL) { \
			fprintf(stderr, "argument `%s` is missing values\n", x); \
			return 0; \
		} \
		y = z(argv[i + 1]); \
		i += 2; \
	}
	unsigned int i = 1;
	while (argv[i]) {
		if ARG_COMMON("-u", r_arg(uid), stoui32)
		else if ARG_COMMON("-g", r_arg(gid), stoui32)
		else if ARG_COMMON("-c", r_arg(cert_path), (char *))
		else if ARG_COMMON("-k", r_arg(private_key_path), (char *))
		else if ARG_COMMON("-t", r_arg(thread_count), stoui16)
		else if ARG_COMMON("-w", r_arg(timeout), stoui16)
		else if ARG_COMMON("-b", r_arg(buf_sz), stoui16)
		else if (strcmp(argv[i], "-s") == 0) {
			if (r_arg(n_http_services) == 0xFFFFFFFF) {
				fputs("cannot add any more http services\n", stderr);
				i += 3;
				continue;
			}
			if (argv[i + 1] == NULL) {
				fprintf(stderr, "argument `%s` is missing values\n", "-s");
				return 0;
			}
			if ((argv[i + 2] != NULL && *argv[i + 2] != '-')) {
				unsigned char chr;
				for (unsigned int ii = 0; (chr = argv[i + 1][ii]); ++ii) {
					if ((chr < 'A' || chr > 'Z') && chr - '-' > 1 /* - and . */ && (chr < '0' || chr > '9')) {
						continue;
					}
				}
				r_arg(http_services) = realloc(r_arg(http_services), sizeof(struct http_service) * ++r_arg(n_http_services));
				r_arg(http_services)[r_arg(n_http_services) - 1].name = argv[i + 1];
				r_arg(http_services)[r_arg(n_http_services) - 1].name_len = strlen(argv[i + 1]);
				r_arg(http_services)[r_arg(n_http_services) - 1].port = htons(stoui16(argv[i + 2]));
				i += 3;
			} else {
				r_arg(default_http_service).name = "default";
				r_arg(default_http_service).name_len = 7;
				r_arg(default_http_service).port = htons(stoui16(argv[i + 1]));
				i += 2;
			}
		} else if (strcmp(argv[i], "-f") == 0) {
			r_arg(force_connection_close) = 1;
			i += 1;
		}  else if (strcmp(argv[i], "-a") == 0) {
			fputs("-a is unsafe and shouldn't be used\n", stderr);
			r_arg(use_stack_buf) = 1;
			i += 1;
		} else if (strcmp(argv[i], "-h") == 0) {
			printf("-c : path to certificate file\n-k : path to private key\n-s : optionally a service name (http request host header value), and a tcp port number (e.g. -s localhost 1234)\n-u : uid to run server with\n-g : gid to run server with\n-t : the amount of threads to be serving (default is %u)\n-w : timeout in ms (default is %u)\n-b : main buffer size (default is %u)\n-f : force `Connection: close` header in http v1.1 responses\n-r : the amount of times to retry finding headers\n-a : use alloca instead of malloc for `buf` (UNSAFE)\n-h : display this text\n", THREAD_COUNT_DEFAULT, TIMEOUT_DEFAULT, BUF_SZ_DEFAULT);
			return 0;
		} else {
			fprintf(stderr, "unknown argument `%s`\n", argv[i]);
			return 0;
		}
	}
	if (r_arg(cert_path) == NULL) {
		fprintf(stderr, "required argument `%s` is missing a value\n", "-c");
		return 0;
	}
	if (r_arg(private_key_path) == NULL) {
		fprintf(stderr, "required argument `%s` is missing a value\n", "-k");
		return 0;
	}
	if (r_arg(uid) == 0 || r_arg(uid) == 0) {
		for (unsigned int i = 0; env[i]; ++i) {
			if (strncmp(env[i], "SUDO_UID=", 9) == 0) {
				r_arg(uid) = stoui32(&env[i][9]);
			} else if (strncmp(env[i], "SUDO_GID=", 9) == 0) {
				r_arg(gid) = stoui32(&env[i][9]);
			}
		}
	}
	if (r_arg(thread_count) < 1 || r_arg(thread_count) > 0xFFFF) {
		fprintf(stderr, "invalid value for `%s`\n", "-t");
		return 0;
	}
	if (r_arg(buf_sz) < 0x100) {
		fprintf(stderr, "invalid value for `%s`\n", "-b");
		return 0;
	}
	return 1;
	#undef CHECK_ARG
	#undef ARG_COMMON
}