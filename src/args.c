#define args_c
#include "args.h"
#include "general.h"
#include "utils.h"

short unsigned int r_arg(timeout) = 4000;
unsigned char r_arg(force_connection_close) = 0;
int r_arg(uid);
int r_arg(gid);
char *r_arg(cert_path);
char *r_arg(private_key_path);
short unsigned int r_arg(thread_count) = 4, r_arg(buf_sz) = 0x1000;
struct http_service *r_arg(http_services) = NULL;
struct http_service r_arg(default_http_service) = (struct http_service){ .name = NULL, 0 };
unsigned int r_arg(n_http_services) = 0;
int parse_args(char *argv[], char *env[]) {
	#define ARG_COMMON(x, y, z) (strcmp(argv[i], x) == 0) { \
		if (argv[i + 1] == NULL) { \
			fprintf(stderr, "argument `%s` is missing values\n", x); \
			return 0; \
		} \
		y = z(argv[i + 1]); \
		i += 2; \
	}
	#define CHECK_ARG(x, y, z) if (y == z) { \
		fprintf(stderr, "missing argument `%s`\n", x); \
		return 0; \
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
		} else {
			fprintf(stderr, "unknown argument `%s`\n", argv[i]);
			return 0;
		}
	}
	CHECK_ARG("-c", r_arg(cert_path), NULL);
	CHECK_ARG("-k", r_arg(private_key_path), NULL);
	if (r_arg(uid) == 0 || r_arg(uid) == 0) {
		for (unsigned int i = 0; env[i]; ++i) {
			if (strncmp(env[i], "SUDO_UID=", 9) == 0) {
				r_arg(uid) = stoui32(&env[i][9]);
			} else if (strncmp(env[i], "SUDO_GID=", 9) == 0) {
				r_arg(gid) = stoui32(&env[i][9]);
			}
		}
	}
	return 1;
	#undef CHECK_ARG
	#undef ARG_COMMON
}