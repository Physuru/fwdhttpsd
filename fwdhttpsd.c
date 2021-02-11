// fwdhttpsd v0.1.1

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <pthread.h>
#include <signal.h>

#include <netinet/in.h>
#include <openssl/ssl.h>

#define PTR_PLUS(ptr, n) ((typeof(ptr))((char *)(ptr) + n))

int sv_sock = 0;
struct sockaddr_in addr = { 0 };
int addr_len = sizeof(addr);
SSL_CTX *ctx = NULL;

struct http_service {
	char *name;
	unsigned int name_len;
	unsigned int port;
};
struct http_service *http_services = NULL;
unsigned int n_http_services = 0;

int chrcasecmp(char c1, char c2) {
	if (c1 >= 'A' && c1 <= 'Z') c1 += 'a' - 'A';
	if (c2 >= 'A' && c2 <= 'Z') c2 += 'a' - 'A';
	return c2 - c1;
}

void sigint_handler(int sig) {
	if (ctx != NULL) {
		SSL_CTX_free(ctx);
		ctx = NULL;
	}
	if (http_services != NULL) {
		free(http_services);
		http_services = NULL;
	}
	close(sv_sock);
	exit(sig != SIGINT);
}
#define clean_then_exit() sigint_handler(1)
struct http_service *find_service(char *name) {
	for (unsigned int i = 0; i < n_http_services; ++i) {
		if (strncmp(name, http_services[i].name, http_services[i].name_len) == 0 &&
			name[http_services[i].name_len] == '\r' &&
			name[http_services[i].name_len + 1] == '\n') {
			return &http_services[i];
		}
	}
	return NULL;
}

unsigned char setcreds(int uid, int gid, int chkn_uid, int chkn_gid) {
	setgid(gid);
	setegid(gid);
	setuid(uid);
	seteuid(uid);
	return getuid() != chkn_uid && getgid() != chkn_gid;
}

void *handle(void *whatever) {
	for (;;) {
		#define ADDV 0x280

		int cl_sock = accept(sv_sock, NULL, NULL);
		SSL *ssl = SSL_new(ctx);
		if (ssl == NULL) {
			goto o;
		}
		SSL_set_fd(ssl, cl_sock);

		if (SSL_accept(ssl) == -1) {
			fputs("SSL_read (1) returned -1\n", stderr);
			goto o;
		}

		unsigned int buf_sz = 2, buf_idx = 0;
		char *buf = NULL;

		int r = 0;

		struct http_service *service = NULL;
		unsigned int name_start_idx = 0, find_idx = 0;
		unsigned char matches = 0;
		do {
			buf_sz += ADDV;
			char *tmp = realloc(buf, buf_sz);
			if (tmp == NULL) {
				fputs("out of memory\n", stderr);
				goto o;
			}
			buf = tmp;
			buf[buf_sz - 1] = 0;
			buf[buf_sz - 2] = 0;

			r = SSL_read(ssl, PTR_PLUS(buf, buf_idx), ADDV);
			if (r < 0) {
				fprintf(stderr, "SSL_read (1) returned %i\n", r);
				goto o;
			}

			// identify the service via the "Host" request header
			buf_idx += r;
			while (find_idx < buf_idx) {
				if (matches >= 8) {
					while (find_idx < buf_idx && matches != 10) {
						if (buf[find_idx++] != ((char []){ '\r', '\n' })[(matches++) - 8]) {
							matches = 8;
						}
					}
					if (matches == 10) {
						service = find_service(PTR_PLUS(buf, name_start_idx));
						break;
					}
				} else if (matches == 7) {
					while ((find_idx < buf_idx) && (buf[find_idx] == ' ' || buf[find_idx] == '\t')) ++find_idx;
					if (find_idx < buf_idx) {
						name_start_idx = find_idx;
						++matches;
					}
				} else if (matches == 2 && buf[find_idx] == '\r') {
					goto no_services;
				} else if (chrcasecmp(buf[find_idx++], ((char []){ '\r', '\n', 'H', 'o', 's', 't', ':' })[matches++]) != 0) {
					matches = 0;
				}
			}
		} while (service == NULL && buf_sz < ADDV * 0x10 && SSL_pending(ssl));
		no_services: if (service == NULL) {
			fputs("no services found\n", stderr);
			goto o;
		}

		int service_sock = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in service_addr = { 0 };
		service_addr.sin_family = AF_INET;
		service_addr.sin_addr.s_addr = 0b00000001000000000000000001111111; // 127.0.0.1
		service_addr.sin_port = service->port;

		if (connect(service_sock, (struct sockaddr *)&service_addr, sizeof(service_addr)) != 0) {
			fprintf(stderr, "unable to connect to service named `%s`\n", service->name);
			goto o;
		}

		write(service_sock, buf, buf_idx);
		while (SSL_pending(ssl)) {
			r = SSL_read(ssl, buf, buf_sz - 2);
			if (r < 0) {
				fprintf(stderr, "SSL_read (2) returned %i\n", r);
				goto o;
			}
			write(service_sock, buf, r);
		}

		while ((r = read(service_sock, buf, buf_sz - 2)) > 0) {
			// overwrite the value of the "Connection" response header with "close"
			find_idx = 0, matches = 0;
			while (matches >= 0 && find_idx < r) {
				if (matches >= 13 && buf[find_idx] != '\r') {
					buf[find_idx] = matches == 18 ? ' ' : ((char []){ 'c', 'l', 'o', 's', 'e' })[(matches++) - 13];
					++find_idx;
				} else if (matches >= 13) {
					matches = -1;
					break;
				} else if (matches == 2 && buf[find_idx] == '\r') {
					matches = -1;
					break;
				} else if (chrcasecmp(buf[find_idx++], "\r\nConnection:"[matches++]) != 0) {
					matches = 0;
				}
			}
			int x = SSL_write(ssl, buf, r);
			if (x < 0) {
				fprintf(stderr, "SSL_write (1) returned %i\n", x);
				goto o;
			}
		}

		o:;
		if (ssl != NULL) {
			SSL_free(ssl);
			ssl = NULL;
		}
		close(cl_sock);
		if (buf != NULL) {
			free(buf);
			buf = NULL;
		}
		#undef ADDV
	}
	return NULL;
}

int parse_args(char *argv[], uid_t *uid, gid_t *gid, char **cert_path, char **private_key_path, short unsigned int *thread_count) {
	#define ARG_COMMON(arg, par, proc) (strcmp(argv[i], arg) == 0) { if (argv[i + 1] == NULL) { fprintf(stderr, "argument `%s` is missing values\n", arg); return 0; } *(par) = proc(argv[i + 1]); i += 2; }
	#define CHECK_ARG(arg, par, def) if (*(par) == def) { fprintf(stderr, "missing argument `%s`\n", arg); return 0; }
	unsigned int i = 1;
	while (argv[i]) {
		if ARG_COMMON("-u", uid, atoi)
		else if ARG_COMMON("-g", gid, atoi)
		else if ARG_COMMON("-c", cert_path, (char *))
		else if ARG_COMMON("-k", private_key_path, (char *))
		else if ARG_COMMON("-t", thread_count, atoi)
		else if (strcmp(argv[i], "-s") == 0) {
			if (argv[i + 1] == NULL || argv[i + 2] == NULL) {
				fprintf(stderr, "argument `%s` is missing values\n", "-s");
				return 0;
			}
			http_services = realloc(http_services, sizeof(struct http_service) * ++n_http_services);
			http_services[n_http_services - 1].name = argv[i + 1];
			http_services[n_http_services - 1].name_len = strlen(argv[i + 1]);
			http_services[n_http_services - 1].port = htons(atoi(argv[i + 2]));
			i += 3;
		} else {
			fprintf(stderr, "unknown argument `%s`\n", argv[i]);
			return 0;
		}
	}
	CHECK_ARG("-c", cert_path, NULL);
	CHECK_ARG("-k", private_key_path, NULL);
	return 1;
	#undef CHECK_ARG
	#undef ARG_COMMON
}
int main(int argc, char *argv[], char *env[]) {
	// set up sigint handler
	signal(SIGINT, sigint_handler);
	// maybe owned by root w/ set{uid,gid} bit(s) set
	setuid(0);
	setgid(0);
	// root required to obtain port 443
	if (getuid() != 0) {
		fputs("must be run as root\n", stderr);
		clean_then_exit();
	}
	// set up socket
	sv_sock = socket(AF_INET, SOCK_STREAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	// try to listen on port 443
	int opt = 1;
	setsockopt(sv_sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
	addr.sin_port = 0b1011101100000001; // 443
	if (bind(sv_sock, (struct sockaddr *)&addr, addr_len) < 0 ||
		listen(sv_sock, 0) < 0) {
		clean_then_exit();
	}
	// args
	uid_t new_uid = 0;
	gid_t new_gid = 0;
	char *cert_path = NULL, *private_key_path = NULL;
	short unsigned int thread_count = 4;
	if (!parse_args(argv, &new_uid, &new_gid, &cert_path, &private_key_path, &thread_count)) {
		clean_then_exit();
	}
	if (thread_count < 1 || thread_count > 0xFFFF) {
		fputs("invalid value for `-t`\n", stderr);
		clean_then_exit();
	}
	// we don't need root anymore
	if (new_uid == 0 || new_gid == 0) {
		for (unsigned int i = 0; env[i]; ++i) {
			if (strncmp(env[i], "SUDO_UID=", 9) == 0) {
				new_uid = atoi(&env[i][9]);
			} else if (strncmp(env[i], "SUDO_GID=", 9) == 0) {
				new_gid = atoi(&env[i][9]);
			}
		}
	}
	if (!setcreds(new_uid, new_gid, 0, 0)) {
		fputs("unsafe; try `-u` and `-g`\n", stderr);
		clean_then_exit();
	}
	// set up tls
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_cipher_list(ctx, "AES256-SHA256");
	SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, private_key_path, SSL_FILETYPE_PEM);
	// threads
	puts("ready!");
	for (short unsigned int i = 0; i < (thread_count - 1); ++i) {
		pthread_t x = 0; // this variable is mostly unused
		pthread_create(&x, NULL, (void *(*)(void *))&handle, NULL);
	}
	handle(NULL);

	// shouldn't get here
	return (clean_then_exit(), 1);
}
