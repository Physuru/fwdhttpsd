#include "args.h"
#include "exit.h"
#include "general.h"
#include "serve.h"
#include "utils.h"

void sigint_handler(int unused) {
	signal(SIGINT, SIG_DFL);
	_clean_then_exit(0, 0);
}

int main(int argc, char *argv[], char *env[]) {
	puts("version 0.2.0");
	// write warning to `stdout` and `stderr` if `(char)(-1)` is not equal to `0xFF`
	if ((unsigned char)(-1) != 0xFF) {
		for (char fd = STDOUT_FILENO; fd <= STDERR_FILENO; ++fd) {
			write(fd, "assumptions broken - either this system does not use two's complement to store negative integers, or a byte is not equal to 8 bits on your system. this program may not work as intended on your system.\n", 201);
		}
	}
	// main thread id
	main_pthread_id = pthread_self();
	// network byte order
	_127_0_0_1 = htonl(_127_0_0_1);
	_443 = htons(_443);
	// set up singal handlers
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	// program file is maybe owned by root w/ set{uid,gid} bit(s) set
	uid_t old_uid = getuid();
	gid_t old_gid = getgid();
	setuidgid(0, 0, -1, -1);
	// root required to obtain port 443
	if (getuid() != 0) {
		fputs("must be run as root\n", stderr);
		clean_then_exit();
	}
	// set up socket
	sv_sock = socket(AF_INET, SOCK_STREAM, 0);
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_addr.s_addr = INADDR_ANY;
	// try to listen on port 443
	int opt = 1;
	setsockopt(sv_sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
	sv_addr.sin_port = _443;
	if (bind(sv_sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr)) < 0 ||
		listen(sv_sock, 0) < 0) {
		clean_then_exit();
	}
	// args
	if (!parse_args(argv, env)) {
		clean_then_exit();
	}
	if (r_arg(thread_count) < 1 || r_arg(thread_count) > 0xFFFF) {
		fprintf(stderr, "invalid value for `%s`\n", "-t");
		clean_then_exit();
	}
	if (r_arg(buf_sz) < 0x100) {
		fprintf(stderr, "invalid value for `%s`\n", "-b");
		clean_then_exit();
	}
	// we don't need root anymore
	if ((old_uid != 0 && old_uid != r_arg(uid)) ||
		(old_gid != 0 && old_gid != r_arg(gid)) ||
		!setuidgid(r_arg(uid), r_arg(gid), 0, 0)) {
		fputs("unsafe; try `-u` and `-g`, or maybe run with sudo\n", stderr);
		clean_then_exit();
	}
	// set up tls
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_cipher_list(ssl_ctx, "AES256-SHA256");
	if (SSL_CTX_use_certificate_file(ssl_ctx, r_arg(cert_path), SSL_FILETYPE_PEM) != 1) {
		fputs("invalid certificate\n", stderr);
		clean_then_exit();
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, r_arg(private_key_path), SSL_FILETYPE_PEM) != 1) {
		fputs("invalid private key\n", stderr);
		clean_then_exit();
	}
	// threads
	puts("ready!");
	for (short unsigned int i = 1; i < r_arg(thread_count); ++i) {
		puts("wowie");
		pthread_t x = 0; // this variable is mostly unused. `pthread_create` will crash if it's not here, though.
		pthread_create(&x, NULL, (void *(*)(void *))&serve, calloc(r_arg(buf_sz), 1));
	}
	serve(calloc(r_arg(buf_sz), 1)); // this current thread is included in `thread_count`

	// shouldn't get here
	return (clean_then_exit(), 1);
}
