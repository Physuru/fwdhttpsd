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
	puts("version 0.3.2");
	// write warning to `stdout` and `stderr` if `(char)(-1)` is not equal to `0xFF`
	if ((unsigned char)(-1) != 0xFF) {
		for (char fd = STDOUT_FILENO; fd <= STDERR_FILENO; ++fd) {
			while (write(fd, "assumptions broken - either this system does not use two's complement to store negative integers, or a byte is not equal to 8 bits on your system. this program may not work as intended on your system.\n", 201) <= 0);
		}
	}
	// main thread id
	main_pthread_id = pthread_self();
	// args
	if (!parse_args(argv, env)) {
		clean_then_exit();
	}
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
	struct sockaddr_in sv_addr = { 0 };
	size_t sv_addr_sz = 0;
	if (r_arg(use_ipv4)) {
		sv_socket = socket(AF_INET, SOCK_STREAM, 0);
		sv_addr_sz = sizeof(struct sockaddr_in);
		struct sockaddr_in *sv_addr_4 = (struct sockaddr_in *)&sv_addr;
		sv_addr_4->sin_family = AF_INET;
		sv_addr_4->sin_addr.s_addr = INADDR_ANY;
		sv_addr_4->sin_port = htons(443);
		ipv4_loopback.s_addr = htonl(ipv4_loopback.s_addr);
	} else {
		sv_socket = socket(AF_INET6, SOCK_STREAM, 0);
		sv_addr_sz = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 *sv_addr_6 = (struct sockaddr_in6 *)&sv_addr;
		sv_addr_6->sin6_family = AF_INET6;
		sv_addr_6->sin6_addr = in6addr_any;
		sv_addr_6->sin6_port = htons(443);
		short unsigned int is_le = 0x1234;
		is_le = *(unsigned char *)&is_le == 0x34;
		ipv6_loopback.s6_addr[is_le ? 15 : 0] = 1;
	}
	// try to bind to port 443
	int opt = 1;
	setsockopt(sv_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
	if (bind(sv_socket, (struct sockaddr *)&sv_addr, sv_addr_sz) < 0 ||
		listen(sv_socket, 0) < 0) {
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
		pthread_t x = 0; // this variable is mostly unused. `pthread_create` will crash if it's not here, though.
		pthread_create(&x, NULL, (void *(*)(void *))&serve, calloc(r_arg(buf_sz), 1));
	}
	serve(calloc(r_arg(buf_sz), 1)); // this current thread is included in `thread_count`

	// shouldn't get here
	return (clean_then_exit(), 1);
}
