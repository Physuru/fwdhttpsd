#include "args.h"
#include "general.h"

unsigned char exiting = 0;
void _clean_then_exit(unsigned char status, unsigned char safe) {
	if (!safe) {
		if (!exiting) {
			puts("\ncleaning up - please wait...\nsend sigint again to skip clean-up.");
			exiting = 1;
			shutdown(sv_sock, SHUT_RD);
		}
		if (r_arg(thread_count)) {
			return;
		}
	}
	if (ssl_ctx != NULL) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}
	if (r_arg(http_services) != NULL) {
		free(r_arg(http_services));
		r_arg(http_services) = NULL;
	}
	close(sv_sock);
	exit(status);
}