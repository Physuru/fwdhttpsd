#include "args.h"
#include "exit.h"
#include "general.h"
#include "utils.h"

void *serve(char *buf) {
	if (buf == NULL) {
		fputs("warning: thread cancelled due to low memory\n", stderr);
		--r_arg(thread_count);
		goto serve__general_near_end;
	}
	for (;;) {
		// effectively stop this thread if `exiting` is non-zero
		if (exiting) {
			if (buf != NULL) {
				free(buf);
				buf = NULL;
			}
			--r_arg(thread_count);
			_clean_then_exit(0, 0);
			break;
		}

		int cl_sock = accept(sv_sock, NULL, NULL);
		if (cl_sock < 1) {
			continue;
		}
		struct timeval timeout = { .tv_sec = 4, 0 };
		setsockopt(cl_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(cl_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		SSL *ssl = SSL_new(ssl_ctx);
		if (ssl == NULL) {
			goto serve__block__near_end;
		}
		SSL_set_fd(ssl, cl_sock);

		int r = 0;
		char http_keep_alive = 1;

		test:;
		if (SSL_accept(ssl) == -1) {
			fputs("SSL_accept (1) returned -1\n", stderr);
			goto serve__block__near_end;
		}
		puts("accepted");

		r = SSL_read(ssl, buf, r_arg(buf_sz));
		if (r < 0) {
			fprintf(stderr, "SSL_read (1) returned %i\n", r);
			goto serve__block__near_end;
		}

		// identify client http version
		unsigned char expected_protocol_id = 0; do { /* do...while statement is used so `break` can be used here */
			char *f = memchr(buf, ' ', r);
			if (f++ == NULL) {
				break;
			}
			f = memchr(f, ' ', r + f - buf);
			if (f++ == NULL || r + f - buf < 8) {
				break;
			}
			if (strncmp(f, "HTTP/1.1", 8) == 0 && (f[8] == ' ' || f[8] == '\r')) {
				expected_protocol_id = 1;
			} else if (strncmp(f, "HTTP/2", 6) == 0 && (f[6] == ' ' || f[6] == '\r')) {
				expected_protocol_id = 2;
			}
		} while (0);

		// attempt to parse first `Host` request header
		char *host = memncasemem(buf, r_arg(buf_sz), "\r\nHost:", 7);
		if (host == NULL) {
			goto serve__block__near_end;
		}
		char *srv_name = host + 7;
		while (*srv_name == ' ') ++srv_name;
		if (memnmem(srv_name, buf + r_arg(buf_sz) - srv_name, "\r\n\r\n", 4) == NULL) {
			fputs("http headers are too long!\n", stderr);
			if (expected_protocol_id == 1) {
				quick_respond(ssl, expected_protocol_id, "400 Bad Request", "Request HTTP header section is too long.");
			}
			goto serve__block__near_end;
		}
		// `Host` header value -> `struct http_service`
		struct http_service *service = find_service(srv_name);
		if (service == NULL) {
			fputs("no services found\n", stderr);
			goto serve__block__near_end;
		}

		// connect to the http server
		int service_sock = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in service_addr = { 0 };
		service_addr.sin_family = AF_INET;
		service_addr.sin_addr.s_addr = _127_0_0_1;
		service_addr.sin_port = service->port;

		if (connect(service_sock, (struct sockaddr *)&service_addr, sizeof(service_addr)) != 0) {
			fprintf(stderr, "unable to connect to service named `%s`\n", service->name);
			goto serve__block__near_end;
		}

		write(service_sock, buf, r);
		while (SSL_pending(ssl)) {
			r = SSL_read(ssl, buf, r_arg(buf_sz));
			if (r < 0) {
				fprintf(stderr, "SSL_read (2) returned %i\n", r);
				goto serve__block__near_end;
			}
			write(service_sock, buf, r);
		}

		// identify server http version
		if ((r = read(service_sock, buf, 9)) > 0) do { /* do...while statement is used so `break` can be used here */
			if (SSL_write(ssl, buf, r) < 0 || r != 9) {
				goto serve__block__near_end;
			}
			if (strncmp(buf, "HTTP/1.1 ", 9) == 0) {
				if (expected_protocol_id != 1) {
					quick_respond(ssl, expected_protocol_id, "502 Bad Gateway", "HTTP version mismatch.");
					goto serve__block__near_end;
				}
				goto prtcl_id_1;
			} else if (strncmp(buf, "HTTP/2 ", 7) == 0) {
				if (expected_protocol_id != 2) {
					goto serve__block__near_end;
				}
				goto prtcl_id_2;
			}
		} while (0); else {
			goto serve__block__near_end;
		}

		// read response into `buf` and sends it to client
		rwl: {
			r = r_arg(buf_sz);
			while (r == r_arg(buf_sz) && (r = read(service_sock, buf, r_arg(buf_sz))) > 0) {
				if (SSL_write(ssl, buf, r) < 0) {
					fputs("SSL_write returned a value less than 0\n", stderr);
					goto serve__block__near_end;
				}
			}
			goto success;
		}

		prtcl_id_1: {
			r = read(service_sock, buf, r_arg(buf_sz));
			char *f1 = memncasemem(buf, r, "\r\nConnection:", 13 /* length of the previous argument */);
			char *f = f1 != NULL ? f1 + 13 : buf;
			char *f2 = memnmem(f, buf + r - f, "\r\n\r\n", 4 /* length of the previous argument */);
			// check if some response headers didn't fit into `buf`
			if (f2 == NULL) {
				quick_respond(ssl, expected_protocol_id, "502 Bad Gateway", "Response HTTP header section is too long.");
				goto serve__block__near_end;
			}
			if (f1 != NULL) do { /* do...while statement is used so `break` can be used here */
				// check for duplicate `Connection` headers
				char *t = memncasemem(f, buf + r - f, "\r\nConnection:", 13 /* length of the previous argument */);
				if (t != NULL && t < f2) {
					quick_respond(ssl, expected_protocol_id, "502 Bad Gateway", "Response HTTP header section is bad.");
					goto serve__block__near_end;
				}
				while (*f == ' ' || *f == '\t') ++f;
				if (f2 - f < 5 ||
					strncasecmp(f, "close", 5) != 0) {
					break;
				}
				f += 5;
				while (*f == ' ' || *f == '\t') ++f;
				if (*f == '\r') {
					http_keep_alive = 0;
				}
			} while (0);
			SSL_write(ssl, buf, r);
			// rwl section will handle the rest
			goto rwl;
		}

		prtcl_id_2:; {
			fputs("http 2 is not implemented yet\n", stderr);
			goto serve__block__near_end;
		}

		success:;
		if (expected_protocol_id == 1 && http_keep_alive) {
			if (http_keep_alive++ == 4) {
				quick_respond(ssl, expected_protocol_id, "408 Request Timeout", "Please try again.");
				goto serve__block__near_end;
			}
			goto test;
		}
		serve__block__near_end:;
		// clean-up
		if (ssl != NULL) {
			SSL_free(ssl);
			ssl = NULL;
		}
		shutdown(cl_sock, SHUT_RDWR);
		close(cl_sock);
		shutdown(service_sock, SHUT_RDWR);
		close(service_sock);
	}
	serve__general_near_end:;
	while (pthread_self() == main_pthread_id) {
		sleep(0xFFFFFFFF);
	}
	// although i'd be surprised if this check ever passed, this is here anyway
	if (buf != NULL) {
		free(buf);
		buf = NULL;
	}
	pthread_cancel(pthread_self());
	return NULL;
}