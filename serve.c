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
		SSL *ssl = SSL_new(ssl_ctx);
		if (ssl == NULL) {
			goto serve__block_near_end;
		}
		SSL_set_fd(ssl, cl_sock);

		if (SSL_accept(ssl) == -1) {
			fputs("SSL_accept (1) returned -1\n", stderr);
			goto serve__block_near_end;
		}

		int r = SSL_read(ssl, buf, r_arg(buf_sz));
		if (r < 0) {
			fprintf(stderr, "SSL_read (1) returned %i\n", r);
			goto serve__block_near_end;
		}

		// identify client http version
		unsigned char expected_protocol_id = 0; do {
			char *f = memchr(buf, ' ', r);
			if (f++ == NULL) {
				break;
			}
			f = memchr(f, ' ', r + f - buf);
			if (f++ == NULL) {
				break;
			}
			if ((r + f - buf) < 8) {
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
			goto serve__block_near_end;
		}
		char *srv_name = host + 7;
		while (*srv_name == ' ') ++srv_name;
		if (memnmem(srv_name, buf + r_arg(buf_sz) - srv_name, "\r\n\r\n", 4) == NULL) {
			fputs("http headers are too long!\n", stderr);
			if (expected_protocol_id == 1) {
				SSL_write(ssl, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 40\r\n\r\nRequest HTTP header section is too long.", 109);
			}
			goto serve__block_near_end;
		}
		// `Host` header value -> `struct http_service`
		struct http_service *service = find_service(srv_name);
		if (service == NULL) {
			fputs("no services found\n", stderr);
			goto serve__block_near_end;
		}

		// connect to the http server
		int service_sock = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in service_addr = { 0 };
		service_addr.sin_family = AF_INET;
		service_addr.sin_addr.s_addr = _127_0_0_1;
		service_addr.sin_port = service->port;

		if (connect(service_sock, (struct sockaddr *)&service_addr, sizeof(service_addr)) != 0) {
			fprintf(stderr, "unable to connect to service named `%s`\n", service->name);
			goto serve__block_near_end;
		}

		write(service_sock, buf, r);
		while (SSL_pending(ssl)) {
			r = SSL_read(ssl, buf, r_arg(buf_sz));
			if (r < 0) {
				fprintf(stderr, "SSL_read (2) returned %i\n", r);
				goto serve__block_near_end;
			}
			write(service_sock, buf, r);
		}

		// identify server http version
		if ((r = read(service_sock, buf, 9)) > 0) {
			if (SSL_write(ssl, buf, r) < 0 || r != 9) {
				goto serve__block_near_end;
			}
			if (strncmp(buf, "HTTP/1.1 ", 9) == 0) {
				if (expected_protocol_id != 1) {
					SSL_write(ssl, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 22\r\n\r\nHTTP version mismatch.", 89);
					goto serve__block_near_end;
				}
				goto prtcl_id_1;
			} else if (strncmp(buf, "HTTP/2 ", 7) == 0) {
				if (expected_protocol_id != 2) {
					goto serve__block_near_end;
				}
				goto prtcl_id_2;
			}
		} else {
			goto serve__block_near_end;
		}

		// read response into `buf` and sends it to client
		rwl: {
			while ((r = read(service_sock, buf, r_arg(buf_sz))) > 0) {
				if (SSL_write(ssl, buf, r) < 0) {
					fputs("SSL_write returned a value less than 0\n", stderr);
					goto serve__block_near_end;
				}
			}
			goto success;
		}

		prtcl_id_1: {
			// this code removes the response's `Connection` header, and replaces it with its own
			// better handling for http/1.1's `Connection` header in general is coming soon
			r = read(service_sock, buf, r_arg(buf_sz));
			char *f1 = memncasemem(buf, r, "\r\nConnection:", 13 /* length of the previous argument */);
			char *f = f1 != NULL ? f1 + 13 : buf;
			char *f2 = memnmem(f, buf + r - f, "\r\n\r\n", 4 /* length of the previous argument */);
			// check if some response headers didn't fit into `buf`
			if (f2 == NULL) {
				SSL_write(ssl, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 41\r\n\r\nResponse HTTP header section is too long.", 110 /* length of the previous argument */);
				goto serve__block_near_end;
			}
			if (f1 != NULL) {
				// check for duplicate `Connection` headers
				char *t = memncasemem(f, buf + r - f, "\r\nConnection:", 13 /* length of the previous argument */);
				if (t != NULL && t < f2) {
					SSL_write(ssl, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 36\r\n\r\nResponse HTTP header section is bad.", 105 /* length of the previous argument */);
					goto serve__block_near_end;
				}
				// write response up until the start of the `Connection` header
				SSL_write(ssl, buf, f1 - buf);
				while (*f != '\r') ++f;
			}
			// here, `f` will either be at the `\r` after the `Connection` header's value, or at the start of the http response
			SSL_write(ssl, f, f2 - f);
			// write the "Connection: close" header right before the CRLFCRLF sequence
			SSL_write(ssl, "\r\nConnection: close\r\n\r\n", 23 /* length of the previous argument */);
			// write the remaining bytes in `buf`
			f2 += 4;
			SSL_write(ssl, f2, buf + r - f2);
			// rwl section will handle the rest
			goto rwl;
		}

		prtcl_id_2:; {
			fputs("http 2 is not implemented yet\n", stderr);
			goto serve__block_near_end;
		}

		success:;
		// placeholder for when i implement `Connection: keep-alive`, etc
		serve__block_near_end:;
		// clean-up
		if (ssl != NULL) {
			SSL_free(ssl);
			ssl = NULL;
		}
		close(cl_sock);
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