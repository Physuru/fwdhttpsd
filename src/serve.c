// to-do count: 4

#define POLLRDHUP 0b10000000000000
#define CHUNKED_ENCODING 0xFFFFFFFFFFFFFFFF

#include <poll.h>
#include <netinet/tcp.h>

#include "args.h"
#include "exit.h"
#include "general.h"
#include "utils.h"

#if 1
int _SSL_write(void *x, char *data, size_t len) {
	for (size_t i = 0; i < len; ++i) putc(data[i], stdout);
	return SSL_write(x, data, len);
}
#define SSL_write _SSL_write
#endif

void *serve(void *unused) {
	char *h_buf = NULL, *buf = NULL; // signedness doesn't really matter for `h_buf` or `buf`
	if (r_arg(use_stack_buf)) {
		buf = alloca(r_arg(buf_sz));	
	} else {
		h_buf = malloc(r_arg(buf_sz));
		if (h_buf == NULL) {
			fputs("warning: thread cancelled due to low memory\n", stderr);
			goto serve__general__err;
		}
		buf = h_buf;
	}

	serve__main__start:

	// effectively stop this thread if `exiting` is non-zero
	if (exiting) {
		if (h_buf != NULL) {
			free(h_buf);
			h_buf = NULL;
		}
		--r_arg(thread_count);
		_clean_then_exit(0, 0);
		goto serve__general__near_end;
	}

	// tls
	SSL *ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		fputs("warning: thread cancelled due to low memory\n", stderr);
		goto serve__general__err;
	}

	#define NOTIFY_ERR(err_id) quick_respond_err(ssl, expected_protocol_id, err_id)

	// accept
	int cl_socket = accept(sv_socket, NULL, NULL);
	if (cl_socket < 1) {
		goto serve__main__start;
	}

	// timeout (ms)
	struct timeval timeout = {
		.tv_sec = r_arg(timeout) / 1000,
		.tv_usec = (r_arg(timeout) % 1000) * 1000,
	};
	setsockopt(cl_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(cl_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	// tls
	SSL_set_fd(ssl, cl_socket);
	if (SSL_accept(ssl) == -1) {
		goto serve__main__near_end;
	}

	// read the status line, and hopefully all of the headers
	int n_read_bytes = SSL_read(ssl, buf, r_arg(buf_sz));
	if (n_read_bytes < 16) {
		//fprintf(stderr, "SSL_read (1) returned %i\n", n_read_bytes);
		goto serve__main__near_end;
	}

	// identify client http version
	// format: `METHOD PATH PROTOCOL_ID\r\n`
	unsigned char expected_protocol_id = 0;

	// skip past first ` `
	char *exp_f = memchr(buf, ' ', n_read_bytes);
	if (exp_f++ == NULL) {
		NOTIFY_ERR(CLIENT_PRTCL_NOT_IMPLEMENTED);
		goto serve__main__near_end;
	}
	// skip past second space
	exp_f = memchr(exp_f, ' ', n_read_bytes + exp_f - buf);
	if (exp_f++ == NULL || buf + n_read_bytes - exp_f < 10) {
		NOTIFY_ERR(CLIENT_PRTCL_NOT_IMPLEMENTED);
		goto serve__main__near_end;
	}
	if (strncmp(exp_f, "HTTP/", 5 /* strlen("HTTP/") */) != 0) {
		NOTIFY_ERR(CLIENT_PRTCL_NOT_IMPLEMENTED);
		goto serve__main__near_end;
	}
	exp_f += 5;
	// identify version
	if (strncmp(exp_f /* strlen("HTTP/") */, "1.1", 3 /* strlen("1.1") */) == 0) {
		expected_protocol_id = 1;
		exp_f += 3 /* strlen("1.1") */;
	} else if (*exp_f == '2') {
		expected_protocol_id = 2;
		++exp_f; // exp += 1 /* strlen("2") */;
	}
	if (!expected_protocol_id || (expected_protocol_id == 2 /* temporary */) || *(exp_f++) != '\r' || *(exp_f++) != '\n') {
		NOTIFY_ERR(CLIENT_PRTCL_NOT_IMPLEMENTED);
		goto serve__main__near_end;
	}

	// client request header parsing
	// to-do: is it important to parse the request `Content-Length` header?

	// find headers
	char *req_host_header = NULL;
	char *req_content_length_header = NULL;
	unsigned int req_content_length = 0, req_read = 0;
	char *req_crlfcrlf = NULL;
	char *req_crlf = NULL;
	char *req_after_read_data = buf + n_read_bytes;
	if (!find_headers(exp_f, req_after_read_data, 2, "Host", &req_host_header, "Content-Length", &req_content_length_header, &req_crlfcrlf, &req_crlf)) {
		NOTIFY_ERR(REQ_HEADERS_IMPROPER);
		goto serve__main__near_end;
	}

	if (req_crlfcrlf == NULL) {
		NOTIFY_ERR(REQ_HEADERS_TOO_LONG);
		goto serve__main__near_end;
	}
	if (req_host_header == NULL) {
		NOTIFY_ERR(NO_HOST_HEADER);
		goto serve__main__near_end;
	}
	// attempt to parse first `Content-Length` request header
	if (req_content_length_header != NULL) {
		req_content_length_header += 15 /* strlen("Content-Length:") */;
		skip_space_tab(&req_content_length_header, req_after_read_data);
		req_content_length = stoui(req_content_length_header, 4, '\r');
		req_read = buf + n_read_bytes - req_crlfcrlf - 4;
	}
	// attempt to parse first `Host` request header
	char *srv_name = req_host_header + 5 /* strlen("Host:") */;
	skip_space_tab(&srv_name, req_after_read_data);
	// `Host` header value -> `struct http_service`
	struct http_service *service = find_service(srv_name, req_crlfcrlf);
	if (service == NULL) {
		NOTIFY_ERR(INVALID_SERVICE);
		goto serve__main__near_end;
	}

	// connect to the http server
	int service_socket;
	struct sockaddr_storage service_addr = { 0 };
	size_t service_addr_sz = 0;
	if (r_arg(use_ipv4)) {
		service_addr_sz = sizeof(struct sockaddr_in);
		service_socket = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in *service_addr_4 = (struct sockaddr_in *)&service_addr;
		service_addr_4->sin_family = AF_INET;
		service_addr_4->sin_addr = ipv4_loopback;
		service_addr_4->sin_port = service->port;
	} else {
		service_addr_sz = sizeof(struct sockaddr_in6);
		service_socket = socket(AF_INET6, SOCK_STREAM, 0);
		struct sockaddr_in6 *service_addr_6 = (struct sockaddr_in6 *)&service_addr;
		service_addr_6->sin6_family = AF_INET6;
		service_addr_6->sin6_addr = ipv6_loopback;
		service_addr_6->sin6_port = service->port;
	}
	if (connect(service_socket, (struct sockaddr *)&service_addr, sizeof(service_addr)) != 0) {
		fprintf(stderr, "unable to connect to service named `%s`\n", service->name);
		NOTIFY_ERR(SERVICE_DOWN);
		goto serve__main__near_end;
	}

	// send the initial request to the http server
	if (write(service_socket, buf, n_read_bytes) < 0) {
		goto serve__main__near_end;
	}
	while (req_read < req_content_length || SSL_has_pending(ssl)) {
		n_read_bytes = SSL_read(ssl, buf, r_arg(buf_sz));
		if (n_read_bytes < 0 || write(service_socket, buf, n_read_bytes) < 0) {
			goto serve__main__near_end;
		}
		req_read += n_read_bytes;
	}

	// identify server http version
	char prtcl_id[8] = { 0 }; // the longest string that i care to have in here is "HTTP/1.1"
	int prtcl_id_len = read(service_socket, prtcl_id, 5 /* strlen("HTTP/") */);
	if (prtcl_id_len <= 0) {
		goto serve__main__near_end;
	}
	// http check
	if (strncmp(prtcl_id, "HTTP/", 5 /* strlen("HTTP/") */) != 0) {
		NOTIFY_ERR(SERVER_PRTCL_NOT_IMPLEMENTED);
		goto serve__main__near_end;
	}
	// http 2 check
	prtcl_id_len += read(service_socket, prtcl_id + 5 /* strlen("HTTP/") */, 1);
	if (prtcl_id[5] == '2') {
		/*
			http 2 is currently unsupported
			when http 2 support is added, this section will probably look like:

			if (expected_protocol_id != 2) {
				NOTIFY_ERR(HTTP_VERSION_MISMATCH);
				goto serve__main__near_end;
			}
			goto serve__prtcl_2;
		*/
		NOTIFY_ERR(SERVER_PRTCL_NOT_IMPLEMENTED);
		goto serve__main__near_end;
	}
	// http 1.1 check
	prtcl_id_len += read(service_socket, prtcl_id + 6 /* strlen("HTTP/") + 1 */, 2);
	if (strncmp(prtcl_id + 5 /* strlen("HTTP/") */, "1.1", 3 /* strlen("1.1") */) == 0) {
		if (expected_protocol_id != 1) {
			NOTIFY_ERR(HTTP_VERSION_MISMATCH);
			goto serve__main__near_end;
		}
		goto serve__prtcl_1;
	}
	// unsupported http version
	NOTIFY_ERR(SERVER_PRTCL_NOT_IMPLEMENTED);
	goto serve__main__near_end;

	serve__prtcl_1: for (;;) {
		// check if there's any data to read
		struct pollfd pollfds[] = {
			{ .fd = cl_socket, .events = POLLIN | POLLRDHUP, .revents = 0, },
			{ .fd = service_socket, .events = POLLIN | POLLRDHUP, .revents = 0, },
		};
		int poll_ret = poll(pollfds, 2, r_arg(timeout));
		if (poll_ret <= 0 || ((pollfds[0].revents | pollfds[1].revents) & POLLRDHUP)) {
			goto serve__main__near_end;
		}
		if (!r_arg(force_connection_close) && (pollfds[0].revents & POLLIN)) {
			// read from cl_socket and write to service_socket
			do {
				n_read_bytes = SSL_read(ssl, buf, r_arg(buf_sz));
				if (n_read_bytes < 0 || write(service_socket, buf, n_read_bytes) < 0) {
					goto serve__main__near_end;
				}
			} while (SSL_has_pending(ssl));
		}
		if (pollfds[1].revents & POLLIN) {
			// earlier, a few bytes were read into `prtcl_id`
			// here, they're sent to the client
			if (prtcl_id_len != 0) {
				if (SSL_write(ssl, prtcl_id, prtcl_id_len) <= 0) {
					goto serve__main__near_end;
				}
				prtcl_id_len = 0;
			}

			unsigned char http_keep_alive = 1;
			unsigned long long int res_body_length = 0, res_total_read_body_bytes = 0;
			unsigned char n_tried_find_headers = 0;
			unsigned char sent_connection_close = 0;

			n_read_bytes = read(service_socket, buf, r_arg(buf_sz));
			// there are a lot of checks similar to the following one in this section. they exist in-case a connection suddenly breaks.
			if (n_read_bytes <= 0) {
				goto serve__main__near_end;
			}
			// pointer to the first byte after the read data (`buf + n_read_bytes`)
			char *res_after_read_data = buf + n_read_bytes;

			// error on "Switching Protocols" responses
			char *status_code_start = memchr(buf, ' ', 9);
			if (status_code_start != NULL) {
				++status_code_start;
				if (strncmp(status_code_start, "101", 3) == 0) {
					NOTIFY_ERR(SERVER_PRTCL_NOT_IMPLEMENTED);
					goto serve__main__near_end;
				}
			}

			char *offset_buf = buf;
			// parse response headers
			char *res_connection_header = NULL;
			char *res_content_length_header = NULL;
			char *res_transfer_encoding_header = NULL;
			char *res_after_connection_header = NULL;
			// to-do: consider implementing the "Keep-Alive" header
			// char *keep_alive_header = NULL;
			char *res_crlfcrlf = NULL;
			char *res_crlf = NULL;

			serve__prtcl_1__find_res_headers:;

			if (!find_headers(buf, res_after_read_data, 3, "Connection", &res_connection_header, "Content-Length", &res_content_length_header, "Transfer-Encoding", &res_transfer_encoding_header, &res_crlfcrlf, &res_crlf)) {
				NOTIFY_ERR(RES_HEADERS_IMPROPER);
				goto serve__main__near_end;
			}
			++n_tried_find_headers;

			// set `res_body_length`
			if (res_body_length == 0) {
				if (res_content_length_header != NULL) {
					// get value of `Content-Length` header as a uint64_t
					res_content_length_header += 15 /* strlen("Content-Length:") */;
					skip_space_tab(&res_content_length_header, res_after_read_data);
					res_body_length = stoui(res_content_length_header, 8 /* octets */, '\r');
					// `CHUNKED_ENCODING` is reserved for, well, chunked encoding
					if (res_body_length == CHUNKED_ENCODING) {
						NOTIFY_ERR(RES_HEADERS_IMPROPER);
						goto serve__main__near_end;
					}
				} else if (res_transfer_encoding_header != NULL) {
					// parse `Transfer-Encoding` header
					res_transfer_encoding_header += 18 /* strlen("Transfer-Encoding:") */;
					// skip over spaces and tabs
					skip_space_tab(&res_transfer_encoding_header, res_after_read_data);
					// ensure that the value of the `Transfer-Encoding` header is "chunked"
					if (res_crlfcrlf - res_transfer_encoding_header >= 7 /* strlen("chunked") */ ||
						strncasecmp(res_transfer_encoding_header, "chunked", 7 /* strlen("chunked") */) == 0) {
						res_body_length = CHUNKED_ENCODING;
					}
				}
			}

			// parse the `Connection` header and save the address of the CR at the end of it for `force_connection_close`
			if (!r_arg(force_connection_close) && res_after_connection_header == NULL && res_connection_header != NULL) {
				res_after_connection_header = res_connection_header;
				skip_space_tab(&res_after_connection_header, res_after_read_data);
				if (res_crlfcrlf - res_after_connection_header >= 5 /* strlen("close") */ &&
					strncasecmp(res_after_connection_header, "close", 5 /* "length" of the previous argument */) == 0) {
					http_keep_alive = 0;
				}
				res_after_connection_header += 5 /* strlen("close") */;
				skip_space_tab(&res_after_connection_header, res_after_read_data);
				if (*res_after_connection_header != '\r') {
					http_keep_alive = 1;
					++res_after_connection_header;
				}
				skip_to_crlf(&res_after_connection_header, res_after_read_data);
			}

			// check if some response headers didn't fit into `buf`
			if (res_crlfcrlf == NULL) {
				if (n_tried_find_headers == 5) {
					NOTIFY_ERR(RES_HEADERS_TOO_LONG);
					goto serve__main__near_end;
				}
				if (res_crlf == NULL) {
					// yes, this means that very long headers will not get parsed
					// that's not something that i care about
					if (n_read_bytes < 1 ||
						SSL_write(ssl, offset_buf, n_read_bytes) <= 0) {
						goto serve__main__near_end;
					}
					offset_buf = buf + 1;
					buf[0] = res_after_read_data[-1];
					if ((n_read_bytes = read(service_socket, offset_buf, r_arg(buf_sz) - 1)) <= 0) {
						goto serve__main__near_end;
					}
					res_after_read_data = offset_buf + n_read_bytes;
				} else {
					if (r_arg(force_connection_close) && res_connection_header != NULL && !sent_connection_close) {
						if (SSL_write(ssl, offset_buf, res_connection_header /* strlen("\r\n") */ - offset_buf) < 0 ||
							SSL_write(ssl, "Connection: close", 17 /* "length" of the previous argument */) < 0 ||
							SSL_write(ssl, res_after_connection_header, res_after_read_data - res_after_connection_header) < 0) {
							goto serve__main__near_end;
						}
						sent_connection_close = 1;
					}
					if (SSL_write(ssl, offset_buf, res_crlf + 2 /* strlen("\r\n") */ - offset_buf) <= 0) {
						goto serve__main__near_end;
					}
					unsigned int unprocessed_byte_count = res_after_read_data - res_crlf - 2 /* strlen("\r\n") */;
					memcpy(buf, res_crlf + 2 /* strlen("\r\n") */, unprocessed_byte_count);
					offset_buf = buf + unprocessed_byte_count;
					if ((n_read_bytes = read(service_socket, offset_buf, r_arg(buf_sz) - unprocessed_byte_count)) <= 0) {
						goto serve__main__near_end;
					}
					res_after_read_data = offset_buf + n_read_bytes;
				}
				goto serve__prtcl_1__find_res_headers;
			}
			if (r_arg(force_connection_close) && res_connection_header != NULL && !sent_connection_close) {
				if (SSL_write(ssl, offset_buf, res_connection_header /* strlen("\r\n") */ - offset_buf) < 0 ||
					SSL_write(ssl, "Connection: close", 17 /* "length" of the previous argument */) < 0 ||
					SSL_write(ssl, res_after_connection_header, res_crlfcrlf + 4 /* strlen("\r\n\r\n") */ - res_after_connection_header) < 0) {
					goto serve__main__near_end;
				}
				sent_connection_close = 1;
			} else if (SSL_write(ssl, offset_buf, res_crlfcrlf + 4 /* strlen("\r\n\r\n") */ - offset_buf) < 0) {
				goto serve__main__near_end;
			}

			if (sent_connection_close) {
				http_keep_alive = 0;
			}

			// handle `Transfer-Encoding: chunked`
			if (res_body_length == CHUNKED_ENCODING) {
				// set-up
				char *chunk = res_crlfcrlf + 4 /* strlen("\r\n\r\n") */;
				int chunk_size = 0;
				int remaining_in_buf = res_after_read_data - chunk;
				char res_crlfcrlf_c = 0;

				// loop until the final chunk is found
				for (;;) {
					// ascii-encoded length -> length, as an unsigned integer
					// this parses a maximum of seven (7) ascii-encoded hexadecimal digits
					for (unsigned char parsed_len_bytes = 0; parsed_len_bytes < 7;) {
						unsigned char digit;

						if (!remaining_in_buf) {
							if (read(service_socket, &digit, 1) != 1) {
								goto serve__main__near_end;
							}
						} else {
							digit = *(chunk++);
							--remaining_in_buf;
						}

						if (SSL_write(ssl, &digit, 1) < 0) {
							goto serve__main__near_end;
						}

						if (digit == '\r') {
							break;
						}

						if (digit >= 'a') {
							digit -= 87; // 'a' -> 10
						} else if (digit >= 'A') {
							digit -= 55; // 'A' -> 10
						} else {
							digit -= '0'; // '0' -> 0
						}

						if (digit > 15) {
							// invalid digit
							goto serve__main__near_end;
						}
						
						chunk_size *= 0x10;
						chunk_size += digit;
						++parsed_len_bytes;
					}

					// prevents out-of-bounds memory from being parsed here
					if (!remaining_in_buf) {
						chunk = buf;
						if (read(service_socket, chunk, 1) != 1) {
							goto serve__main__near_end;
						}
						remaining_in_buf = 1;
					}
					// make sure that `\n` immediately follows `\r`
					if (*(chunk++) != '\n' || SSL_write(ssl, "\n", 1) < 0) {
						goto serve__main__near_end;
					}
					// `\n` is one byte
					--remaining_in_buf;

					// the final chunk is guaranteed to have zero-length
					if (!chunk_size) {
						// handle trailers
						res_crlfcrlf_c = 2 /* strlen("\r\n") */;
						char x;
						while (res_crlfcrlf_c != 4 /* strlen("\r\n\r\n") */) {
							if (remaining_in_buf) {
								x = *(chunk++);
								--remaining_in_buf;
							} else {
								if ((n_read_bytes = read(service_socket, &x, 1)) != 1) {
									goto serve__main__near_end;
								}
							}
							if (SSL_write(ssl, &x, n_read_bytes) <= 0) {
								goto serve__main__near_end;
							}

							if (x == "\r\n"[res_crlfcrlf_c % 2 /* strlen("\r\n") */]) {
								++res_crlfcrlf_c;
							} else {
								res_crlfcrlf_c = 0;
							}
						}
						if (http_keep_alive) {
							goto serve__prtcl_1;
						}
						goto serve__main__near_end;
					}

					// send the chunk to the client
					while (chunk_size) {
						unsigned int lower;

						// ensures that enough data to be sent is in `buf`
						if (!remaining_in_buf) {
							chunk = buf;
							lower = chunk_size < r_arg(buf_sz) ? chunk_size : r_arg(buf_sz);
							remaining_in_buf = read(service_socket, buf, lower);
							if (remaining_in_buf < 0) {
								goto serve__main__near_end;
							}
						}

						// actually send the data
						lower = chunk_size < remaining_in_buf ? chunk_size : remaining_in_buf;
						if (SSL_write(ssl, chunk, lower) < 0) {
							goto serve__main__near_end;
						}

						chunk_size -= lower;
						chunk += lower;
						remaining_in_buf -= lower;
					}

					// "\r\n" directly follows a chunk
					for (int x = 0; x < 2 /* strlen("\r\n") */; ++x) {
						char c;
						if (!remaining_in_buf) {
							if (read(service_socket, &c, 1) != 1) {
								goto serve__main__near_end;
							}
						} else {
							c = *(chunk++);
							--remaining_in_buf;
						}

						if (SSL_write(ssl, &c, 1) < 0) {
							goto serve__main__near_end;
						}
					}
				}
			} else {
				// handles `Content-Length` or no length
				if (SSL_write(ssl, res_crlfcrlf + 4 /* strlen("\r\n\r\n") */, res_after_read_data - res_crlfcrlf - 4 /* strlen("\r\n\r\n") */) < 0) {
					goto serve__main__near_end;
				}
				res_total_read_body_bytes += res_after_read_data - res_crlfcrlf - 4 /* strlen("\r\n\r\n") */;

				while (res_total_read_body_bytes < res_body_length) {
					n_read_bytes = read(service_socket, buf, r_arg(buf_sz));
					res_total_read_body_bytes += n_read_bytes;
					if (n_read_bytes < 0 || SSL_write(ssl, buf, n_read_bytes) < 0) {
						goto serve__main__near_end;
					}
				}
			}

			// `Connection: keep-alive` stuff
			if (!http_keep_alive) {
				goto serve__main__near_end;
			}
			// `goto serve__main__start;` is implied
		}
	}

	// to-do: http/2 (http 2)
	// serve__prtcl_2: {}

	// to-do: websockets

	#undef NOTIFY_ERR

	serve__main__near_end:;
	// clean-up
	if (ssl != NULL) {
		SSL_free(ssl);
		ssl = NULL;
	}
	shutdown(cl_socket, SHUT_RDWR);
	close(cl_socket);
	shutdown(service_socket, SHUT_RDWR);
	close(service_socket);

	goto serve__main__start;

	serve__general__err:;
	if (h_buf != NULL) {
		free(h_buf);
		h_buf = NULL;
	}
	// if this is the last thread doing anything, then exit the program
	if (!(--r_arg(thread_count))) {
		clean_then_exit();
	}

	serve__general__near_end:;
	while (pthread_self() == main_pthread_id) {
		sleep(0xFFFFFFFF);
	}
	pthread_cancel(pthread_self());
	return NULL;
}