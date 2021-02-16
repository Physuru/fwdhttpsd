// to-do count: 4

#define POLLRDHUP 8192

#include <poll.h>

#include "args.h"
#include "exit.h"
#include "general.h"
#include "utils.h"

void *serve(char *buf) {
	if (buf == NULL) {
		fputs("warning: thread cancelled due to low memory\n", stderr);
		--r_arg(thread_count);
		goto serve__general__near_end;
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
		struct timeval timeout = { .tv_sec = r_arg(timeout) / 1000, .tv_usec = (r_arg(timeout) % 1000) * 1000 };
		setsockopt(cl_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(cl_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		SSL *ssl = SSL_new(ssl_ctx);
		if (ssl == NULL) {
			goto serve__block__near_end;
		}
		SSL_set_fd(ssl, cl_sock);

		if (SSL_accept(ssl) == -1) {
			goto serve__block__near_end;
		}

		int read_bytes = SSL_read(ssl, buf, r_arg(buf_sz));
		if (read_bytes < 0) {
			fprintf(stderr, "SSL_read (1) returned %i\n", read_bytes);
			goto serve__block__near_end;
		}

		// identify client http version
		char *exp_f;
		unsigned char expected_protocol_id = 0; do { /* do...while statement is used so `break` can be used here */
			exp_f = memchr(buf, ' ', read_bytes);
			if (exp_f++ == NULL) {
				break;
			}
			exp_f = memchr(exp_f, ' ', read_bytes + exp_f - buf);
			if (exp_f++ == NULL || read_bytes + exp_f - buf < 8) {
				break;
			}
			// http
			if (strncmp(exp_f, "HTTP/", 5 /* strlen("HTTP/") */) != 0) {
				break;
			}
			if (strncmp(exp_f + 5 /* strlen("HTTP/") */, "1.1", 3 /* strlen("1.1") */) == 0 && (exp_f[8] == ' ' || exp_f[8] == '\r')) {
				expected_protocol_id = 1;
			} /*else if (f[5] == '2' && (f[6] == ' ' || f[6] == '\r')) {
				expected_protocol_id = 2;
			}*/ else {
				quick_respond(ssl, 1, "501 Not Implemented", "Unsupported protocol.");
				goto serve__block__near_end;
			}
		} while (0);

		// to-do: is it important to parse the request `Content-Length` header?
		// attempt to parse first `Host` request header
		char *req_host_header = "Host";
		char *req_content_length_header = "Content-Length";
		unsigned int req_content_length = 0, req_read = 0;
		char *req_crlfcrlf = NULL;
		{
			unsigned char prtcl_id_len = exp_f - buf;
			find_headers(buf + prtcl_id_len, buf + read_bytes, 2, &req_host_header, &req_content_length_header, &req_crlfcrlf);
		}
		if (req_crlfcrlf == NULL) {
			quick_respond(ssl, expected_protocol_id, "400 Bad Request", "Request HTTP header section is too long.");
			goto serve__block__near_end;
		}
		if (req_host_header == NULL) {
			quick_respond(ssl, expected_protocol_id, "400 Bad Request", "No service specified.");
			goto serve__block__near_end;
		}
		if (req_content_length_header != NULL) {
			req_content_length_header += 15 /* strlen("Content-Length:") */;
			skip_space_tab(&req_content_length_header);
			req_content_length = stoui(req_content_length_header, 4, '\r');
			req_read = buf + read_bytes - req_crlfcrlf - 4;
		}
		char *srv_name = req_host_header + 5 /* strlen("Host:") */;
		skip_space_tab(&srv_name);
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
			quick_respond(ssl, expected_protocol_id, "502 Bad Gateway", "Unable to connect to service.");
			goto serve__block__near_end;
		}

		write(service_sock, buf, read_bytes);
		while (req_read < req_content_length || SSL_has_pending(ssl)) {
			read_bytes = SSL_read(ssl, buf, r_arg(buf_sz));
			if (read_bytes < 0) {
				fprintf(stderr, "SSL_read (2) returned %i\n", read_bytes);
				goto serve__block__near_end;
			}
			write(service_sock, buf, read_bytes);
			req_read += read_bytes;
		}
		read_bytes = 0;

		// identify server http version
		char prtcl_id[8] = { 0 }; // the longest string that i care to have in here is "HTTP/1.1"
		int prtcl_id_len = read(service_sock, prtcl_id, 5 /* strlen("HTTP/") */);
		if (prtcl_id_len <= 0) {
			goto serve__block__near_end;
		}
		if (strncmp(prtcl_id, "HTTP/", 5 /* strlen("HTTP/") */) == 0) {
			int x = read(service_sock, prtcl_id + 5 /* strlen("HTTP/") */, 1);
			prtcl_id_len += x;
			if (prtcl_id[5] == '2') {
				quick_respond(ssl, expected_protocol_id, "501 Not Implemented", "Server responded using an unsupported protocl.");
				goto serve__block__near_end;
				/*if (expected_protocol_id != 2) {
					quick_respond(ssl, expected_protocol_id, "502 Bad Gateway", "HTTP version mismatch.");
					goto serve__block__near_end;
				}
				goto serve__prtcl_2;*/
			}
			x = read(service_sock, prtcl_id + 6 /* strlen("HTTP/") + 1 */, 2);
			prtcl_id_len += x;
			if (strncmp(prtcl_id + 5 /* strlen("HTTP/") */, "1.1", 3 /* strlen("1.1") */) == 0) {
				if (expected_protocol_id != 1) {
					quick_respond(ssl, expected_protocol_id, "502 Bad Gateway", "HTTP version mismatch.");
					goto serve__block__near_end;
				}
				goto serve__prtcl_1;
			} else {
				quick_respond(ssl, expected_protocol_id, "501 Not Implemented", "Server responded using an unsupported protocol.");
				goto serve__block__near_end;
			}
		}
		SSL_write(ssl, prtcl_id, prtcl_id_len);
		// `goto serve__block__rwl;` is implied

		// read response into `buf` and send it to client
		serve__block__rwl: for (;;) {
			struct pollfd pollfds[] = {
				{ .fd = cl_sock, .events = POLLIN | POLLRDHUP, .revents = 0 },
				{ .fd = service_sock, .events = POLLIN | POLLRDHUP, .revents = 0 }
			};
			int poll_ret = poll(pollfds, 2, r_arg(timeout));
			if (poll_ret <= 0 || ((pollfds[0].revents | pollfds[1].revents) & POLLRDHUP)) {
				goto serve__block__near_end;
			}
			if ((pollfds[0].revents & POLLIN)) {
				// write data to service_sock
				while (SSL_has_pending(ssl) && (read_bytes = SSL_read(ssl, buf, r_arg(buf_sz))) > 0) {
					if (write(service_sock, buf, read_bytes) < 1) {
						break;
					}
				}
			}
			while ((pollfds[1].revents & POLLIN) && (read_bytes = read(service_sock, buf, r_arg(buf_sz))) > 0) {
				if (SSL_write(ssl, buf, read_bytes) < 1) {
					break;
				}
			}
		}

		serve__prtcl_1: for (;;) {
			struct pollfd pollfds[] = {
				{ .fd = cl_sock, .events = POLLIN | POLLRDHUP, .revents = 0 },
				{ .fd = service_sock, .events = POLLIN | POLLRDHUP, .revents = 0 }
			};
			int poll_ret = poll(pollfds, 2, r_arg(timeout));
			if (poll_ret <= 0 || ((pollfds[0].revents | pollfds[1].revents) & POLLRDHUP)) {
				goto serve__block__near_end;
			}
			if ((pollfds[0].revents & POLLIN) && !r_arg(force_connection_close)) {
				// write data to service_sock
				do {
					read_bytes = SSL_read(ssl, buf, r_arg(buf_sz));
					if (read_bytes < 0) {
						fprintf(stderr, "SSL_read returned %i\n", read_bytes);
						goto serve__block__near_end;
					}
					write(service_sock, buf, read_bytes);
				} while (SSL_has_pending(ssl));
			}
			if (pollfds[1].revents & POLLIN) {
				char http_keep_alive = 1;
				unsigned long long int length = 0, total_read_resp_body_bytes = 0;

				read_bytes = read(service_sock, buf, r_arg(buf_sz));
				char *status_code_start = memchr(buf, ' ', 9);
				if (status_code_start != NULL) {
					++status_code_start;
					if (strncmp(status_code_start, "101", 3) == 0) {
						quick_respond(ssl, expected_protocol_id, "501 Not Implemented", "Server responded using an unsupported protocol.");
						goto serve__block__near_end;
					}
				}

				char *after_read_data = buf + read_bytes;

				char *connection_header = "Connection";
				char *content_length_header = "Content-Length";
				char *transfer_encoding_header = "Transfer-Encoding";
				// to-do: consider implementing the "Keep-Alive" header
				// char *keep_alive_header = "Keep-Alive";
				char *crlfcrlf = NULL;
				find_headers(buf, after_read_data, 3, &connection_header, &content_length_header, &transfer_encoding_header, &crlfcrlf);

				// check if some response headers didn't fit into `buf`
				if (crlfcrlf == NULL) {
					quick_respond(ssl, expected_protocol_id, "502 Bad Gateway", "Response HTTP header section is too long.");
					goto serve__block__near_end;
				}
				total_read_resp_body_bytes = after_read_data - 4 /* strlen("\r\n\r\n") */ - crlfcrlf;

				if (content_length_header == NULL || content_length_header >= crlfcrlf) do {
					if (transfer_encoding_header == NULL) {
						break;
					}
					transfer_encoding_header += 18 /* strlen("Transfer-Encoding:") */;
					// skip over spaces and tabs
					skip_space_tab(&transfer_encoding_header);
					// ensure that the value of the `Transfer-Encoding` header is "chunked"
					if (crlfcrlf - transfer_encoding_header < 7 /* strlen("chunked") */ ||
						strncasecmp(transfer_encoding_header, "chunked", 7 /* strlen("chunked") */) != 0) {
						serve__prtcl_1__bad_headers:;
						quick_respond(ssl, expected_protocol_id, "502 Bad Gateway", "Response HTTP header section is bad.");
						goto serve__block__near_end;
					}
					transfer_encoding_header += 7 /* strlen("chunked") */;
					skip_space_tab(&transfer_encoding_header);
					if (*transfer_encoding_header != '\r') {
						goto serve__prtcl_1__bad_headers;
					}
					length = CHUNKED_ENCODING;
				} while (0); else {
					// get value of `Content-Length` header as a uint64_t
					content_length_header += 15 /* strlen("Content-Length:") */;
					skip_space_tab(&content_length_header);
					length = stoui(content_length_header, 8 /* octets */, '\r');
					// `CHUNKED_ENCODING` is reserved for, well, chunked encoding
					if (length == CHUNKED_ENCODING) {
						goto serve__prtcl_1__bad_headers;
					}
				}
				char *after_connection_header = connection_header; // this *will* be pointing to the '\r' after the `Connection` header
				if (connection_header != NULL) {
					skip_space_tab(&after_connection_header);
					if (crlfcrlf - after_connection_header >= 5 /* strlen("close") */ &&
						strncasecmp(after_connection_header, "close", 5 /* "length" of the previous argument */) == 0) {
						http_keep_alive = 0;
					}
					after_connection_header += 5 /* strlen("close") */;
					skip_space_tab(&after_connection_header);
					if (*after_connection_header != '\r') {
						http_keep_alive = 1;
						++after_connection_header;
					}
					skip_to_cr(&after_connection_header);
				}
				SSL_write(ssl, prtcl_id, prtcl_id_len);
				prtcl_id_len = 0;
				if (r_arg(force_connection_close)) {
					SSL_write(ssl, buf, connection_header - 2 - buf);
					SSL_write(ssl, after_connection_header, crlfcrlf - after_connection_header);
					SSL_write(ssl, "\r\nConnection: close\r\n\r\n", 23 /* "length" of the previous argument */);
					http_keep_alive = 0;
				}
				if (length == CHUNKED_ENCODING) {
					char *chunk = crlfcrlf + 4;
					if (!r_arg(force_connection_close)) {
						SSL_write(ssl, buf, chunk - buf);
					}
					int chunk_size = 0;
					int remaining_in_buf = after_read_data - chunk;
					char crlfcrlf_c = 0;
					for (;;) {
						for (unsigned char parsed_len_bytes = 0; parsed_len_bytes < 7;) {
							unsigned char digit;
							if (!remaining_in_buf) {
								if (read(service_sock, &digit, 1) < 0) {
									goto serve__block__near_end;
								}
							} else {
								digit = *(chunk++);
								--remaining_in_buf;
							}
							SSL_write(ssl, &digit, 1);
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
								goto serve__block__near_end;
							}
							chunk_size *= 0x10;
							chunk_size += digit;
							++parsed_len_bytes;
						}
						if (!remaining_in_buf) {
							chunk = buf;
							read(service_sock, chunk, 1);
							remaining_in_buf = 1;
						}
						if (*(chunk++) != '\n') {
							goto serve__block__near_end;
						}
						SSL_write(ssl, "\n", 1);
						--remaining_in_buf;
						if (!chunk_size) {
							crlfcrlf_c = 2;
							char x;
							while (crlfcrlf_c != 4) {
								read_bytes = read(service_sock, &x, 1);
								SSL_write(ssl, &x, read_bytes);
								if (x == "\r\n"[crlfcrlf_c % 2]) {
									++crlfcrlf_c;
								} else {
									crlfcrlf_c = 0;
								}
							}
							if (http_keep_alive) {
								goto serve__prtcl_1;
							}
							goto serve__block__near_end;
						}
						while (chunk_size) {
							unsigned int lower;
							if (!remaining_in_buf) {
								chunk = buf;
								lower = chunk_size < r_arg(buf_sz) ? chunk_size : r_arg(buf_sz);
								remaining_in_buf = read(service_sock, buf, lower);
							}
							lower = chunk_size < remaining_in_buf ? chunk_size : remaining_in_buf;
							SSL_write(ssl, chunk, lower);
							chunk_size -= lower;
							chunk += lower;
							remaining_in_buf -= lower;
						}
						for (int x = 0; x < 2; ++x) {
							char c;
							if (!remaining_in_buf) {
								read(service_sock, &c, 1);
							} else {
								c = *(chunk++);
								--remaining_in_buf;
							}
							SSL_write(ssl, &c, 1);
						}
					}
				} else {
					// this works for unspecified content-length because all of the response headers will be in `buf`
					if (r_arg(force_connection_close)) {
						SSL_write(ssl, crlfcrlf + 4, after_read_data - crlfcrlf - 4);
					} else {
						SSL_write(ssl, buf, read_bytes);
					}
					while (total_read_resp_body_bytes < length) {
						read_bytes = read(service_sock, buf, r_arg(buf_sz));
						total_read_resp_body_bytes += read_bytes;
						if (read_bytes < 0 || SSL_write(ssl, buf, read_bytes) < 0) {
							goto serve__block__near_end;
						}
					}
				}
				if (!http_keep_alive) {
					goto serve__block__near_end;
				}
			}
		}

		serve__prtcl_2: {
			// to-do: http/2 (http 2)
			fputs("important warning: http/2 is not properly implemented yet - attempting to use a bad generic read/write loop...\n", stderr);
			goto serve__block__rwl;
		}

		// to-do: websockets

		while (!SSL_shutdown(ssl));
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
	serve__general__near_end:;
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