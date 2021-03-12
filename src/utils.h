#ifndef https_utils_h
#define https_utils_h

#include <openssl/ssl.h>

unsigned char setuidgid(int uid, int gid, int chkn_uid, int chkn_gid);
long unsigned int stoui(char *str, unsigned char max_size, char end_char);
extern struct http_service *(*find_service)(char *name, char *after_buf);
#define stoui64(x) stoui(x, 8, 0)
#define stoui32(x) stoui(x, 4, 0)
#define stoui16(x) stoui(x, 2, 0)
#define stoui8(x) stoui(x, 1, 0)
void quick_respond(SSL *ssl, unsigned char protocol_id, char *status, char *res_body);
void skip_space_tab(char **str, char *after_str);
void skip_to_crlf(char **str, char *after_str);
char find_headers(char *ssl, char *str, unsigned int n, ...);

void quick_respond_err(SSL *ssl, unsigned char protocol_id, unsigned char err_id);
#define CLIENT_PRTCL_NOT_IMPLEMENTED 0
#define REQ_HEADERS_TOO_LONG 1
#define NO_HOST_HEADER 2
#define INVALID_SERVICE 3
#define SERVICE_DOWN 4
#define SERVER_PRTCL_NOT_IMPLEMENTED 5
#define HTTP_VERSION_MISMATCH 6
#define RES_HEADERS_TOO_LONG 7
#define RES_HEADERS_IMPROPER 8
#define REQ_HEADERS_IMPROPER 9

#endif