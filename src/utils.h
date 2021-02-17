#ifndef https_utils_h
#define https_utils_h

#include <openssl/ssl.h>

unsigned char setuidgid(int uid, int gid, int chkn_uid, int chkn_gid);
long unsigned int stoui(char *str, unsigned char max_size, char end_char);
struct http_service *find_service(char *name);
#define stoui64(x) stoui(x, 8, 0)
#define stoui32(x) stoui(x, 4, 0)
#define stoui16(x) stoui(x, 2, 0)
#define stoui8(x) stoui(x, 1, 0)
void quick_respond(SSL *, unsigned char, char *, char *);
void quick_respond_err(SSL *, unsigned char, unsigned char);
void skip_space_tab(char **);
void skip_to_cr(char **);
void find_headers(char *str, char *str_end, short unsigned int n, ...);

#define NOTIFY_ERR(err_id) quick_respond_err(ssl, expected_protocol_id, err_id)
#define CLIENT_PRTCL_NOT_IMPLEMENTED 0
#define REQ_HEADERS_TOO_LONG 1
#define NO_HOST_HEADER 2
#define INVALID_SERVICE 3
#define SERVICE_DOWN 4
#define SERVER_PRTCL_NOT_IMPLEMENTED 5
#define HTTP_VERSION_MISMATCH 6
#define RES_HEADERS_TOO_LONG 7
#define RES_HEADERS_IMPROPER 8

#endif