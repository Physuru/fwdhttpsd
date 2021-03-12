#include "general.h"

pthread_t main_pthread_id = 0;

int sv_socket = 0;
SSL_CTX *ssl_ctx = NULL;

struct in_addr ipv4_loopback = { .s_addr = 0x7f000001 };
struct in6_addr ipv6_loopback = { 0 };