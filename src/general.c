#include "general.h"

pthread_t main_pthread_id = 0;

int sv_socket = 0;
struct sockaddr_in sv_addr = { 0 };
SSL_CTX *ssl_ctx = NULL;

unsigned int _127_0_0_1 = 0x7f000001;
short unsigned int _443 = 443;