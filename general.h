#ifndef https_general_h
#define https_general_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ctype.h>

#include <pthread.h>
#include <signal.h>

#include <netinet/in.h>
#include <openssl/ssl.h>

extern pthread_t main_pthread_id;

extern int sv_sock;
extern struct sockaddr_in sv_addr;
extern SSL_CTX *ssl_ctx;

extern unsigned int _127_0_0_1;
extern short unsigned int _443;

#define CHUNKED_ENCODING 0xFFFFFFFFFFFFFFFF

#endif