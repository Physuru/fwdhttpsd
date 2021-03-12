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

extern int sv_socket;
extern SSL_CTX *ssl_ctx;

extern struct in_addr ipv4_loopback;
extern struct in6_addr ipv6_loopback;

#endif