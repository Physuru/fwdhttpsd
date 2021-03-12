#ifndef https_args_h
#define https_args_h

struct http_service {
	char *name;
	unsigned int name_len;
	unsigned int port;
};
#define r_arg(name) __arg_ ## name

#ifndef https_args_c
extern short unsigned int r_arg(timeout);
extern unsigned char r_arg(force_connection_close);
extern unsigned char r_arg(use_stack_buf);
extern int r_arg(uid);
extern int r_arg(gid);
extern char *r_arg(cert_path);
extern char *r_arg(private_key_path);
extern unsigned char r_arg(use_ipv4);
extern short unsigned int r_arg(buf_sz) /* `buf` size */, r_arg(thread_count) /* the amount of threads that will accept incoming data */;
extern struct http_service *r_arg(http_services);
extern struct http_service r_arg(default_http_service);
extern unsigned int r_arg(n_http_services);
int parse_args(char *argv[], char *env[]);
#endif

#endif