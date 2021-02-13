#ifndef https_utils_h
#define https_utils_h

int chrcasecmp(char c1, char c2);
char *memncasemem(char *h, unsigned int h_len, char *s, unsigned int s_len);
char *memnmem(char *h, unsigned int h_len, char *s, unsigned int s_len);
unsigned char setuidgid(int uid, int gid, int chkn_uid, int chkn_gid);
long unsigned int stoui(char *str, unsigned char max_size);
struct http_service *find_service(char *name);
#define stoui64(x) stoui(x, 8)
#define stoui32(x) stoui(x, 4)
#define stoui16(x) stoui(x, 2)
#define stoui8(x) stoui(x, 1)

#endif