#ifndef https_exit_h
#define https_exit_h

void _clean_then_exit(unsigned char status, unsigned char safe);
#define clean_then_exit() _clean_then_exit(1, 1)
extern unsigned char exiting;

#endif