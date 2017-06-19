#ifndef TCPDUMP_FTP_H
#define TCPDUMP_FTP_H

#include "util.h"
#undef OFFSET
#define OFFSET 16
#define FTP 0
#define FTP_DATA 1

void consume_ftp(const u_char * packet, int * verbose, int packet_size, int type);

#endif //TCPDUMP_FTP_H
