#ifndef TCPDUMP_HTTP_H
#define TCPDUMP_HTTP_H

#include "util.h"
#undef OFFSET
#define OFFSET 16

#define HTTP_REQUEST 0
#define HTTP_RESPONSE 1

void consume_http(const u_char * packet, int * verbose, int packet_size, int type);

#endif //TCPDUMP_HTTP_H
