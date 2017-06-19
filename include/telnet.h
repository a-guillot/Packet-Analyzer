#ifndef TCPDUMP_TELNET_H
#define TCPDUMP_TELNET_H

#include <arpa/telnet.h>
#include "util.h"

#undef OFFSET
#define OFFSET 16

void consume_telnet(const u_char * packet, int * verbose, int packet_size);
char * get_option_name(int option);

#endif //TCPDUMP_TELNET_H
