#ifndef TCPDUMP_IMAP_H
#define TCPDUMP_IMAP_H

#include "util.h"
#undef OFFSET
#define OFFSET 16

void consume_imap(const u_char * packet, int * verbose, int packet_size);

#endif //TCPDUMP_IMAP_H
