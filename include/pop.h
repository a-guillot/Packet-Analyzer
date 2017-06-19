#ifndef TCPDUMP_POP_H
#define TCPDUMP_POP_H

#include "util.h"
#undef OFFSET
#define OFFSET 16

void consume_pop(const u_char * packet, int * verbose, int packet_size);

#endif //TCPDUMP_POP_H
