#ifndef TCPDUMP_SMTP_H
#define TCPDUMP_SMTP_H

#include "util.h"
#undef OFFSET
#define OFFSET 16

void consume_smtp(const u_char * packet, int * verbose, int packet_size);

#endif //TCPDUMP_SMTP_H
