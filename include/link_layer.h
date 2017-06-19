//
// Created by andreas on 09/11/16.
//

#ifndef TCPDUMP_LINK_LAYER_H
#define TCPDUMP_LINK_LAYER_H


#include <net/ethernet.h>
#include "network.h"

#include "util.h"

#undef OFFSET
#define OFFSET 4

enum protocol {IP_PROTOCOL, ARP, RARP, AARP, VLAN, IPV6, UNKNOWN};

void consume(const u_char *packet, int * verbose, int packet_size);
u_int16_t print(const u_char *packet, int *verbose);
char * get_protocol_name(enum protocol);
enum protocol get_protocol(unsigned int);

#endif //TCPDUMP_LINK_LAYER_H
