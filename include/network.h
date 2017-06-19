//
// Created by andreas on 09/11/16.
//

#ifndef TCPDUMP_NETWORK_H
#define TCPDUMP_NETWORK_H

#include <netinet/ip.h>

#include "util.h"
#include "transport.h"

#undef OFFSET
#define OFFSET 8

void consume_ip(const u_char * packet, int * verbose, int packet_size);
void consume_arp(const u_char * packet, int * verbose, int packet_size);
void consume_rarp(const u_char * packet, int * verbose, int packet_size);
void consume_aarp(const u_char * packet, int * verbose, int packet_size);
void consume_vlan(const u_char * packet, int * verbose, int packet_size);
void consume_ipv6(const u_char * packet, int * verbose, int packet_size);

void print_ip(const struct iphdr *packet, int *verbose);
void print_arp(const u_char *packet, int *verbose);
void print_rarp(const u_char *packet, int *verbose);
void print_aarp(const u_char *packet, int *verbose);
void print_vlan(const u_char *packet, int *verbose);
void print_ipv6(const u_char *packet, int *verbose);

enum protocol4 {UDP, TCP};
#endif //TCPDUMP_NETWORK_H
