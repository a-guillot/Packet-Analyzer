#ifndef TCPDUMP_TRANSPORT_H
#define TCPDUMP_TRANSPORT_H

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "util.h"

#include "bootp.h"
#include "dns.h"
#include "ftp.h"
#include "http.h"
#include "imap.h"
#include "pop.h"
#include "smtp.h"
#include "telnet.h"


#undef OFFSET
#define OFFSET 12

void consume_udp(const u_char * packet, int * verbose, int packet_size);
void consume_tcp(const u_char * packet, int * verbose, int packet_size);
void to_application(const u_char * packet, u_int16_t source, u_int16_t dest, int * verbose, int packet_size);
char * get_options (const struct tcphdr *packet);

void print_udp(const struct udphdr *packet, int *verbose);

// on a besoin du lui donner la taille au cas où ce soit juste un acquittement
void print_tcp(const struct tcphdr *packet, int *verbose, int packet_size);

#endif //TCPDUMP_TRANSPORT_H
