#ifndef TCPDUMP_UTIL_H
#define TCPDUMP_UTIL_H

#define UNUSED(x) (void)x
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <stdarg.h>

#undef OFFSET
#define OFFSET 20
#define MAX_LINE_LENGTH 70

void print_ascii(const u_char *s, int taille, int offset);
void pprint(int offset, char * s, ...);
void print_packet_start(int * verbose);

#endif //TCPDUMP_UTIL_H
