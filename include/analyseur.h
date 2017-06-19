//
// Created by andreas on 02/11/16.
//

#ifndef TCPDUMP_ANALYSEUR_H
#define TCPDUMP_ANALYSEUR_H

#include "../include/link_layer.h"
#include "../include/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <argp.h>
#include <signal.h>

struct args
{
    char *interface;
    char *filename;
    char *filter;
    int verbose;
};

void init_signals(struct sigaction * signal_handler);
void end_loop();
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);
int parse_opt (int key, char *arg, struct argp_state *state);


#endif //TCPDUMP_ANALYSEUR_H
