//
// Created by andreas on 09/11/16.
//

#include "../include/link_layer.h"

void consume(const u_char *packet, int * verbose, int packet_size)
{
    enum protocol protocol = print(packet, verbose);

    switch (protocol)
    {
        case IP_PROTOCOL:
            if (*verbose == 3)
                pprint(OFFSET, "IP\n");
            consume_ip(packet + 14, verbose, packet_size);
            break;
        case ARP:
            consume_arp(packet + 14, verbose, packet_size);
            break;
        case RARP:
            consume_rarp(packet + 14, verbose, packet_size);
            break;
        case AARP:
            consume_aarp(packet + 14, verbose, packet_size);
            break;
        case VLAN:
            consume_vlan(packet + 14, verbose, packet_size);
            break;
        case IPV6:
            consume_ipv6(packet + 14, verbose, packet_size);
            break;
        case UNKNOWN:
        default:
            printf("Unknown network protocol.\n");
            break;
    }
}

u_int16_t print(const u_char *packet, int *verbose)
{
    const struct ether_header *ethernet = (struct ether_header *)(packet);
    unsigned int type = ntohs(ethernet->ether_type);
    enum protocol protocol;

    char * protocol_name = NULL;
    protocol = get_protocol(type);

    if (*verbose == 2)
    {
        pprint(0, "Ethernet : %s -> ", ether_ntoa((struct ether_addr*)&ethernet->ether_shost));
        printf("%s\n", ether_ntoa((struct ether_addr*)&ethernet->ether_dhost));
    }
    else if (*verbose == 3)
    {
        if (protocol != UNKNOWN)
            pprint(0, "Ethernet II utilisant le protocole %s.\n", get_protocol_name(protocol));
        else
            pprint(0, "Etherner 802.3 avec un paquet de taille %.4x.\n", type);

        pprint(OFFSET, "Adresse de destination : %s\n", ether_ntoa((struct ether_addr*)&ethernet->ether_dhost));
        pprint(OFFSET, "Adresse source         : %s\n", ether_ntoa((struct ether_addr*)&ethernet->ether_shost));
    }
    free(protocol_name);

    return protocol;
}

char * get_protocol_name(enum protocol protocol)
{
    char * res = NULL;

    switch (protocol)
    {
        case IP_PROTOCOL:
            res = malloc(strlen("IP") * sizeof(char));
            strcpy(res, "IP");
            break;
        case ARP:
            res = malloc(strlen("ARP") * sizeof(char));
            strcpy(res, "ARP");
            break;
        case RARP:
            res = malloc(strlen("RARP") * sizeof(char));
            strcpy(res, "RARP");
            break;
        case AARP:
            res = malloc(strlen("AARP") * sizeof(char));
            strcpy(res, "AARP");
            break;
        case VLAN:
            res = malloc(strlen("VLAN") * sizeof(char));
            strcpy(res, "VLAN");
            break;
        case IPV6:
            res = malloc(strlen("IPV6") * sizeof(char));
            strcpy(res, "IPV6");
            break;
        case UNKNOWN:
            res = malloc(strlen("UNKNOWN") * sizeof(char));
            strcpy(res, "UNKNOWN");
            break;
    }
    return res;
}
enum protocol get_protocol(unsigned int code)
{
    enum protocol protocol;
    switch (code)
    {
        case ETHERTYPE_IP:
            protocol = IP_PROTOCOL;
            break;
        case ETHERTYPE_ARP:
            protocol = ARP;
            break;
        case ETHERTYPE_REVARP:
            protocol = RARP;
            break;
        case ETHERTYPE_AARP:
            protocol = AARP;
            break;
        case ETHERTYPE_VLAN:
            protocol = VLAN;
            break;
        case ETHERTYPE_IPV6:
            protocol = IPV6;
            break;
        default:
            protocol = UNKNOWN;
            break;
    }
    return protocol;
}