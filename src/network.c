//
// Created by andreas on 09/11/16.
//

#include "../include/network.h"

void consume_ip(const u_char * packet, int * verbose, int packet_size)
{
    struct iphdr * ip = (struct iphdr *)packet;
    print_ip(ip, verbose);

    packet_size -= ip->ihl * 4;

    switch (ip->protocol)
    {
        case 6:
            if (*verbose == 3)
                pprint(OFFSET, "TCP\n");
            consume_tcp(packet + (ip->ihl * 4), verbose, packet_size);
            break;
        case 17:
            if (*verbose == 3)
                pprint(OFFSET, "UDP\n");
            consume_udp(packet + (ip->ihl * 4), verbose, packet_size);
            break;
        default:
            printf("Protocole de transport non supporté.\n");
            break;
    }
}
void consume_arp(const u_char * packet, int * verbose, int packet_size)
{
    UNUSED(packet);
    UNUSED(verbose);
    UNUSED(packet_size);
}
void consume_rarp(const u_char * packet, int * verbose, int packet_size)
{
    UNUSED(packet);
    UNUSED(verbose);
    UNUSED(packet_size);
}
void consume_aarp(const u_char * packet, int * verbose, int packet_size)
{
    UNUSED(packet);
    UNUSED(verbose);
    UNUSED(packet_size);
}
void consume_vlan(const u_char * packet, int * verbose, int packet_size)
{
    UNUSED(packet);
    UNUSED(verbose);
    UNUSED(packet_size);
}
void consume_ipv6(const u_char * packet, int * verbose, int packet_size)
{
    UNUSED(packet);
    UNUSED(verbose);
    UNUSED(packet_size);
}

void print_ip(const struct iphdr *packet, int *verbose)
{
    /*
     * inet_aton utilise un buffer statique, il faut donc appeler la fonction 2 fois
     */
    struct in_addr address;
    address.s_addr = packet->saddr;
    char *s = inet_ntoa(address);

    if (*verbose == 2)
    {
        pprint(0, "IP : %s -> ", s);
        address.s_addr = packet->daddr;
        char *s = inet_ntoa(address);
        printf("%s\n", s);
    }
    else if (*verbose == 3)
    {
        pprint(OFFSET, "Version             : %u\n", packet->version);
        pprint(OFFSET, "IHL                 : %u (soit %u octets)\n", packet->ihl, (packet->ihl * 4));
        pprint(OFFSET, "TOS                 : %d\n", packet->tos);
        pprint(OFFSET, "Taille totale       : %u\n", ntohs(packet->tot_len));
        pprint(OFFSET, "Id                  : %u\n", ntohs(packet->id));
        pprint(OFFSET, "Fragment offset     : %u\n", ntohs(packet->frag_off));
        pprint(OFFSET, "TTL                 : %d\n", packet->ttl);
        pprint(OFFSET, "Protocol            : ");

        if (packet->protocol == 0x06)
            printf("TCP (6).\n");
        else if (packet->protocol == 0x11)
            printf("UDP (11).\n");
        else
            printf("%d.\n", packet->protocol);

        pprint(OFFSET, "Checksum            : 0x%04x\n", ntohs(packet->check));
        pprint(OFFSET, "Adresse source      : %s\n", s);

        address.s_addr = packet->daddr;
        char *s = inet_ntoa(address);

        pprint(OFFSET, "Adresse destination : %s\n", s);
    }
}
void print_arp(const u_char *packet, int *verbose)
{
    UNUSED(packet);
    UNUSED(verbose);

    pprint(OFFSET, "Not implemented.\n");
}
void print_rarp(const u_char *packet, int *verbose)
{
    UNUSED(packet);
    UNUSED(verbose);

    pprint(OFFSET, "Not implemented.\n");
}
void print_aarp(const u_char *packet, int *verbose)
{
    UNUSED(packet);
    UNUSED(verbose);

    pprint(OFFSET, "Not implemented.\n");
}
void print_vlan(const u_char *packet, int *verbose)
{
    UNUSED(packet);
    UNUSED(verbose);

    pprint(OFFSET, "Not implemented.\n");
}
void print_ipv6(const u_char *packet, int *verbose)
{
    UNUSED(packet);
    UNUSED(verbose);

    pprint(OFFSET, "Not implemented.\n");
}