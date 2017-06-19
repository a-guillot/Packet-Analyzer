#include "../include/transport.h"

void to_application(const u_char * packet, u_int16_t source, u_int16_t dest, int * verbose, int packet_size)
{
    if (packet_size > 0)
    {
        if (((source == 67) || (source == 68)) || ((dest == 67) || (dest == 68)))
        {
            if (*verbose == 3)
                pprint(OFFSET, "BOOTP\n");
            consume_bootp(packet, verbose, packet_size);
        }

        else if ((source == 53) || (dest == 53))
        {
            if (*verbose == 3)
                pprint(OFFSET, "DNS\n");
            consume_dns(packet, verbose, packet_size);
        }

        else if ((source == 25) || (dest == 25))
        {
            if (*verbose == 3)
                pprint(OFFSET, "SMTP\n");
            consume_smtp(packet, verbose, packet_size);
        }

        else if ((source == 110) || (dest == 110))
        {
            if (*verbose == 3)
                pprint(OFFSET, "POP\n");
            consume_pop(packet, verbose, packet_size);
        }

        else if ((source == 143) || (dest == 143))
        {
            if (*verbose == 3)
                pprint(OFFSET, "IMAP\n");
            consume_imap(packet, verbose, packet_size);
        }

        else if ((source == 23) || (dest == 23))
        {
            if (*verbose == 3)
                pprint(OFFSET, "TELNET\n");
            consume_telnet(packet, verbose, packet_size);
        }

        else if (((source == 20) || (source == 21)) || ((dest == 20) || (dest == 21)))
        {
            if (*verbose == 3)
                pprint(OFFSET, "FTP\n");

            int type;
            if (source == 21 || dest == 21)
                type = FTP;
            else
                type = FTP_DATA;

            consume_ftp(packet, verbose, packet_size, type);
        }

        else if ((source == 80) || (dest == 80))
        {
            if (*verbose == 3)
                pprint(OFFSET, "HTTP\n");

            int type;
            if (dest == 80)
                type = HTTP_REQUEST;
            else
                type = HTTP_RESPONSE;

            consume_http(packet, verbose, packet_size, type);
        }

        else
            pprint(OFFSET, "Protocole applicatif non implémenté.\n");
    }
}

void consume_udp(const u_char * packet, int * verbose, int packet_size)
{
    struct udphdr * udp = (struct udphdr *)packet;
    print_udp(udp, verbose);

    packet_size -= 8;

    to_application((packet + 8), ntohs(udp->source), ntohs(udp->dest), verbose, packet_size);
}

void consume_tcp(const u_char * packet, int * verbose, int packet_size)
{
    struct tcphdr * tcp = (struct tcphdr *)packet;
    print_tcp(tcp, verbose, packet_size);

    packet_size -= 4 * tcp->doff;

    to_application((packet + (4 * tcp->doff)), ntohs(tcp->source), ntohs(tcp->dest), verbose, packet_size);
}

void print_udp(const struct udphdr *packet, int *verbose)
{
    if (*verbose == 2)
    {
        pprint(0, "UDR : source = %u, destination = %u\n", ntohs(packet->source), ntohs(packet->dest));
    }
    else if (*verbose == 3)
    {
        pprint(OFFSET, "Port source      : %u\n", ntohs(packet->source));
        pprint(OFFSET, "Port destination : %u\n", ntohs(packet->dest));
        pprint(OFFSET, "Longueur         : %u\n", ntohs(packet->len));
        pprint(OFFSET, "Checksum         : 0x%04x\n", ntohs(packet->check));
    }
}

void print_tcp(const struct tcphdr *packet, int *verbose, int packet_size)
{
    char * options = get_options(packet);

    if ((*verbose == 1) && (packet_size == (4 * packet->doff)))
    {
        pprint(0, "TCP : %s\n", options);
    }
    else if (*verbose == 2)
    {
        pprint(0, "TCP : source = %u, destination = %u, options = %s\n",
               ntohs(packet->source),
               ntohs(packet->dest),
               options);
    }
    else if (*verbose == 3)
    {
        pprint(OFFSET, "Port source           : %u\n", ntohs(packet->source));
        pprint(OFFSET, "Port destination      : %u\n", ntohs(packet->dest));
        pprint(OFFSET, "Numéro de séquence    : %u\n", ntohl(packet->seq));
        pprint(OFFSET, "Numéro d'acquittement : %u\n", ntohl(packet->ack_seq));
        pprint(OFFSET, "Data Offset           : %u\n", packet->doff);

        pprint(OFFSET, "Activated flags       : %s\n", options);

        pprint(OFFSET, "Fenêtre               : %u\n", ntohs(packet->window));
        pprint(OFFSET, "Checksum              : 0x%04x\n", ntohs(packet->check));
        pprint(OFFSET, "Pointeur urgent       : %u\n", ntohs(packet->urg_ptr));
    }

    free(options);
}

char * get_options (const struct tcphdr *packet)
{
    char * options = malloc(40);
    short needs_comma = 0;

    if (1 & packet->urg)
    {
        strcat(options, "URG");
        needs_comma = 1;
    }
    if (1 & packet->rst)
    {
        if (needs_comma)
            strcat(options, ", ");
        strcat(options, "RST");
        needs_comma = 1;
    }
    if (1 & packet->psh)
    {
        if (needs_comma)
            strcat(options, ", ");
        strcat(options, "PSH");
        needs_comma = 1;
    }
    if (1 & packet->urg)
    {
        if (needs_comma)
            strcat(options, ", ");
        strcat(options, "URG");
        needs_comma = 1;
    }
    if (1 & packet->syn)
    {
        if (needs_comma)
            strcat(options, ", ");
        strcat(options, "SYN");
        needs_comma = 1;
    }
    if (1 & packet->fin)
    {
        if (needs_comma)
            strcat(options, ", ");
        strcat(options, "FIN");
        needs_comma = 1;
    }
    if (1 & packet->ack)
    {
        if (needs_comma)
            strcat(options, ", ");
        strcat(options, "ACK");
    }

    return options;
}