#include "../include/bootp.h"

void consume_bootp(const u_char * packet, int * verbose, int packet_size)
{
    struct bootp * bootp = (struct bootp *) packet;

    int magicCookie[4] = VM_RFC1048;
    int i, offset, dhcp = 1;

    if (*verbose == 1)
    {
        for (i = 0; i < 4; i++)
            if (magicCookie[i] != bootp->bp_vend[i])
                dhcp = 0;
        pprint(0, "BOOTP ");
        if (dhcp)
            printf("+ DHCP\n");
        else
            printf("\n");
    }
    else if (*verbose == 2)
    {
        for (i = 0; i < 4; i++)
            if (magicCookie[i] != bootp->bp_vend[i])
                dhcp = 0;
        pprint(0, "BOOTP ");
        if (dhcp)
            printf("+ DHCP\n");
        else
            printf("\n");
    }
    else
    {
        pprint(OFFSET, "Packet opcode type : ");
        if (bootp->bp_op == BOOTREPLY)
            printf("boot reply");
        else
            printf("boot request");
        printf("\n");

        if (bootp->bp_htype == 1)
            pprint(OFFSET, "Hardware address type : Ethernet.\n");
        else
            pprint(OFFSET, "hardware addr type : %hhu\n", (unsigned char) bootp->bp_htype);

        pprint(OFFSET, "hardware addr len : %hhu\n", (unsigned char) bootp->bp_hlen);
        pprint(OFFSET, "gateway hops : %hhu\n", (unsigned char) bootp->bp_hops);

        pprint(OFFSET, "Transaction ID : 0x%08x\n", ntohl(bootp->bp_xid));
        pprint(OFFSET, "seconds since boot began : %d\n", ntohs(bootp->bp_secs));
        pprint(OFFSET, "flags : %d\n", ntohs(bootp->bp_flags));

        pprint(OFFSET, "client ip address : %s\n", inet_ntoa(bootp->bp_ciaddr));
        pprint(OFFSET, "your ip address : %s\n", inet_ntoa(bootp->bp_yiaddr));
        pprint(OFFSET, "server ip address : %s\n", inet_ntoa(bootp->bp_siaddr));
        pprint(OFFSET, "gateway ip address : %s\n", inet_ntoa(bootp->bp_giaddr));

        pprint(OFFSET, "client hardware address : %s\n", ether_ntoa((struct ether_addr*)&bootp->bp_chaddr));

        if (*bootp->bp_sname == 0)
            pprint(OFFSET, "Server host name not given.\n");
        else
            pprint(OFFSET, "server host name : %s\n", bootp->bp_sname);

        if (*bootp->bp_file == 0)
            pprint(OFFSET, "Boot file name not given.\n");
        else
            pprint(OFFSET, "boot file name : %s\n", bootp->bp_file);

        for (i = 0; i < 4; i++)
            if (magicCookie[i] != bootp->bp_vend[i])
                dhcp = 0;

        // TODO décaler, enum sur type dhcp, rendre propre
        if (dhcp)
        {
            pprint(OFFSET, "DHCP\n");

            // remove bootp header size + magic cookie
            packet_size -= 240;
            packet = packet + 240;
            i = 0;

            if (packet[0] == TAG_DHCP_MESSAGE && packet[1] == 1)
            {
                char * s = dhcp_type(packet[2]);
                pprint(OFFSET + 4, "Type : %s\n", s);
                free(s);
                i = 3;
            }

            for ((void)i; i < packet_size; i++)
            {
                offset = packet[i+1];

                if (packet[i] == 255 && offset == 0)
                {
                    pprint(OFFSET + 4, "End.\n");
                    break;
                }

                char * s = dhcp_option_name(packet[i]);
                pprint(OFFSET + 4, "%s -> ", s);
                free(s);

                i += 2;

                while (offset > 0)
                {
                    printf("%01x ", packet[i++]);
                    offset--;
                }
                i--;
                printf("\n");
            }
        }
    }
}
char * dhcp_type(int option)
{
    char * s = malloc(20);

    switch (option)
    {
        case DHCPDISCOVER:
            strcpy(s, "discover");
            break;
        case DHCPOFFER:
            strcpy(s, "offer");
            break;
        case DHCPREQUEST:
            strcpy(s, "request");
            break;
        case DHCPDECLINE:
            strcpy(s, "decline");
            break;
        case DHCPACK:
            strcpy(s, "ack");
            break;
        case DHCPNAK:
            strcpy(s, "nack");
            break;
        case DHCPRELEASE:
            strcpy(s, "release");
            break;
        case DHCPINFORM:
            strcpy(s, "inform");
            break;
    }

    return s;
}

char * dhcp_option_name(int option)
{
    char * s = malloc(40);

    switch (option)
    {
        case TAG_CLIENT_ID:
            sprintf(s , "%s", "client identifier");
            break;
        case TAG_SUBNET_MASK:
            sprintf(s , "%s", "subnet mask");
            break;
        case TAG_REQUESTED_IP:
            sprintf(s , "%s", "requested ip address");
            break;
        case TAG_PARM_REQUEST:
            sprintf(s , "%s", "parameter request list");
            break;
        case TAG_RENEWAL_TIME:
            sprintf(s , "%s", "renewal time value");
            break;
        case TAG_REBIND_TIME:
            sprintf(s , "%s", "rebinding time value");
            break;
        case TAG_IP_LEASE:
            sprintf(s , "%s", "ip address lease time");
            break;
        case TAG_SERVER_ID:
            sprintf(s , "%s", "dhcp server identifier");
            break;
        default:
            sprintf(s, "%d", option);
            break;
    }

    return s;
}