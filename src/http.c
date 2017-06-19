#include "../include/http.h"

void consume_http(const u_char * packet, int * verbose, int packet_size, int type)
{
    if (*verbose == 1 || *verbose == 2)
    {
        pprint(0, "HTTP : ");

        if (type == HTTP_REQUEST)
            printf("Request ");
        else
            printf("Response ");

        if (packet[0] == 0x47 && packet[1] == 0x45 && packet[2] == 0x054)
            printf("(GET).\n");
        else if (packet[0] == 0x050 && packet[1] == 0x4f
                && packet[2] == 0x53 && packet[3] == 0x54)
            printf("(POST).\n");
        else
            printf("\n");
    }
    else
    {
        pprint(OFFSET, "\"\n");
        print_ascii(packet, packet_size, OFFSET + 4);
        pprint(OFFSET, "\"\n");
    }
}