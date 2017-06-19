#include "../include/ftp.h"

void consume_ftp(const u_char * packet, int * verbose, int packet_size, int type)
{
    if (*verbose == 1 || *verbose == 2)
    {
        pprint(0, "FTP");

        if (type == FTP_DATA)
            printf("-DATA");

        printf("\n");
    }
    else
    {
        pprint(OFFSET, "\"\n");
        print_ascii(packet, packet_size, OFFSET + 4);
        pprint(OFFSET, "\"\n");
    }
}