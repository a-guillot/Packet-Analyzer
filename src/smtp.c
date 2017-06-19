#include "../include/smtp.h"

void consume_smtp(const u_char * packet, int * verbose, int packet_size)
{
    if (*verbose == 1 || *verbose == 2)
    {
        pprint(0, "SMTP : %d octets de données.\n", packet_size);
    }
    else
    {
        pprint(OFFSET, "\"\n");
        print_ascii(packet, packet_size, OFFSET + 4);
        pprint(OFFSET, "\"\n");
    }
}
