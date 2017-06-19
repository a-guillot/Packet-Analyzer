#include "../include/telnet.h"

// seulement quelques options sont faites.
char * get_option_name(int option)
{
    char * s = malloc(40);

    switch (option)
    {
        case TELOPT_ECHO:
            sprintf(s , "%s", "echo");
            break;
        case TELOPT_RCP:
            sprintf(s , "%s", "prepare to reconnect");
            break;
        case TELOPT_SGA:
            sprintf(s , "%s", "suppress go ahead");
            break;
        case TELOPT_TTYPE:
            sprintf(s , "%s", "terminal type");
            break;
        case TELOPT_NAWS:
            sprintf(s , "%s", "window size");
            break;
        case TELOPT_TSPEED:
            sprintf(s , "%s", "terminal speed");
            break;
        case TELOPT_LFLOW:
            sprintf(s , "%s", "remote flow control");
            break;
        case TELOPT_LINEMODE:
            sprintf(s , "%s", "Linemode option");
            break;
        case TELOPT_XDISPLOC:
            sprintf(s , "%s", "X Display Location");
            break;
        default:
            sprintf(s, "%d", option);
            break;
    }

    return s;
}

void consume_telnet(const u_char * packet, int * verbose, int packet_size)
{
    // print l'ascii ou les options serait trop long, j'écris donc juste ce qui se passe dans les messages.
    if (*verbose == 1 || *verbose == 2)
    {
        pprint(0, "TELNET : ");

        if (packet[0] == IAC)
            printf("négociations.\n");
        else
            printf("texte.\n");
    }
    else
    {
        int i;
        char * s;

        // négociation des options
        if (packet[0] == IAC)
        {
            for (i = 0; i < packet_size; i++)
            {
                // si le premier est égal à 255 alors on négocie, sinon on écrit
                if (packet[i] == IAC)
                {
                    i++;
                    switch (packet[i])
                    {
                        case DONT:
                            s = get_option_name(packet[++i]);
                            pprint(OFFSET, "DON'T %s\n", s);
                            free(s);
                            break;
                        case DO:
                            s = get_option_name(packet[++i]);
                            pprint(OFFSET, "DO %s\n", s);
                            free(s);
                            break;
                        case WILL:
                            s = get_option_name(packet[++i]);
                            pprint(OFFSET, "WILL %s\n", s);
                            free(s);
                            break;
                        case WONT:
                            s = get_option_name(packet[++i]);
                            pprint(OFFSET, "WON'T %s\n", s);
                            free(s);
                            break;
                        case SB:
                            pprint(OFFSET, "Sub negociation :\n");

                            s = get_option_name(packet[++i]);
                            pprint(OFFSET, "%s => ", s);
                            free(s);

                            // tant que la négociation n'est pas finie (255 240) et que i ne dépasse pas
                            while ((!((packet[i] == IAC) && (packet[i + 1] == SE))) && (i < packet_size))
                                printf("%d ", packet[i++]);
                            printf("\n");

                            pprint(OFFSET, "end sub negociation\n");
                            i++;
                            break;
                        default:
                            pprint(OFFSET, "unsupported\n");
                            break;
                    }
                }
                else
                {
                    pprint(OFFSET, "unsupported\n");
                }
            }
        }
            // envoi de commandes
        else
        {
            pprint(OFFSET, "\"\n");
            print_ascii(packet, packet_size, OFFSET + 4);
            pprint(OFFSET, "\"\n");
        }
    }

}
