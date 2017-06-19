#include "../include/util.h"

void print_ascii(const u_char * s, int taille, int offset)
{
    // pas plus de 50 caractères par ligne
    int i, j, length = 0;

    // on fais le décallage de la première ligne
    for (j = 0; j < offset; j++)
        printf(" ");

    for (i = 0; i < taille; i++)
    {
        if (isprint(s[i]) || isspace(s[i]))
        {
            printf("%c", s[i]);

            if (s[i] == '\n')
                for (j = 0; j < offset; j++)
                    printf(" ");
        }
        length++;

        if (length >= 50)
        {
            printf("\n");
            length = 0;

            // on fais le décallage de chaque nouvelle ligne
            for (j = 0; j < offset; j++)
                printf(" ");
        }
    }

    printf("\n");
}

void pprint(int offset, char * s, ...)
{
    va_list args_list;
    va_start(args_list, s);

    int i;
    for (i = 0; i < offset; i++)
        printf(" ");
    printf("|-> ");

    vfprintf(stdout, s, args_list);
    va_end(args_list);
}

void print_packet_start(int * verbose)
{
    if (*verbose == 2)
        printf("\n");
    else if (*verbose == 3)
    {
        printf("\n\n");

        int i = 0;
        for (i = 0; i < MAX_LINE_LENGTH; i++)
            printf("~");

        printf("\n");
    }
}