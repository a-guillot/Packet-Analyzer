//
// Created by andreas on 02/11/16.
//

#include "../include/analyseur.h"

pcap_t *handle;
struct args args;
int packet_number;

/**
 * Callback appelée par argp_parse.
 * Permets la gestion des arguments.
 * @param key le paramètre, 'v' par exemple
 * @param arg la valeur associée à key
 * @param state utilisée pour les arguments multiples
 * @return si l'appel a fonctionné ou non
 */
int parse_opt (int key, char *arg, struct argp_state *state)
{
    UNUSED(state);
    switch (key)
    {
        case 'i':
        {
            if ((args.interface = malloc(strlen(arg) * sizeof(char))) == NULL)
            {
                fprintf(stderr, "Erreur lors d'une allocation mémoire.\n");
                exit(2);
            }
            strcpy(args.interface, arg);
            break;
        }
        case 'o':
        {
            if ((args.filename = malloc(strlen(arg) * sizeof(char))) == NULL)
            {
                fprintf(stderr, "Erreur lors d'une allocation mémoire.\n");
                exit(2);
            }
            strcpy(args.filename, arg);
            break;
        }
        case 'f':
        {
            if ((args.filter = malloc(strlen(arg) * sizeof(char))) == NULL)
            {
                fprintf(stderr, "Erreur lors d'une allocation mémoire.\n");
                exit(2);
            }
            strcpy(args.filter, arg);
            break;
        }
        case 'v':
        {
            int v = atoi(arg);
            if (v > 0 && v <= 3)
                args.verbose = v;
            else
            {
                fprintf(stderr, "Verbose doit être compris entre 1 et 3.\n");
                exit(1);
            }
            break;
        }
    }
    return 0;
}

/**
 * Initialise les signaux qui vont permettre de sortir
 * de pcap_loop et de pouvoir free toutes les variables
 * @param signal_handler struct sigaction recevant SIGINT
 */
void init_signals(struct sigaction * signal_handler)
{
    signal_handler->sa_handler = &end_loop;
    signal_handler->sa_flags = 0;

    if ((sigaction(SIGINT, signal_handler, NULL)) != 0)
    {
        fprintf(stderr, "Erreur lors de l'initialisation des signaux.\n");
        perror("sigaction");
        exit(1);
    }
}

/**
 * Empêche pcap_loop() d'appeler la fonction callback et le force donc à se terminer
 */
void end_loop()
{
    pcap_breakloop(handle);
}

/**
 * Traitement des paquets reçus sur le réseau
 * @param args les arguments que l'on souhaite passer à la callback, ici la struct args
 * @param header contient les infos (timestamp, length portion present, length packet off wire)
 * @param packet contient tous les headers encapsulés
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    print_packet_start((int *)args);

    if (*((int *)args) == 3)
    {
        printf("Paquet numéro %d.\n", ++packet_number);
        printf("Reçu au temps                   : %ld.%ld\n", header->ts.tv_sec, header->ts.tv_usec);
        printf("Longueur de la portion présente : %u\n", header->caplen);
        printf("Longueur totale du paquet       : %u\n\n", header->len);
    }
    consume(packet, (int *)args, header->len - 14);
}

int main(int argc, char ** argv) {

    /* Gestion des arguments */
    args.filename = NULL;
    args.filter = NULL;
    args.interface = NULL;
    args.verbose = 3;

     struct argp_option options[] =
            {
                    { "interface", 'i', "DEV", 0, "Interface pour l'analyse live", 0},
                    { "fichier", 'o', "FILE", 0, "Fichier d'entrée pour l'analyse offline", 0},
                    { "filtre_bfp", 'f', "BFP", 0, "Filtre BFP", 0},
                    { "verbose", 'v', "VERBOSE", 0, "Niveau de verbosité", 0},
                    { 0 }
            };
    struct argp argp = { options, parse_opt, 0, 0, 0, 0, 0};
    argp_parse (&argp, argc, argv, 0, 0, 0);

    if (args.interface && args.filename)
    {
        fprintf(stderr, "La capture ne peut pas être live et offline à la fois.\n");
        exit(1);
    }

    /* Création des variables */
    char * dev;                         // Nom de l'interface
    char errbuf[PCAP_ERRBUF_SIZE];      // Buffer contenant les messages d'erreur
    struct sigaction signal_handler;    // structure permettant d'intercepter le Ctrl+C

    struct bpf_program expression;      // Expression du filtre compilée
    bpf_u_int32 mask, net;              // IP+netmask de l'interface filtrée

    /* Gestion de la fin du programme avec l'envoi de signaux */
    init_signals(&signal_handler);

    /* Trouver l'interface si jamais elle n'est pas précisée */
    if (args.interface == NULL)
    {
        if ((dev = pcap_lookupdev(errbuf)) == NULL) {
            fprintf(stderr, "Impossible de trouver l'interface par défaut : '%s'\n", errbuf);
            exit(2);
        }
    }
    else
            dev = args.interface;

    printf("Interface : %s\n\n", dev);

    if (args.filename == NULL)
    {
        /*
         * Ouverture de l'interface en mode Live
         * - "BUFSIZ" est la taille du snapshot qu'on recevra (définir dans pcap.h)
         * - "1" pour utiliser le mode confus
         * - "1000" pour le temps de timeout d'une lecture
         */
        if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL)
        {
            fprintf(stderr, "Impossible d'ouvrir l'interface %s : '%s'\n", dev, errbuf);
            exit(3);
        }
    }
    else
        if ((handle = pcap_open_offline(args.filename, errbuf)) == NULL)
        {
            fprintf(stderr, "Erreur lors de l'ouverture du fichier '%s': %s\n", args.filename, errbuf);
            exit(3);
        }

    if (args.filter)
    {
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "Can't get netmask for device %s\n", dev);
            net = 0;
            mask = 0;
        }
        if (pcap_compile(handle, &expression, args.filter, 0, net) == -1)
        {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", args.filter, pcap_geterr(handle));
            exit(2);
        }
        if (pcap_setfilter(handle, &expression) == -1)
        {
            fprintf(stderr, "Couldn't install filter %s: %s\n", args.filter, pcap_geterr(handle));
            exit(2);
        }
    }

    /*
     * Boucle sur la réception des paquets :
     * - "-1" indique que l'on souhaite recevoir un nombre infini de paquets.
     * - "got_packet" est la fonction de callback qui sera appelée lors de la réception d'un paquet
     * - le dernier paramètre correspond aux paramètres à donner à la callback
     */
    if ((pcap_loop(handle, -1, got_packet, (u_char *)&args.verbose)) == -1)
    {
        fprintf(stderr, "Une erreur est survenue pendant pcap_loop.\n");
        pcap_perror(handle, "Error: ");
        exit(4);
    }

    free(args.filename);
    free(args.filter);
    free(args.interface);
}

/* Notes sur le projet :
 *
 * Les modes online et offline sont exclusifs
 * Utiliser pcap loop plutot que pcap next
 * .2x pour print de l'hexa
 * a terme ne plus utiliser les sniff
 * ntohs nécessaire pour changer l'ordre de certains trucs comme les ports tcp
 * */