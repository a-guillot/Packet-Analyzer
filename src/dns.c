#include "../include/dns.h"

void consume_dns(const u_char * p, int * verbose, int packet_size)
{
    u_char * packet = (unsigned char *)malloc(packet_size);
    memcpy(packet, p, packet_size);

    HEADER *dns = (HEADER *) p;

    int question_number = ntohs(dns->qdcount);
    int answer_number = ntohs(dns->ancount);
    int authority_number = ntohs(dns->nscount);
    int resource_number = ntohs(dns->arcount);

    if (*verbose == 1 || *verbose == 2)
    {
        pprint(0, "DNS ");
        if (dns->qr) printf("Reponse ");
        else printf("Query ");

        // opcode
        char * s = dns_opcode(dns->opcode);
        printf("Opcode : %s.\n", s);
        free(s);
    }
    else
    {
        pprint(OFFSET, "Query Identification Number : 0x%2x\n", ntohs(dns->id));

        // type
        pprint(OFFSET, "Type : ");

        if (dns->qr) printf("Reponse.\n");
        else printf("Query.\n");

        // opcode
        char * s = dns_opcode(dns->opcode);
        pprint(OFFSET, "Opcode : %s.\n", s);
        free(s);

        // truncated or not
        pprint(OFFSET, "The message is ");
        if (dns->tc)
            printf ("truncated.\n");
        else
            printf("not truncated.\n");

        // do or do not query recursively
        pprint(OFFSET, "Do ");
        if (!dns->rd) printf("not ");
        printf("query recursively.\n");

        // recursion is or is not available
        pprint(OFFSET, "Recursion is ");
        if (!dns->ra) printf("not ");
        printf("available.\n");

        // authoritative or not
        pprint(OFFSET, "Authoritative : ");
        if (dns->aa) printf("yes.\n");
        else printf("no.\n");

        // number of painful things to parse
        pprint(OFFSET, "Number of questions   : %d.\n", question_number);
        pprint(OFFSET, "Number of answers     : %d.\n", answer_number);
        pprint(OFFSET, "Number of authorities : %d.\n", authority_number);
        pprint(OFFSET, "Number of resources   : %d.\n", resource_number);

        // move the cursor to after the header
        packet = packet + 12;
        packet_size -= 12;

        u_char * next;

        // print les questions et se replace au bon endroit
        if (question_number > 0)
            next = parse_questions(packet, question_number);

        // print les réponses et se déplace au bon endroit
        if (answer_number > 0)
            next = parse_answers(packet, next, answer_number);

        if (authority_number > 0)
            next = parse_auth(packet, next, authority_number);

        if (resource_number > 0)
            next = parse_resources(packet, next, resource_number);
    }
}

char * dns_opcode(int code)
{
    char *s = malloc(30);

    switch (code)
    {
        case 0:
            strcpy(s, "Query");
            break;
        case 1:
            strcpy(s, "Inverse Query");
            break;
        case 2:
            strcpy(s, "Server Status Request");
            break;
        case 4:
            strcpy(s, "Notify");
            break;
        case 5:
            strcpy(s, "Update");
            break;
        default:
            sprintf(s, "%d", code);
            break;
    }

    return s;
}

u_char * parse_questions(u_char * questions, int question_number)
{
    pprint(OFFSET, "Questions :\n");
    int i;

    for (i = 0; i < question_number; i++)
    {
        pprint(OFFSET + 4, "");

        // on se déplace du bon nombre d'octets
        questions = dns_name(questions, questions) + 5;
        printf("\n");

        struct question *q = (struct question *)questions;
        pprint(OFFSET + 4, "Question type  : %d\n", ntohs(q->question_type));
        pprint(OFFSET + 4, "Question class : %d\n", ntohs(q->question_class));

        questions += 4;
    }

    return questions;
}

u_char * parse_answers(u_char * total, u_char * answers, int answer_number)
{
    pprint(OFFSET, "Answers :\n");
    int i;


    for (i = 0; i < answer_number; i++)
    {
        pprint(OFFSET + 4, "");

        answers = dns_name(total, answers) + 2;
        printf("\n");

        answers = dns_print_resource(answers);
    }

    return answers;
}

u_char * parse_auth(u_char * total, u_char * authorities, int authority_number)
{
    pprint(OFFSET, "Authorities :\n");
    int i;


    for (i = 0; i < authority_number; i++)
    {
        pprint(OFFSET + 4, "");

        authorities = dns_name(total, authorities) + 2;
        printf("\n");

        authorities = dns_print_resource(authorities);
    }

    return authorities;
}

u_char * parse_resources(u_char * total, u_char * resources, int resource_number)
{
    pprint(OFFSET, "Resources :\n");
    int i;


    for (i = 0; i < resource_number; i++)
    {
        pprint(OFFSET + 4, "");

        resources = dns_name(total, resources) + 2;
        printf("\n");

        resources = dns_print_resource(resources);
    }

    return resources;
}

u_char * dns_print_resource(u_char * resource)
{
    struct resource *r = (struct resource *)resource;
    uint16_t type = ntohs(r->type);
    uint16_t class = ntohs(r->class);
    uint32_t ttl = ntohl(r->ttl);
    uint16_t length = ntohs(r->rData_length);

    pprint(OFFSET + 4, "Type   : %u\n", type);
    pprint(OFFSET + 4, "Class  : %u\n", class);
    pprint(OFFSET + 4, "TTL    : %u\n", ttl);
    pprint(OFFSET + 4, "Length : %u\n", length);

    return resource + 10;
}

u_char * dns_name(u_char * total, u_char * question)
{
    int i;
    u_int8_t first_byte = question[0];

    // si jamais c'est un pointeur
    if (first_byte >= POINTER)
    {
        dns_name(question, total);
    }
    // si c'est directement le nom
    else
    {
        for (i = 1; i <= first_byte; i++)
            if (isprint(question[i]))
                printf("%c", question[i]);

        u_char * next = question + first_byte + 1;

        // le nom continue
        if (*next != 0)
        {
            printf(".");

            question = dns_name(total, next);
        }
    }

    return question;
}