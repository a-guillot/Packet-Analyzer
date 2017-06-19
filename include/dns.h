#ifndef TCPDUMP_DNS_H
#define TCPDUMP_DNS_H

#include "util.h"
#include <arpa/nameser_compat.h>

#undef OFFSET
#define OFFSET 16
#define POINTER 0b11000000
#define OFFSET_MASK 0x3fff

struct question
{
    u_int16_t question_type;
    u_int16_t question_class;
};

struct resource {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rData_length;
};

void consume_dns(const u_char * packet, int * verbose, int packet_size);
char * dns_opcode(int code);

u_char * parse_questions(u_char * questions, int question_number);
u_char * parse_answers(u_char * total, u_char * answers, int answer_number);
u_char * parse_auth(u_char * total, u_char * answers, int answer_number);
u_char * parse_resources(u_char * total, u_char * answers, int answer_number);
u_char * dns_name(u_char * total, u_char * question);
u_char * dns_print_resource(u_char * answer);

#endif //TCPDUMP_DNS_H
