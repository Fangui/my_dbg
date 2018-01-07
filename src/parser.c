#include "parser.h"

#include <stdlib.h>

int is_blank(char c)
{
    return c == '\t' || c == '\0' || c == ' ';
}

static inline int is_number(const char c)
{
    return c >= '0' && c <= '9';
}

static inline int is_number_hex(const char c)
{
    return is_number(c) || (c >= 'a' && c <= 'f') || c == 'x';
}

const char *remove_blank(const char *command)
{
    if (!command)
        return NULL;

    while (*command == ' ' || *command == '\t')
        ++command;

    return command;
}

static const char *remove_number(const char *command)
{
    while (is_number(*command))
        ++command;

    return command;
}

static const char *remove_number_hex(const char *command)
{
    while (is_number_hex(*command))
        ++command;

    return command;
}

int parse_examine(const char *str, char *format, long *size, long *start_addr)
{
    if (!str)
        return -1;

    *format = *str;

    if (!(*format == 'x' || *format == 'd' || *format == 'i' || *format == 's'))
        return -1;

    ++str;

    str = remove_blank(str);

    if (*str == '\0')
        return -1;

    *size = strtol(str, NULL, 10);

    str = remove_number(str),
    str = remove_blank(str);

    if (*str == '\0')
        return -1;

    *start_addr = strtol(str, NULL, 16);

    return 0;
}

int parse_disassemble(const char *str, long *size, long *start_addr)
{
    if (!str || *str == '\0')
        return -1;

    *start_addr = strtol(str, NULL, 16);

    str = remove_number_hex(str);
    str = remove_blank(str);

    if (*str == '\0')
        return -1;

    *size = strtol(str, NULL, 10);
    return 0;
}
