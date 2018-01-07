#ifndef PARSER_H_
# define PARSER_H_

int is_blank(char c);

const char *remove_blank(const char *command);

int parse_examine(const char *str, char *format, long *size, long *start_addr);

int parse_disassemble(const char *str, long *size, long *start_addr);

#endif /* !PARSER_H_ */
