#ifndef COMMANDS_UTILS_H_
# define COMMANDS_UTILS_H_

#include <sys/types.h>
#include <stdint.h>

void my_cat(const char *path);

char *get_proc_system(const char *exe, pid_t pid);

unsigned long int get_rip(pid_t pid);

uint8_t *read_process(pid_t pid, long size, long start_addr);

uint8_t *read_peektext(pid_t pid, long size, long start_addr);

void examine_print(char format, long size, const uint8_t *buf);

long get_last_addr(pid_t pid);

#endif /* !COMMANDS_UTILS_H_ */
