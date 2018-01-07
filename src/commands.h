#ifndef COMMANDS_H_
# define COMMANDS_H_

#include <sys/types.h>

struct wl_list;

#define gdb_cmd(cmd_name, cmd_func) \
static struct command __name_ ## cmd_name \
__attribute__ ((section("cmds"), used)) = \
{ .name = #cmd_name, .func = cmd_func }

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX_SIZE_INST 64
#define SIZE_INST 8

struct command
{
    char *name;
    void (*func)(const char *str, pid_t pid, struct wl_list *list);
};

#endif /* !COMMANDS_H_ */
