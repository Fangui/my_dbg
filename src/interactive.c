#include "breakpoint.h"
#include "commands.h"
#include "interactive.h"
#include "parser.h"

#include <err.h>
#include <libunwind-ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>

extern struct command __start_cmds[];
extern struct command __stop_cmds[];

static char *character_name_generator(const char *text, int state)
{
    static unsigned idx;
    static unsigned len;

    if (!state)
    {
        idx = 0;
        len = strlen(text);
    }

    while (idx < __stop_cmds - __start_cmds)
    {
        struct command *cmd = __start_cmds + idx++;
        if (!strncmp(cmd->name, text, len))
            return strdup(cmd->name);
    }

    return NULL;
}

static char **character_name_completion(const char *text, int start, int end)
{
    (void)start;
    (void)end;

    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, character_name_generator);
}

static void list_delete(struct wl_list *list)
{
    struct breakpoint *bp = wl_container_of(list->next, bp, link);

    while (&bp->link != list)
    {
        struct breakpoint *tmp = bp;
        bp = wl_container_of(bp->link.next, bp, link);
        
        free(tmp);
    }
}

static void interactive(pid_t pid)
{
    char *command = NULL;
    struct wl_list list;
    wl_list_init(&list);

    rl_attempted_completion_function = character_name_completion;
    rl_outstream = stderr;

    while (1)
    {
        command = readline("dbg> ");

        const char *new_command = remove_blank(command);
        if (!command || (!strncmp(new_command, "quit", 4)
                     && is_blank(new_command[4])))
        {
            list_delete(&list);
            break;
        }

        int has_found = 0;

        for (unsigned i = 0; i < __stop_cmds - __start_cmds  && !has_found; ++i)
        {
            struct command *cmd = __start_cmds + i;
            unsigned len = strlen(cmd->name);
            if (!strncmp(new_command, cmd->name, len) && 
                 is_blank(new_command[len]))
            {
                has_found = 1;
                cmd->func(remove_blank(new_command + len), pid, &list);
            }
        }
        if (!has_found)
            fprintf(stderr, "Undefined command: %s. Try help.\n", command);

        add_history(command);
        free(command);
    }

    fprintf(stderr, "quit\n");
    free(command);
}

void init_interact(int argc, char *argv[])
{
    pid_t fork_ret = fork();

    if (fork_ret > 0)
    {
        int id = waitpid(fork_ret, NULL, 0);
        if (id == -1)
            err(1, "error while waitpid");

        interactive(fork_ret);

    }
    else if (fork_ret == 0)
    {
        if (argc > 1)
        {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
                err(1, "Error while trace program");

            if (execvp(argv[1], argv + 1))
                err(1, "Error while execvp %s", argv[1]);
        }
    }
    else
        err(1, "Error while fork");
}
