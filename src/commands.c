#include "breakpoint.h"
#include "commands.h"
#include "commands_utils.h"
#include "disassemble.h"
#include "parser.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>

static void get_state(pid_t pid)
{
    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status))
    {
        fprintf(stderr, "The program is not being run\n");
        return;
    }

    if (WIFSTOPPED(status))
    {
        printf("0x%08lx\n", get_rip(pid));
    }
}

void cmd_continue(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)arg;

    if (restore_reg(list, pid))
        goto error;

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
        goto error;

    int status;
    waitpid(pid, &status, 0);

    return;

error:
    warnx("Error in continue with ptrace");
}
gdb_cmd(continue, cmd_continue);

void cmd_step(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)arg;

    if (!restore_reg(list, pid))
    {
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        get_state(pid);
    }
    else
        warnx("Error in step_inst while restore with ptrace");
}
gdb_cmd(step_instr, cmd_step);

void cmd_next(const char *arg, pid_t pid, struct wl_list *list)
{

    unsigned long int rip = get_rip(pid);
    if (!rip)
    {
        warnx("Error in next while getting rip");
        return;
    }

    uintptr_t next_inst = check_inst_call(pid, rip, SIZE_INST);

    if (!next_inst)
        cmd_step(arg, pid, list);
    else
    {
        struct breakpoint *bp = add_breakpoint(pid, (void*)next_inst,
                                               TMP_BREAK, 0);
        if (!bp)
            warnx("Error while add breakpoint with ptrace");
        else
            add_list(list, bp);

        cmd_continue(arg, pid, list);
    }
}
gdb_cmd(next_instr, cmd_next);

void cmd_finish(const char *arg, pid_t pid, struct wl_list *list)
{
    long func_addr = get_last_addr(pid);
    if (!func_addr)
        return;

    call_add_breakpoint(func_addr, pid, list, TMP_BREAK);
    cmd_continue(arg, pid, list);
}
gdb_cmd(finish, cmd_finish);

void cmd_attach(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)list;
    if (!arg || *arg == '\0')
    {
        fprintf(stderr, "Need pid to attach\n");
        return;
    }

    pid_t pid_attach = strtol(arg, NULL, 10);

    if (ptrace(PTRACE_ATTACH, pid_attach, NULL, NULL) == -1)
    {
        warnx("Error while ptrace in attach, pid incorrect");
        return;
    }

    int status;
    waitpid(pid, &status, 0);
}
gdb_cmd(attach, cmd_attach);

void cmd_quit(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)list;
    (void)arg;
    (void)pid;
    return;
}
gdb_cmd(quit, cmd_quit);
