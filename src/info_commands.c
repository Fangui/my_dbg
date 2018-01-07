#include "breakpoint.h"
#include "commands.h"
#include "commands_utils.h"

#include <err.h>
#include <libunwind-ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

void cmd_help(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)list;
    (void)arg;
    (void)pid;

    printf("%s", "info_regs: display registers\n"
            "info_memory: display the memory mappings of the debugged program\n"
            "disassemble: display size instructions starting at the "
                          "adresse start_addr\n"
            "examine: read into the debugged program memory "
                      "and display it with $format\n"

            "backtrace: display the call trace at the current rip\n"
            "breakpoint: set a breakpoint to the indicate address\n"
            "break_del: delete the breakpoint matching the ID\n"
            "break_list: display breakpoints with their types, "
                         "ID and addresses\n"
            "tbreak: set a tempory breakpoint that can only be hit one time\n"
            "breakf: set a breakpoint on the first matching symbol found\n"
            "step_instr: step into the program\n"
            "next_instr: same as step_instr but will step over "
                         "a call function if there is one\n"
            "finish: continues until the end of the current function\n"
            "continue: continue the program being debugged\n"
            "attach: Attach the pid to the process\n"
            "quit: exit\n"
            "help: display help message\n");
}
gdb_cmd(help, cmd_help);

#define print_reg(name) \
    printf("%s: 0x%llx\n", #name, regs.name)
void cmd_info_regs(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)arg;
    (void)list;

    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    print_reg(rip);
    print_reg(rsp);
    print_reg(rbp);
    print_reg(eflags);
    print_reg(orig_rax);
    print_reg(rax);
    print_reg(rbx);
    print_reg(rcx);
    print_reg(rdx);
    print_reg(rdi);
    print_reg(rsi);
    print_reg(r8);
    print_reg(r9);
    print_reg(r10);
    print_reg(r11);
    print_reg(r12);
    print_reg(r13);
    print_reg(r14);
    print_reg(r15);
    print_reg(cs);
    print_reg(ds);
    print_reg(es);
    print_reg(fs);
    print_reg(gs);
    print_reg(ss);
    print_reg(fs_base);
    print_reg(gs_base);
}
gdb_cmd(info_regs, cmd_info_regs);

#define SYM_SIZE 256
void cmd_backtrace(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)arg;
    (void)list;

    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
    struct UPT_info *ui = _UPT_create(pid);

    if (!as || !ui)
    {
        warn("Error in backtrace while create address");
        goto END;
    }
    unw_cursor_t cursor;
    unsigned cpt = 0;

    if (unw_init_remote(&cursor, as, ui))
    {
        warn("Error in backtrace while init remote");
        goto END;
    }

    while (unw_step(&cursor) > 0)
    {
        unw_word_t offset;
        unw_word_t pc;
        unw_get_reg(&cursor, UNW_REG_IP, &pc);
        if (pc == 0)
            break;

        char sym[SYM_SIZE];
        if (!unw_get_proc_name(&cursor, sym, SYM_SIZE, &offset))
            printf("#%u 0x%lx in %s\n", cpt, pc, sym);
        else
        {
            warnx("Error: unable to obtain symbol");
            break;
        }
        ++cpt;
    }

END:
    unw_destroy_addr_space(as);
    _UPT_destroy(ui);
}
gdb_cmd(backtrace, cmd_backtrace);

void cmd_info_memory(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)list;
    (void)arg;

    char *file = get_proc_system("maps", pid);

    if (!file || access(file, F_OK) == -1)
        warnx("Can't get info_memory");
    else
        my_cat(file);

    free(file);
}
gdb_cmd(info_memory, cmd_info_memory);

void cmd_break_list(const char *arg, pid_t pid, struct wl_list *list)
{
    (void)arg;
    (void)pid;

    struct breakpoint *bp = NULL;

    wl_list_for_each_reverse(bp, list, link)
    {
        bp->is_tmp ? printf("TYPE: Tbreak ") : printf("TYPE: Breakpoint");
        printf("ID : %u | TYPE ADDR 0x%lx\n", bp->id, (uintptr_t)bp->addr);
    }
}
gdb_cmd(break_list, cmd_break_list);
