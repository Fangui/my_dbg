#include "breakpoint.h"

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdlib.h>

void call_add_breakpoint(long addr, pid_t pid,
                         struct wl_list *list, char is_tmp)
{
    unsigned id = 1;
    if (list->next != list)
    {
        struct breakpoint *tmp = wl_container_of(list->next, tmp, link);
        id = tmp->id + 1;
    }

    struct breakpoint *bp = add_breakpoint(pid, (void*)addr, is_tmp, id);
    if (!bp)
        warnx("Error while add breakpoint with ptrace");
    else
        add_list(list, bp);
}

struct breakpoint *add_breakpoint(pid_t pid, void *addr,
                                  char is_tmp, unsigned id)
{
    struct breakpoint *bp = malloc(sizeof(struct breakpoint));
    if (!bp)
        return NULL;

    bp->addr   = addr;
    bp->is_tmp = is_tmp;
    bp->id     = id;
    if (set_breakpoint(bp, pid))
    {
        free(bp);
        return NULL;
    }

    if (!is_tmp)
        printf("%s %u in 0x%lx\n", "Add breakpoint n", id, (uintptr_t)addr);

    return bp;
}

int set_breakpoint(struct breakpoint *bp, pid_t pid)
{
    long orig = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, NULL);
    if (orig == -1 && errno)
        return -1;

    if (ptrace(PTRACE_POKETEXT, pid, bp->addr,
              (orig & TRAP_MASK) | TRAP_INST, NULL) == -1)
        return -1;

     bp->origin = orig;
     return 0;
}

struct breakpoint *get_breakpoint(struct wl_list *list, uintptr_t addr)
{
    struct breakpoint *bp = NULL;

    wl_list_for_each(bp, list, link)
    {
        if (bp->addr == (void*)addr)
            return bp;
    }

    return NULL;
}

struct breakpoint *get_breakpoint_id(struct wl_list *list, unsigned id)
{
    struct breakpoint *bp = NULL;

    wl_list_for_each(bp, list, link)
    {
        if (bp->id == id)
            return bp;
    }

    return NULL;
}

static void remove_breakpoint(struct breakpoint *bp)
{
    wl_list_remove(&bp->link);
    free(bp);
}

int delete_breakpoint(pid_t pid, struct breakpoint *bp)
{
    long origin = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, NULL);
    if (origin == -1 && errno)
        return -1;

    void *ptr_origin = (void *)((origin & TRAP_MASK) | (bp->origin & 0xFF));
    if (ptrace(PTRACE_POKETEXT, pid, bp->addr, ptr_origin) == -1)
        return -1;

    remove_breakpoint(bp);

    return 0;
}

int restore_reg(struct wl_list *list, pid_t pid)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        return -1;

    regs.rip -= 1;

    struct breakpoint *bp = get_breakpoint(list, regs.rip);
    if (!bp)
        return 0;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
        return -1;

    long origin = ptrace(PTRACE_PEEKTEXT, pid, bp->addr, NULL);
    if (origin == -1 && errno)
        return -1;

    void *ptr_origin = (void *)((origin & TRAP_MASK) | (bp->origin & 0xFF));
    if (ptrace(PTRACE_POKETEXT, pid, bp->addr, ptr_origin) == -1)
        return -1;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
        return -1;

    int status;
    waitpid(pid, &status, 0);

    if (bp->is_tmp)
    {
        remove_breakpoint(bp);
    }
    else if (ptrace(PTRACE_POKETEXT, pid, bp->addr,
                   ((origin & TRAP_MASK) | TRAP_INST)) == -1)
        return -1;

    return 0;
}

void add_list(struct wl_list *list, struct breakpoint *bp)
{
    struct wl_list new;
    wl_list_init(&new);

    bp->link = new;
    new.next = NULL;
    new.prev = NULL;

    wl_list_insert(list, &bp->link);
}
