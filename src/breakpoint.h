#ifndef BREAKPOINT_H_
# define BREAKPOINT_H_

# include <sys/types.h>
# include <wayland-util.h>

# define TRAP_INST   0xCC
# define TRAP_MASK   ~0xFF
# define TMP_BREAK   1

struct breakpoint
{
    void           *addr;
    long           origin;
    char           is_tmp;
    unsigned       id;

    struct wl_list link;
};

struct breakpoint *add_breakpoint(pid_t pid, void *addr, char is_tmp,
                                  unsigned id);

int set_breakpoint(struct breakpoint *bp, pid_t pid);

struct breakpoint *get_breakpoint(struct wl_list *list, uintptr_t addr);

struct breakpoint *get_breakpoint_id(struct wl_list *list, unsigned id);

int restore_reg(struct wl_list *list, pid_t pid);

int delete_breakpoint(pid_t pid, struct breakpoint *bp);

void add_list(struct wl_list *list, struct breakpoint *bp);

void call_add_breakpoint(long addr, pid_t pid,
                         struct wl_list *list, char is_tmp);

#endif /* !BREAKPOINT_H_ */
