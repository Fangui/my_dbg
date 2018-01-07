#include "commands_utils.h"

#include <err.h>
#include <errno.h>
#include <libunwind-ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <unistd.h>

#define BUF_SIZE 4096
void my_cat(const char *path)
{
    FILE *file = fopen(path, "r");
    if (!file)
        return;

    char buf[BUF_SIZE];
    unsigned r;

    while ((r = fread(buf, sizeof(char), BUF_SIZE, file)))
        fwrite(buf, sizeof(char), r, stdout);

    fclose(file);
}

#define MAX_SIZE 16
char *get_proc_system(const char *file, pid_t pid)
{
    const char proc[] = "/proc/";
    char pid_str[MAX_SIZE];
    int len_pid = sprintf(pid_str, "%d", pid);

    if (len_pid < 0)
        return NULL;

    unsigned len_proc = sizeof(proc);
    unsigned len_file  = strlen(file);

    char *path = malloc((len_proc + len_pid + len_file + 1) * sizeof(char));
    if (!file)
        return NULL;

    memcpy(path, proc, len_proc);
    memcpy(path + len_proc - 1, pid_str, len_pid);

    path[len_proc - 1 + len_pid] = '/';
    memcpy(path + len_proc + len_pid, file, len_file + 1);

    return path;
}

unsigned long int get_rip(pid_t pid)
{
     struct user_regs_struct regs;
     if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        return 0;

     return regs.rip;
}

uint8_t *read_process(pid_t pid, long size, long start_addr)
{
    struct iovec local[1];
    struct iovec remote[1];

    uint8_t *buf1 = malloc(size * sizeof(uint8_t));
    if (!buf1)
    {
        warnx("Error while malloc");
        return NULL;;
    }

    local[0].iov_base = buf1;
    local[0].iov_len = size;
    remote[0].iov_base = (void *) start_addr;
    remote[0].iov_len =  size;

    if (process_vm_readv(pid, local, 1, remote, 1, 0) == -1)
    {
        free(buf1);
        return NULL;
    }

    return buf1;
}

uint8_t *read_peektext(pid_t pid, long size, long start_addr)
{
    uint8_t *buf = calloc(size + 1, sizeof(char));
    for (long i = 0; i + 4 < size; i += 4)
    {
        long data = ptrace(PTRACE_PEEKTEXT, pid, start_addr + i, 0);
        if (data == -1 && errno)
        {
            warnx("error while ptrace peektext");
            free(buf);
            return NULL;
        }
        memcpy(buf + i, &data, 4);
    }

    return buf;
}

void examine_print(char format, long size, const uint8_t *buf)
{
    long i = 0;
    unsigned cpt = 1;

    for (; i + 4 < size; i += sizeof(int), ++cpt)
    {
        int dest;
        memcpy(&dest, buf + i, sizeof(int));

        if (format == 'd')
            printf("%10d", dest);
        else if (format == 'x')
            printf("0x%08x", dest);

        if (cpt == 4)
        {
            cpt = 0;
            printf("%s", "\n");
        }
        else
            printf("%s", "\t");
    }
    if (cpt != 1)
        printf("\n");
}

long get_last_addr(pid_t pid)
{
    long res = 0;

    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
    struct UPT_info *ui = _UPT_create(pid);

    if (!as || !ui)
    {
        warn("Error while create addr space");
        goto END;
    }

    unw_cursor_t cursor;
    if (unw_init_remote(&cursor, as, ui))
    {
        warn("Error while init remote");
        goto END;
    }

    if (unw_step(&cursor) > 0)
    {
        unw_word_t pc;
        unw_get_reg(&cursor, UNW_REG_IP, &pc);

        res = pc;
    }

END:
    unw_destroy_addr_space(as);
    _UPT_destroy(ui);
    return res;
}
