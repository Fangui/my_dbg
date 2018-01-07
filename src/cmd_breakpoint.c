#include "breakpoint.h"
#include "commands.h"
#include "commands_utils.h"

#include <err.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

void cmd_breakpoint(const char *arg, pid_t pid, struct wl_list *list)
{
    if (!arg || *arg == '\0')
    {
        fprintf(stderr, "breakpoint need address argument\n");
        return;
    }

    long addr = strtol(arg, NULL, 16);
    call_add_breakpoint(addr, pid, list, !TMP_BREAK);
}
gdb_cmd(break, cmd_breakpoint);

void cmd_tbreakpoint(const char *arg, pid_t pid, struct wl_list *list)
{
    if (!arg || *arg == '\0')
    {
        fprintf(stderr, "tbreak need address in argument\n");
        return;
    }

    long addr = strtol(arg, NULL, 16);
    call_add_breakpoint(addr, pid, list, TMP_BREAK);
}
gdb_cmd(tbreak, cmd_tbreakpoint);

void cmd_break_del(const char *arg, pid_t pid, struct wl_list *list)
{
    if (!arg || *arg == '\0')
    {
        fprintf(stderr, "Need the ID to delete in argument\n");
        return;
    }
    unsigned id = strtol(arg, NULL, 10);

    struct breakpoint *bp = get_breakpoint_id(list, id);
    if (!bp)
    {
        fprintf(stderr, "Cannot remove breakpoint, not match any id\n");
    }
    else if (delete_breakpoint(pid, bp))
    {
        warnx("Error while ptrace when delete breakpoint");
    }
}
gdb_cmd(break_del, cmd_break_del);

#define INIT_SIZE 1024

static char *read_auxv(pid_t pid)
{
    char *buf = NULL;
    char *path = get_proc_system("auxv", pid);
    if (!path)
        return NULL;

    FILE *file = fopen(path, "r");
    unsigned idx = 0;
    unsigned size = INIT_SIZE;

    if (!file)
    {
        warn("Error while open %s when read_auxv", path);
        goto END;
    }

    buf = malloc(INIT_SIZE * sizeof(char));
    if (!buf)
    {
        warn("Error while malloc when read_auxv");
        goto END;
    }

    while (fread(buf + idx, sizeof(char), INIT_SIZE, file))
    {
        size += INIT_SIZE;
        buf = realloc(buf, size * sizeof(char));
        if (!buf)
        {
            warn("Error while realloc when read_auxv");
            goto END;
        }
    }

END:
   free(path);
   fclose(file);
   return buf;
}

static long get_start_header(pid_t pid)
{
    long res = 0;
    char *proc_auxv = read_auxv(pid);
    if (!proc_auxv)
        return 0;

    Elf64_auxv_t *auxv = (Elf64_auxv_t *)proc_auxv;

    for (; auxv->a_type != AT_NULL; ++auxv)
    {
        if( auxv->a_type == AT_PHDR)
        {
            res = auxv->a_un.a_val;
            break;
        }
    }

    free(proc_auxv);
    return res;
}

static Elf64_Addr get_virtual_address(const char *map_start, Elf64_Ehdr *header)
{
    Elf64_Phdr *phdr = (Elf64_Phdr *)(map_start + header->e_phoff);
    Elf64_Addr v_addr = 0;
    for (unsigned i = 0; i < header->e_phnum; ++i, ++phdr)
    {
        if (phdr->p_type == PT_PHDR)
            v_addr = phdr->p_vaddr;
    }

    return v_addr;
}

static int add_bp_symbol(const char *map_start, const char *arg, pid_t pid,
                         struct wl_list *list)
{
    Elf64_Ehdr *header = (Elf64_Ehdr *)map_start;
    Elf64_Shdr *sections = (Elf64_Shdr *)(map_start + header->e_shoff);
    Elf64_Shdr *shdr = sections;

    Elf64_Addr v_addr = get_virtual_address(map_start, header);
    long offset = get_start_header(pid) - v_addr;

    for (unsigned i = 0; i < header->e_shnum; ++i, ++shdr)
    {
        if (shdr->sh_type == SHT_SYMTAB)
        {
            Elf64_Sym *sym = (Elf64_Sym *)(map_start + shdr->sh_offset);
            const char *str_tab = map_start + sections[shdr->sh_link].sh_offset;

            for (unsigned j = 0; j < shdr->sh_size / sizeof(*sym); ++j, ++sym)
            {
                if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC &&
                    !strcmp(str_tab + sym->st_name, arg))
                {
                    call_add_breakpoint(sym->st_value + offset,
                                        pid, list, !TMP_BREAK);
                    return 1;
                }
            }
        }
    }

    return 0;
}

void cmd_breakf(const char *arg, pid_t pid, struct wl_list *list)
{
    if (!arg || *arg == '\0')
    {
        fprintf(stderr, "Missing function name parameter\n");
        return;
    }

    char *path = get_proc_system("exe", pid);
    if (!path)
        return;

    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        warnx("Error while open file %s", path);
        free(path);
        return;
    }

    struct stat stat;
    if (fstat(fd, &stat) == -1)
    {
         warn("Error while fstat when breakf");
         goto END;
    }

    void *map_start = mmap(0, stat.st_size, PROT_READ,
                           MAP_PRIVATE, fd, 0);

    if (map_start == MAP_FAILED)
    {
        warn("Error while mapping %s", path);
        goto END;
    }

    if (!add_bp_symbol(map_start, arg, pid, list))
        fprintf(stderr, "function not found in %s\n", path);
    munmap(map_start, stat.st_size);

END:
    close(fd);
    free(path);
}
gdb_cmd(breakf, cmd_breakf);
