#include "commands.h"
#include "commands_utils.h"
#include "parser.h"

#include <err.h>
#include <capstone/capstone.h>
#include <wayland-util.h>
#include <string.h>

void get_instruction(pid_t pid, long size, long start_addr, long cpt,
                     size_t inst_per_iter)
{
    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return;

    for (long i = 0; i < cpt; ++i)
    {
        uint8_t *buf = read_process(pid, size, start_addr);

        if (!buf)
        {
            buf = read_peektext(pid, size, start_addr);
            if (!buf)
                break;
        }

        size_t count = cs_disasm(handle, buf, size, start_addr, 0, &insn);
        if (count > 0)
        {
            size_t nb_inst = MIN(count, inst_per_iter);
            for (size_t j = 0; j < nb_inst; ++j)
            {
                printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address,
                        insn[j].mnemonic, insn[j].op_str);

            }
            start_addr = insn[nb_inst - 1].address
                       + insn[nb_inst - 1].size;
            cs_free(insn, count);
            size = SIZE_INST;
        }
        else
        {
            if (size > MAX_SIZE_INST)
            {
                warn("Error while disassemble");
                free(buf);
                break;
            }
            else
                size *= 2;
            --cpt;
        }
        free(buf);
    }

    cs_close(&handle);
}

#define ITER_EXAMINE 1
void cmd_examine(const char *str, pid_t pid, struct wl_list *list)
{
    (void)list;
    char format = 0;
    long size = 0;
    long start_addr = 0;

    if (parse_examine(str, &format, &size, &start_addr))
    {
        fprintf(stderr, "Usage: examine $format size start_addr\n");
        return;
    }

    if (format == 'i')
    {
        get_instruction(pid, size, start_addr, ITER_EXAMINE, size);
        return;
    }

    uint8_t *buf = read_process(pid, size, start_addr);

    if (!buf)
    {
        buf = read_peektext(pid, size, start_addr);
        if (!buf)
            return;
    }

    if (format == 's')
        printf("%s\n", buf);
    else
        examine_print(format, size, buf);

    free(buf);
}
gdb_cmd(examine, cmd_examine);

#define INST_PER_ITER 1
void cmd_disassemble(const char *str, pid_t pid, struct wl_list *list)
{
    (void)list;
    long size = 0;
    long start_addr = 0;

    if (parse_disassemble(str, &size, &start_addr))
    {
        fprintf(stderr, "Usage: disassemble start_addr size\n");
        return;
    }

    get_instruction(pid, SIZE_INST, start_addr, size, INST_PER_ITER);
}
gdb_cmd(disassemble, cmd_disassemble);

uintptr_t check_inst_call(pid_t pid, unsigned long int start_addr,
                          unsigned size)
{
    if (size > MAX_SIZE_INST)
        return 0;

    uintptr_t res = 0;
    uint8_t *buf = read_peektext(pid, size, start_addr);
    if (!buf)
        return 0;

    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return 0;

    size_t count = cs_disasm(handle, buf, size, start_addr, 0, &insn);
    if (count > 1)
    {
        if (!strncmp("call", insn[0].mnemonic, 4))
        {
            res = insn[1].address;
        }
        cs_free(insn, count);
    }
    else if (count == 0)
        warn("Error while disassemble");

    cs_close(&handle);
    free(buf);

    if (count == 1)
    {
        cs_free(insn, count);
        return check_inst_call(pid, start_addr, size * 2);
    }

    return res;
}
