#ifndef DISASSEMBLE_H_
# define DISASSEMBLE_H_

void get_instruction(pid_t pid, long size, long start_addr, long cpt,
                     size_t max_inst);

void cmd_examine(const char *str, pid_t pid, struct wl_list *list);

uintptr_t check_inst_call(pid_t pid, unsigned long int start_addr,
                          unsigned size);

#endif /* !DISASSEMBLE_H_ */
