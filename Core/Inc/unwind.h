#ifndef UNWIND_H
#define UNWIND_H

#include <stdint.h>
#include <stdio.h>

enum unwind_reason_code {
	URC_OK = 0,			/* operation completed successfully */
	URC_CONTINUE_UNWIND = 8,
	URC_FAILURE = 9			/* unspecified failure of some kind */
};

struct unwind_ctrl_block {
	uint32_t vrs[16];		/* virtual register set */
	const uint32_t *insn;	/* pointer to the current instructions word */
	uint32_t sp_high;		/* highest value of sp allowed */
	uint32_t *lr_addr;		/* address of LR value on the stack */
	/*
	 * 1 : check for stack overflow for each register pop.
	 * 0 : save overhead if there is plenty of stack remaining.
	 */
	int check_each_pop;
	int entries;			/* number of entries left to interpret */
	int byte;			/* current byte number in the instructions word */
};

enum regs {
	SP = 13,
	LR = 14,
	PC = 15
};

struct unwind_idx {
	uint32_t addr_offset;
	uint32_t insn;
};

struct stack_frame {
	/*
	 * FP member should hold R7 when CONFIG_THUMB2_KERNEL is enabled
	 * and R11 otherwise.
	 */
	uint32_t sp;
	uint32_t lr;
	uint32_t pc;

	/* address of the LR value on the stack */
	uint32_t *lr_addr;
};

void unwind_backtrace(void);
void show_unwind_info(void);

#endif //UNWIND_H
