#include "unwind.h"


extern unsigned int Image$$ER_EXIDX$$Base;
extern unsigned int Image$$ER_EXIDX$$Length;
extern unsigned int Image$$ER_EXIDX$$Limit;

const struct unwind_idx *__start_unwind_idx = (struct unwind_idx *)&Image$$ER_EXIDX$$Base;
const struct unwind_idx *__stop_unwind_idx = (struct unwind_idx *)&Image$$ER_EXIDX$$Limit;
static const struct unwind_idx *__origin_unwind_idx = NULL;

#define prel31_to_addr(ptr)				\
({							\
	/* sign-extend to 32 bits */			\
	long offset = (((long)*(ptr)) << 1) >> 1;	\
	(uint32_t)(ptr) + offset;			\
})

/**
 *
 */
uint32_t decode_prel31(uint32_t prel31_value, uint32_t current_address) 
{
    int32_t signed_offset = (int32_t)(prel31_value << 1) >> 1;
    return current_address + signed_offset;
}


static const struct unwind_idx *unwind_find_origin(
		const struct unwind_idx *start, const struct unwind_idx *stop)
{
	while (start < stop) {
		const struct unwind_idx *mid = start + ((stop - start) >> 1);

		if (mid->addr_offset >= 0x40000000)
			/* negative offset */
			start = mid + 1;
		else
			/* positive offset */
			stop = mid;
	}
	return stop;
}

static const struct unwind_idx *search_index(uint32_t addr,
				       const struct unwind_idx *start,
				       const struct unwind_idx *origin,
				       const struct unwind_idx *stop)
{
	uint32_t addr_prel31;


	/*
	 * only search in the section with the matching sign. This way the
	 * prel31 numbers can be compared as uint32_ts.
	 */
	if (addr < (uint32_t)start)
		/* negative offsets: [start; origin) */
		stop = origin;
	else
		/* positive offsets: [origin; stop) */
		start = origin;

	/* prel31 for address relavive to start */
	addr_prel31 = (addr - (uint32_t)start) & 0x7fffffff;

	while (start < stop - 1) {
		const struct unwind_idx *mid = start + ((stop - start) >> 1);

		/*
		 * As addr_prel31 is relative to start an offset is needed to
		 * make it relative to mid.
		 */
		if (addr_prel31 - ((uint32_t)mid - (uint32_t)start) <
				mid->addr_offset)
			stop = mid;
		else {
			/* keep addr_prel31 relative to start */
			addr_prel31 -= ((uint32_t)mid -
					(uint32_t)start);
			start = mid;
		}
	}

	if (start->addr_offset <= addr_prel31)
		return start;
	else {
		return NULL;
	}
}

/**
 * Binary search in the unwind index.
 */
static const struct unwind_idx *unwind_find_idx(uint32_t addr)
{
	const struct unwind_idx *idx;

	if (__origin_unwind_idx == NULL)	
	{
		__origin_unwind_idx = unwind_find_origin(__start_unwind_idx,
												 __stop_unwind_idx);
	}
	
	idx = search_index(addr, __start_unwind_idx,
			   __origin_unwind_idx,
			   __stop_unwind_idx);
	return idx;
}

static uint32_t unwind_get_byte(struct unwind_ctrl_block *ctrl)
{
	uint32_t ret;

	if (ctrl->entries <= 0) {
		printf("unwind: Corrupt unwind table\n");
		return 0;
	}

	ret = (*ctrl->insn >> (ctrl->byte * 8)) & 0xff;

	if (ctrl->byte == 0) {
		ctrl->insn++;
		ctrl->entries--;
		ctrl->byte = 3;
	} else
		ctrl->byte--;

	return ret;
}

/* Before poping a register check whether it is feasible or not */
static int unwind_pop_register(struct unwind_ctrl_block *ctrl,
				uint32_t **vsp, uint32_t reg)
{
	if (ctrl->check_each_pop)
		if (*vsp >= (uint32_t *)ctrl->sp_high)
			return -URC_FAILURE;

	/* Use READ_ONCE_NOCHECK here to avoid this memory access
	 * from being tracked by KASAN.
	 */
	ctrl->vrs[reg] = *(*vsp);
	if (reg == 14)
		ctrl->lr_addr = *vsp;
	(*vsp)++;
	return URC_OK;
}

/* Helper functions to execute the instructions */
static int unwind_exec_pop_subset_r4_to_r13(struct unwind_ctrl_block *ctrl,
						uint32_t mask)
{
	uint32_t *vsp = (uint32_t *)ctrl->vrs[SP];
	int load_sp, reg = 4;

	load_sp = mask & (1 << (13 - 4));
	while (mask) {
		if (mask & 1)
			if (unwind_pop_register(ctrl, &vsp, reg))
				return -URC_FAILURE;
		mask >>= 1;
		reg++;
	}
	if (!load_sp) {
		ctrl->vrs[SP] = (uint32_t)vsp;
	}

	return URC_OK;
}

static int unwind_exec_pop_r4_to_rN(struct unwind_ctrl_block *ctrl,
					uint32_t insn)
{
	uint32_t *vsp = (uint32_t *)ctrl->vrs[SP];
	int reg;

	/* pop R4-R[4+bbb] */
	for (reg = 4; reg <= 4 + (insn & 7); reg++)
		if (unwind_pop_register(ctrl, &vsp, reg))
				return -URC_FAILURE;

	if (insn & 0x8)
		if (unwind_pop_register(ctrl, &vsp, 14))
				return -URC_FAILURE;

	ctrl->vrs[SP] = (uint32_t)vsp;

	return URC_OK;
}

static int unwind_exec_pop_subset_r0_to_r3(struct unwind_ctrl_block *ctrl,
						uint32_t mask)
{
	uint32_t *vsp = (uint32_t *)ctrl->vrs[SP];
	int reg = 0;

	/* pop R0-R3 according to mask */
	while (mask) {
		if (mask & 1)
			if (unwind_pop_register(ctrl, &vsp, reg))
				return -URC_FAILURE;
		mask >>= 1;
		reg++;
	}
	ctrl->vrs[SP] = (uint32_t)vsp;

	return URC_OK;
}

static uint32_t unwind_decode_uleb128(struct unwind_ctrl_block *ctrl)
{
	uint32_t bytes = 0;
	uint32_t insn;
	uint32_t result = 0;

	/*
	 * unwind_get_byte() will advance `ctrl` one instruction at a time, so
	 * loop until we get an instruction byte where bit 7 is not set.
	 *
	 * Note: This decodes a maximum of 4 bytes to output 28 bits data where
	 * max is 0xfffffff: that will cover a vsp increment of 1073742336, hence
	 * it is sufficient for unwinding the stack.
	 */
	do {
		insn = unwind_get_byte(ctrl);
		result |= (insn & 0x7f) << (bytes * 7);
		bytes++;
	} while (!!(insn & 0x80) && (bytes != sizeof(result)));

	return result;
}

/*
 * Execute the current unwind instruction.
 */
static int unwind_exec_insn(struct unwind_ctrl_block *ctrl)
{
	uint32_t insn = unwind_get_byte(ctrl);
	int ret = URC_OK;

	printf("%s: insn = %08lx\n", __func__, insn);

	if ((insn & 0xc0) == 0x00)
		ctrl->vrs[SP] += ((insn & 0x3f) << 2) + 4;
	else if ((insn & 0xc0) == 0x40) {
		ctrl->vrs[SP] -= ((insn & 0x3f) << 2) + 4;
	} else if ((insn & 0xf0) == 0x80) {
		uint32_t mask;

		insn = (insn << 8) | unwind_get_byte(ctrl);
		mask = insn & 0x0fff;
		if (mask == 0) {
			printf("unwind: 'Refuse to unwind' instruction %04lx\n",
				insn);
			return -URC_FAILURE;
		}

		ret = unwind_exec_pop_subset_r4_to_r13(ctrl, mask);
		if (ret)
			goto error;
	} else if ((insn & 0xf0) == 0x90 &&
		   (insn & 0x0d) != 0x0d) {
		ctrl->vrs[SP] = ctrl->vrs[insn & 0x0f];
	} else if ((insn & 0xf0) == 0xa0) {
		ret = unwind_exec_pop_r4_to_rN(ctrl, insn);
		if (ret)
			goto error;
	} else if (insn == 0xb0) {
		if (ctrl->vrs[PC] == 0)
			ctrl->vrs[PC] = ctrl->vrs[LR];
		/* no further processing */
		ctrl->entries = 0;
	} else if (insn == 0xb1) {
		uint32_t mask = unwind_get_byte(ctrl);

		if (mask == 0 || mask & 0xf0) {
			printf("unwind: Spare encoding %04lx\n",
				(insn << 8) | mask);
			return -URC_FAILURE;
		}

		ret = unwind_exec_pop_subset_r0_to_r3(ctrl, mask);
		if (ret)
			goto error;
	} else if (insn == 0xb2) {
		uint32_t uleb128 = unwind_decode_uleb128(ctrl);

		ctrl->vrs[SP] += 0x204 + (uleb128 << 2);
	} else {
		printf("unwind: Unhandled instruction %02lx\n", insn);
		return -URC_FAILURE;
	}

	printf("%s: sp = %08lx lr = %08lx pc = %08lx\n", __func__,
		  ctrl->vrs[SP], ctrl->vrs[LR], ctrl->vrs[PC]);

error:
	return ret;
}

int unwind_frame(struct stack_frame *frame)
{
	const struct unwind_idx *idx;
	struct unwind_ctrl_block ctrl;
	uint32_t sp_low;
    uint32_t pc = 0;
	printf("\n");
	/* store the highest address on the stack to avoid crossing it*/
	sp_low = frame->sp;
//	ctrl.sp_high = ALIGN(sp_low - THREAD_SIZE, THREAD_ALIGN)
//		       + THREAD_SIZE;

	idx = unwind_find_idx(frame->pc);
	pc = decode_prel31(idx->addr_offset, (uint32_t)&idx->addr_offset);
	printf("idx->addr_offset=0x%x, pc=0x%x, idx->ins=0x%x\n", 
		idx->addr_offset, 
		pc, 
		idx->insn);
	ctrl.vrs[SP] = frame->sp;
	ctrl.vrs[LR] = frame->lr;
	ctrl.vrs[PC] = 0;

	if (idx->insn == 1)
		/* can't unwind */
		return -URC_FAILURE;
	else if (frame->pc == prel31_to_addr(&idx->addr_offset)) {
		/*
		 * Unwinding is tricky when we're halfway through the prologue,
		 * since the stack frame that the unwinder expects may not be
		 * fully set up yet. However, one thing we do know for sure is
		 * that if we are unwinding from the very first instruction of
		 * a function, we are still effectively in the stack frame of
		 * the caller, and the unwind info has no relevance yet.
		 */
		if (frame->pc == frame->lr)
			return -URC_FAILURE;
		frame->pc = frame->lr;
		return URC_OK;
	} else if ((idx->insn & 0x80000000) == 0)
		/* prel31 to the unwind table */
		ctrl.insn = (uint32_t *)prel31_to_addr(&idx->insn);
	else if ((idx->insn & 0xff000000) == 0x80000000)
		/* only personality routine 0 supported in the index */
		ctrl.insn = &idx->insn;
	else {
		printf("unwind: Unsupported personality routine %08lx in the index at %p\n",
			idx->insn, idx);
		return -URC_FAILURE;
	}

	/* check the personality routine */
	if ((*ctrl.insn & 0xff000000) == 0x80000000) {
		ctrl.byte = 2;
		ctrl.entries = 1;
	} else if ((*ctrl.insn & 0xff000000) == 0x81000000) {
		ctrl.byte = 1;
		ctrl.entries = 1 + ((*ctrl.insn & 0x00ff0000) >> 16);
	} else {
		printf("unwind: Unsupported personality routine %08lx at %p\n",
			*ctrl.insn, ctrl.insn);
		return -URC_FAILURE;
	}

	ctrl.check_each_pop = 0;

	while (ctrl.entries > 0) {
		int urc;
		// if ((ctrl.sp_high - ctrl.vrs[SP]) < sizeof(ctrl.vrs))
		// 	ctrl.check_each_pop = 1;
		urc = unwind_exec_insn(&ctrl);
		if (urc < 0)
			return urc;
		// if (ctrl.vrs[SP] < sp_low || ctrl.vrs[SP] > ctrl.sp_high)
		// 	return -URC_FAILURE;
	}

	if (ctrl.vrs[PC] == 0)
		ctrl.vrs[PC] = ctrl.vrs[LR];

	/* check for infinite loop */
	if (frame->pc == ctrl.vrs[PC] && frame->sp == ctrl.vrs[SP])
		return -URC_FAILURE;

	frame->sp = ctrl.vrs[SP];
	frame->lr = ctrl.vrs[LR];
	frame->pc = ctrl.vrs[PC];
	frame->lr_addr = ctrl.lr_addr;
	printf("\n");
	return URC_OK;
}

void unwind_backtrace()
{
	struct stack_frame frame = {0};
	
	frame.pc = __current_pc();
	frame.lr = __return_address();
	frame.sp = __current_sp();
	
	while (1) {
		int urc;
		uint32_t where = frame.pc;

		urc = unwind_frame(&frame);
		if (urc < 0)
			break;

		printf("call 0x%p from 0x%p\n", (void *)(where - 1), (void *)(frame.pc - 1));
	}
	
}

void unwind_shown_info()
{
	uint32_t base_addr = (uint32_t)(&Image$$ER_EXIDX$$Base);
	uint32_t length = (uint32_t)(&Image$$ER_EXIDX$$Length);
	uint32_t end_addr = (uint32_t)(&Image$$ER_EXIDX$$Limit);
	uint32_t entry_num = length/8;
	printf("base_addr=0x%x, length=0x%x, end_addr=0x%x\n", base_addr, length, end_addr);
	printf("entry num=%d\n", entry_num);

	const struct unwind_idx *idx;
	for (int i = 0; i < entry_num; i++)
	{
		uint32_t pc = 0;
		idx = (struct unwind_idx *)base_addr;
		pc = decode_prel31(idx->addr_offset, (uint32_t)&idx->addr_offset);
		printf("idx->addr_offset=0x%x, pc=0x%x, idx->ins=0x%x\n", 
				idx->addr_offset, 
				pc, 
				idx->insn);
		base_addr += 8;
	}	
}
