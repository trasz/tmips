#include <sys/param.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <unistd.h>

#define	STACK_PAGES	3
#define	TRACE
#define	DIE_ON_UNKNOWN

#define	nitems(x)	(sizeof((x)) / sizeof((x)[0]))

#ifdef TRACE
#define	TRACE_OPCODE(STR)	do {								\
		fprintf(stderr, "\n%12llx:\t%08x\t%-7s ",					\
		    (unsigned long long)pc, instruction, STR);					\
	} while (0)

#define	TRACE_REG(REG)	do {									\
		if (register_name(REG) != NULL)							\
			fprintf(stderr, "%s,", register_name(REG));				\
		else										\
			fprintf(stderr, "$%d,", REG);						\
	} while (0)

#define	TRACE_RD()	TRACE_REG(rd)
#define	TRACE_RS()	TRACE_REG(rs)
#define	TRACE_RT()	TRACE_REG(rt)

#define	TRACE_RESULT_REG(REG)	do {								\
		if (register_name(REG) != NULL)							\
			fprintf(stderr, "   \t# %s := %#018lx (%ld)", register_name(REG), reg[REG], reg[REG]);	\
		else										\
			fprintf(stderr, "   \t# $%d := %#018lx (%ld)", REG, reg[REG], reg[REG]);\
	} while (0)

#define	TRACE_RESULT_RD()	TRACE_RESULT_REG(rd)
#define	TRACE_RESULT_RS()	TRACE_RESULT_REG(rs)
#define	TRACE_RESULT_RT()	TRACE_RESULT_REG(rt)

#define	TRACE_IMM_REG(REG)	do {								\
		if (register_name(REG) != NULL)							\
			fprintf(stderr, "%d(%s)", immediate, register_name(REG));		\
		else										\
			fprintf(stderr, "%d($%d)", immediate, REG);				\
	} while (0)

#define	TRACE_IMM_RS()	TRACE_IMM_REG(rs)

#define	TRACE_IMM()	do {									\
		fprintf(stderr, "%d", immediate);						\
	} while (0)

#define	TRACE_SA()	do {									\
		fprintf(stderr, "%d", sa);							\
	} while (0)

#define	TRACE_JUMP()	do {									\
		fprintf(stderr, "%x", jump);							\
	} while (0)

#define	TRACE_STR(STR)	fprintf(stderr, "   \t# %s", STR)

static const char *register_names[32] = {
	"$0",   "at",   "v0",   "v1",   "a0",   "a1",   "a2",   "a3",
	"a4",   "a5",   "a6",   "a7",   "t0",   "t1",   "t2",   "t3",
	"s0",   "s1",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
	"t8",   "t9",   "k0",   "k1",   "gp",   "sp",   "s8",   "ra"
};

static const char *
register_name(int i)
{

	if (i < 0 || (unsigned long)i >= nitems(register_names))
		return (NULL);
	return (register_names[i]);
}

#else /* !TRACE */
#define TRACE_OPCODE(X)
#define TRACE_RD()
#define TRACE_RS()
#define TRACE_RT()
#define TRACE_IMM_REG(X)
#define TRACE_IMM_RS()
#define TRACE_IMM()
#define TRACE_JUMP()
#endif /* !TRACE */

/*
 * See the Green Sheet, http://www-inst.eecs.berkeley.edu/~cs61c/resources/MIPS_Green_Sheet.pdf
 */
#define	OPCODE_SPECIAL	0x00

#define	FUNCT_SPECIAL_SLL	0x00
#define	FUNCT_SPECIAL_SRL	0x02
#define	FUNCT_SPECIAL_SRA	0x03

#define	FUNCT_SPECIAL_SLLV	0x04
#define	FUNCT_SPECIAL_SRLV	0x06
#define	FUNCT_SPECIAL_SRAV	0x07

#define	FUNCT_SPECIAL_JR	0x08
#define	FUNCT_SPECIAL_JALR	0x09
#define	FUNCT_SPECIAL_MOVZ	0x0a
#define	FUNCT_SPECIAL_MOVN	0x0b

#define	FUNCT_SPECIAL_SYSCALL	0x0c
#define	FUNCT_SPECIAL_BREAK	0x0d
#define	FUNCT_SPECIAL_SYNC	0x0f

#define	FUNCT_SPECIAL_MFHI	0x10
#define	FUNCT_SPECIAL_MTHI	0x11
#define	FUNCT_SPECIAL_MFLO	0x12
#define	FUNCT_SPECIAL_MTLO	0x13

#define	FUNCT_SPECIAL_DSLLV	0x14
#define	FUNCT_SPECIAL_DSRLV	0x16
#define	FUNCT_SPECIAL_DSRAV	0x17

#define	FUNCT_SPECIAL_MULT	0x18
#define	FUNCT_SPECIAL_MULTU	0x19
#define	FUNCT_SPECIAL_DIV	0x1a
#define	FUNCT_SPECIAL_DIVU	0x1b

#define	FUNCT_SPECIAL_DMULT	0x1c
#define	FUNCT_SPECIAL_DMULTU	0x1d
#define	FUNCT_SPECIAL_DDIV	0x1e
#define	FUNCT_SPECIAL_DDIVU	0x1f

#define	FUNCT_SPECIAL_ADD	0x20
#define	FUNCT_SPECIAL_ADDU	0x21
#define	FUNCT_SPECIAL_SUB	0x22
#define	FUNCT_SPECIAL_SUBU	0x23

#define	FUNCT_SPECIAL_AND	0x24
#define	FUNCT_SPECIAL_OR	0x25
#define	FUNCT_SPECIAL_XOR	0x26
#define	FUNCT_SPECIAL_NOR	0x27

#define	FUNCT_SPECIAL_SLT	0x2a
#define	FUNCT_SPECIAL_SLTU	0x2b
#define	FUNCT_SPECIAL_DADD	0x2c
#define	FUNCT_SPECIAL_DADDU	0x2d

#define	FUNCT_SPECIAL_DSUB	0x2e
#define	FUNCT_SPECIAL_DSUBU	0x2f

#define	FUNCT_SPECIAL_TGE	0x30
#define	FUNCT_SPECIAL_TGEU	0x31
#define	FUNCT_SPECIAL_TLT	0x32
#define	FUNCT_SPECIAL_TLTU	0x33

#define	FUNCT_SPECIAL_TEQ	0x34

#define	FUNCT_SPECIAL_TNE	0x36
#define	FUNCT_SPECIAL_DSLL	0x38
#define	FUNCT_SPECIAL_DSRL	0x3a
#define	FUNCT_SPECIAL_DSRA	0x3b
#define	FUNCT_SPECIAL_DSLL32	0x3c
#define	FUNCT_SPECIAL_DSRL32	0x3e
#define	FUNCT_SPECIAL_DSRA32	0x3f

#define	OPCODE_REGIMM	0x01

#define	FUNCT_REGIMM_BLTZ	0x00
#define	FUNCT_REGIMM_BAL	0x11

#define	OPCODE_J	0x02
#define	OPCODE_JAL	0x03

#define	OPCODE_BEQ	0x04
#define	OPCODE_BNE	0x05
#define	OPCODE_BLEZ	0x06
#define	OPCODE_BGTZ	0x07

#define	OPCODE_ADDI	0x08
#define	OPCODE_ADDIU	0x09
#define	OPCODE_SLTI	0x0a
#define	OPCODE_SLTIU	0x0b

#define	OPCODE_ANDI	0x0c
#define	OPCODE_ORI	0x0d
#define	OPCODE_XORI	0x0e
#define	OPCODE_LUI	0x0f

#define	OPCODE_BEQL	0x14
#define	OPCODE_BNEL	0x15
#define	OPCODE_DADDIU	0x19

#define	OPCODE_LB	0x20
#define	OPCODE_LH	0x21
#define	OPCODE_LWL	0x22
#define	OPCODE_LW	0x23

#define	OPCODE_LBU	0x24
#define	OPCODE_LHU	0x25
#define	OPCODE_LWR	0x26

#define	OPCODE_SB	0x28
#define	OPCODE_SH	0x29
#define	OPCODE_SWL	0x2a
#define	OPCODE_SW	0x2b

#define	OPCODE_SWR	0x2e
#define	OPCODE_CACHE	0x2f

#define	OPCODE_LL	0x30
#define	OPCODE_LWC1	0x31
#define	OPCODE_LWC2	0x32
#define	OPCODE_PREF	0x33

#define	OPCODE_LDC1	0x35
#define	OPCODE_LDC2	0x36
#define	OPCODE_LD	0x37

#define	OPCODE_SC	0x38
#define	OPCODE_SWC1	0x39
#define	OPCODE_SWC2	0x3a

#define	OPCODE_SDC1	0x3d
#define	OPCODE_SDC2	0x3e
#define	OPCODE_SD	0x3f

static int64_t
initial_stack_pointer(void)
{
	char foo[STACK_PAGES * 4096];
	int64_t bar;

	foo[0] = 42;
	bar = 42;
	return ((int64_t)&bar);
}

static int
run(int *pc)
{
	// CPU context.
	int64_t reg[32];

	// Temporaries.
	uint32_t rs, rt, rd, sa, instruction, jump, opcode, funct;
	uint16_t uimmediate;
	int16_t immediate;
	int *next_pc;

	memset(reg, 0, sizeof(reg));
	reg[0] = 0;
	reg[4] = initial_stack_pointer();
	reg[25] = (int64_t)pc;
	reg[29] = reg[4];

	next_pc = pc + 1;

	for (;;) {
		//fprintf(stderr, "\npc %p, next %p", pc, next_pc);
		instruction = be32toh(*pc);

		opcode = (instruction & (0x3F << 26)) >> 26;

		rs = (instruction & (0x1F << 21)) >> 21;
		rt = (instruction & (0x1F << 16)) >> 16;
		rd = (instruction & (0x1F << 11)) >> 11;
		sa = (instruction & (0x1F << 6)) >> 6;

		immediate = (instruction << 16) >> 16;
		uimmediate = (immediate << 16) >> 16;

		jump = instruction & 0x3FFFFFF;

		switch (opcode) {
		case OPCODE_SPECIAL:
			funct = instruction & 0x3F;

			switch (funct) {
			case FUNCT_SPECIAL_SLL:
				TRACE_OPCODE("sll");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = (int32_t)reg[rt] << sa;
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_SRL:
				TRACE_OPCODE("srl");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = (uint32_t)reg[rt] >> sa;
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_SRA:
				TRACE_OPCODE("sra");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = reg[rt] >> sa;
				TRACE_RESULT_RD();
				break;
#if 0
			case FUNCT_SPECIAL_SLLV:
				TRACE_OPCODE("sllv");
				TRACE_RD();
				TRACE_RT();
				break;
#endif
			case FUNCT_SPECIAL_SRLV:
				TRACE_OPCODE("srlv");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				reg[rd] = reg[rt] > reg[rs];
				TRACE_RESULT_RD();
				break;
#if 0
			case FUNCT_SPECIAL_SRAV:
				TRACE_OPCODE("srav");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				break;
#endif
			case FUNCT_SPECIAL_JR:
				TRACE_OPCODE("jr");
				TRACE_RS();
				pc++;
				next_pc = (int *)reg[rs];
				continue;
			case FUNCT_SPECIAL_JALR:
				TRACE_OPCODE("jalr");
				TRACE_RD();
				TRACE_RS();
				reg[rd] = (int64_t)(next_pc + 1);
				TRACE_RESULT_RD();
				pc++;
				next_pc = (int *)reg[rs];
				continue;
#if 0
			case FUNCT_SPECIAL_MOVZ:
				TRACE_OPCODE("movz");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_MOVN:
				TRACE_OPCODE("movn");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
#endif
			case FUNCT_SPECIAL_SYSCALL:
				TRACE_OPCODE("syscall");
				fprintf(stderr, "(%ld, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx)",
				    reg[2], reg[4], reg[5], reg[6], reg[7], reg[8], reg[9]);
				reg[7] = __syscall(reg[2], reg[4], reg[5], reg[6], reg[7], reg[8], reg[9]);
				if (reg[7] != 0)
					reg[2] = errno;
				fprintf(stderr, " = %ld; errno %d", reg[7], errno);
				break;
#if 0
			case FUNCT_SPECIAL_BREAK:
				TRACE_OPCODE("break");
				break;
#endif
			case FUNCT_SPECIAL_SYNC:
				TRACE_OPCODE("sync");
				break;
#if 0
			case FUNCT_SPECIAL_MFHI:
				TRACE_OPCODE("mfhi");
				TRACE_RD();
				break;
			case FUNCT_SPECIAL_MTHI:
				TRACE_OPCODE("mthi");
				TRACE_RS();
				break;
			case FUNCT_SPECIAL_MFLO:
				TRACE_OPCODE("mflo");
				TRACE_RD();
				break;
			case FUNCT_SPECIAL_MTLO:
				TRACE_OPCODE("mtlo");
				TRACE_RS();
				break;
#endif
			case FUNCT_SPECIAL_DSLLV:
				TRACE_OPCODE("dsllv");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				reg[rd] = reg[rt] << reg[rs];
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSRLV:
				TRACE_OPCODE("dsrlv");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				reg[rd] = (uint64_t)reg[rt] >> reg[rs];
				TRACE_RESULT_RD();
				break;
#if 0
			case FUNCT_SPECIAL_DSRAV:
				TRACE_OPCODE("dsrav");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				break;
			case FUNCT_SPECIAL_MULT:
				TRACE_OPCODE("mult");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_MULTU:
				TRACE_OPCODE("multu");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_DIV:
				TRACE_OPCODE("div");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_DIVU:
				TRACE_OPCODE("divu");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_DMULT:
				TRACE_OPCODE("dmult");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_DMULTU:
				TRACE_OPCODE("dmultu");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_DDIV:
				TRACE_OPCODE("ddiv");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_DDIVU:
				TRACE_OPCODE("ddivu");
				TRACE_RS();
				TRACE_RT();
				break;
#endif
			case FUNCT_SPECIAL_ADD:
				TRACE_OPCODE("add");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] + reg[rt];
				break;
			case FUNCT_SPECIAL_ADDU:
				TRACE_OPCODE("addu");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] + reg[rt];
				TRACE_RESULT_RD();
				break;
#if 0
			case FUNCT_SPECIAL_SUB:
				TRACE_OPCODE("sub");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
#endif
			case FUNCT_SPECIAL_SUBU:
				TRACE_OPCODE("subu");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = (uint32_t)reg[rs] - (uint32_t)reg[rt];
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_AND:
				TRACE_OPCODE("and");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] & reg[rt];
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_OR:
				TRACE_OPCODE("or");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] | reg[rt];
				TRACE_RESULT_RD();
				break;
#if 0
			case FUNCT_SPECIAL_XOR:
				TRACE_OPCODE("xor");
				break;
#endif
			case FUNCT_SPECIAL_NOR:
				TRACE_OPCODE("nor");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = ~(reg[rs] | reg[rt]);
				TRACE_RESULT_RD();
				break;
#if 0
			case FUNCT_SPECIAL_SLT:
				TRACE_OPCODE("slt");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
#endif
			case FUNCT_SPECIAL_SLTU:
				TRACE_OPCODE("sltu");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				if ((uint64_t)reg[rs] < (uint64_t)reg[rt])
					reg[rd] = 1;
				else
					reg[rd] = 0;
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DADD:
				TRACE_OPCODE("dadd");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] + reg[rt];
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DADDU:
				TRACE_OPCODE("daddu");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] + reg[rt];
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSUB:
				TRACE_OPCODE("dsub");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] - reg[rt];
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSUBU:
				TRACE_OPCODE("dsubu");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] - reg[rt];
				TRACE_RESULT_RD();
				break;
#if 0
			case FUNCT_SPECIAL_TGE:
				TRACE_OPCODE("tge");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_TGEU:
				TRACE_OPCODE("tgeu");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_TLT:
				TRACE_OPCODE("tlt");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_TLTU:
				TRACE_OPCODE("tltu");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_TEQ:
				TRACE_OPCODE("teq");
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_TNE:
				TRACE_OPCODE("tne");
				TRACE_RS();
				TRACE_RT();
				break;
#endif
			case FUNCT_SPECIAL_DSLL:
				TRACE_OPCODE("dsll");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = reg[rt] << sa;
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSRL:
				TRACE_OPCODE("dsrl");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = (uint64_t)reg[rt] >> sa;
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSRA:
				TRACE_OPCODE("dsra");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = reg[rt] >> sa;
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSLL32:
				TRACE_OPCODE("dsll32");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = reg[rt] << (sa + 32);
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSRL32:
				TRACE_OPCODE("dsrl32");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = reg[rt] >> (sa + 32);
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSRA32:
				TRACE_OPCODE("dsra32");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = reg[rt] >> (32 + sa);
				TRACE_RESULT_RD();
				break;
			default:
#ifdef DIE_ON_UNKNOWN
				fprintf(stderr, "\n");
				errx(1, "unknown special opcode %#x, function %#x at address %p", opcode, funct, (void *)pc);
#else
				TRACE_OPCODE("SPECIAL");
				fprintf(stderr, "(opcode %#x, function %#x)", opcode, funct);
#endif
				break;
			}
			break;

		case OPCODE_REGIMM:
			funct = (instruction & (0x1F << 16)) >> 16;

			switch (funct) {
			case FUNCT_REGIMM_BLTZ:
				TRACE_OPCODE("bltz");
				TRACE_RS();
				TRACE_IMM();
				if (reg[rs] < 0) {
					pc++;
					// We're not shifting left by two, because pc is already an (int *).
					next_pc = next_pc + immediate;
					continue;
				}
				break;
			case FUNCT_REGIMM_BAL:
				TRACE_OPCODE("bal");
				TRACE_IMM();
				reg[31] = (int64_t)(next_pc + 1);
				TRACE_RESULT_REG(31);
				pc++;
				// We're not shifting left by two, because pc is already an (int *).
				next_pc = next_pc + immediate;
				break;
			default:
#ifdef DIE_ON_UNKNOWN
				fprintf(stderr, "\n");
				errx(1, "unknown regimm opcode %#x, function %#x at address %p", opcode, funct, (void *)pc);
#else
				TRACE_OPCODE("REGIMM");
				fprintf(stderr, "(opcode %#x, function %#x)", opcode, funct);
#endif
				break;
			}
			break;

#if 0
		case OPCODE_J:
			TRACE_OPCODE("j");
			TRACE_JUMP();
			break;
		case OPCODE_JAL:
			TRACE_OPCODE("jal");
			TRACE_RS();
			break;
#endif
		case OPCODE_BEQ:
			TRACE_OPCODE("beq");
			TRACE_RS();
			TRACE_RT();
			TRACE_IMM();
			if (reg[rs] == reg[rt]) {
				pc++;
				// We're not shifting left by two, because pc is already an (int *).
				next_pc = next_pc + immediate;
				TRACE_STR("taken");
				continue;
			}
			TRACE_STR("not taken");
			break;
		case OPCODE_BNE:
			TRACE_OPCODE("bne");
			TRACE_RS();
			TRACE_RT();
			TRACE_IMM();
			if (reg[rs] != reg[rt]) {
				pc++;
				// We're not shifting left by two, because pc is already an (int *).
				next_pc = next_pc + immediate;
				TRACE_STR("taken");
				continue;
			}
			TRACE_STR("not taken");
			break;
		case OPCODE_BLEZ:
			TRACE_OPCODE("blez");
			TRACE_RS();
			TRACE_IMM();
			if (reg[rs] <= 0) {
				pc++;
				// We're not shifting left by two, because pc is already an (int *).
				next_pc = next_pc + immediate;
				TRACE_STR("taken");
				continue;
			}
			TRACE_STR("not taken");
			break;
#if 0
		case OPCODE_BGTZ:
			TRACE_OPCODE("bgtz");
			TRACE_RS();
			break;
#endif
		case OPCODE_ADDI:
			TRACE_OPCODE("addi");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			reg[rt] = reg[rs] + immediate;
			break;
		case OPCODE_ADDIU:
			TRACE_OPCODE("addiu");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			reg[rt] = (int64_t)((int32_t)reg[rs]) + immediate;
			TRACE_RESULT_RT();
			break;
#if 0
		case OPCODE_SLTI:
			TRACE_OPCODE("slti");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			break;
#endif
		case OPCODE_SLTIU:
			TRACE_OPCODE("sltiu");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			if (reg[rs] < immediate)
				reg[rt] = 1;
			else
				reg[rt] = 0;
			TRACE_RESULT_RT();
			break;
		case OPCODE_ANDI:
			TRACE_OPCODE("andi");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			reg[rt] = reg[rs] & uimmediate;
			TRACE_RESULT_RT();
			break;
		case OPCODE_ORI:
			TRACE_OPCODE("ori");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			reg[rt] = reg[rs] | uimmediate;
			TRACE_RESULT_RT();
			break;
		case OPCODE_XORI:
			TRACE_OPCODE("xori");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			reg[rt] = reg[rs] ^ uimmediate;
			TRACE_RESULT_RT();
			break;
		case OPCODE_LUI:
			TRACE_OPCODE("lui");
			TRACE_RT();
			TRACE_IMM();
			reg[rt] = (int32_t)immediate << 16;
			TRACE_RESULT_RT();
			break;
		case OPCODE_BEQL:
			TRACE_OPCODE("beql");
			TRACE_RS();
			TRACE_RT();
			TRACE_IMM();
			if (reg[rs] == reg[rt]) {
				pc++;
				// We're not shifting left by two, because pc is already an (int *).
				next_pc = next_pc + immediate;
				TRACE_STR("taken");
			} else {
				// Skip the delay slot.
				pc += 2;
				next_pc = pc + 1;
				TRACE_STR("not taken; delay slot skipped");
			}
			continue;
		case OPCODE_BNEL:
			TRACE_OPCODE("bnel");
			TRACE_RS();
			TRACE_RT();
			TRACE_IMM();
			if (reg[rs] != reg[rt]) {
				pc++;
				// We're not shifting left by two, because pc is already an (int *).
				next_pc = next_pc + immediate;
				TRACE_STR("taken");
			} else {
				// Skip the delay slot.
				pc += 2;
				next_pc = pc + 1;
				TRACE_STR("not taken; delay slot skipped");
			}
			continue;
		case OPCODE_DADDIU:
			TRACE_OPCODE("daddiu");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			reg[rt] = reg[rs] + immediate;
			TRACE_RESULT_RT();
			break;
		case OPCODE_LB:
			TRACE_OPCODE("lb");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = *(int8_t *)(((char *)reg[rs] + immediate));
			TRACE_RESULT_RT();
			break;
#if 0
		case OPCODE_LH:
			TRACE_OPCODE("lh");
			break;
		case OPCODE_LWL:
			TRACE_OPCODE("lwl");
			TRACE_RT();
			break;
#endif
		case OPCODE_LW:
			TRACE_OPCODE("lw");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = be32toh(*(int32_t *)(((char *)reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
		case OPCODE_LBU:
			TRACE_OPCODE("lbu");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = *(uint8_t *)(((char *)reg[rs] + immediate));
			TRACE_RESULT_RT();
			break;
#if 0
		case OPCODE_LHU:
			TRACE_OPCODE("lhu");
			TRACE_RT();
			TRACE_IMM();
			break;
		case OPCODE_LWR:
			TRACE_OPCODE("lwr");
			TRACE_RT();
			break;
#endif
		case OPCODE_SB:
			TRACE_OPCODE("sb");
			TRACE_RT();
			TRACE_IMM_RS();
			*((int8_t *)((char *)(reg[rs]) + immediate)) = reg[rt];
			break;
#if 0
		case OPCODE_SH:
			TRACE_OPCODE("sh");
			TRACE_RT();
			break;
		case OPCODE_SWL:
			TRACE_OPCODE("swl");
			TRACE_RT();
			break;
#endif
		case OPCODE_SW:
			TRACE_OPCODE("sw");
			TRACE_RT();
			TRACE_IMM_RS();
			*((int32_t *)((char *)(reg[rs]) + immediate)) = htobe32(reg[rt]);
			break;
#if 0
		case OPCODE_SWR:
			TRACE_OPCODE("swr");
			TRACE_RT();
			break;
		case OPCODE_CACHE:
			TRACE_OPCODE("cache");
			break;
		case OPCODE_LL:
			TRACE_OPCODE("ll");
			TRACE_RT();
			TRACE_IMM_RS();
			break;
		case OPCODE_LWC1:
			TRACE_OPCODE("lwc1");
			TRACE_RT();
			break;
		case OPCODE_LWC2:
			TRACE_OPCODE("lwc2");
			TRACE_RT();
			break;
		case OPCODE_PREF:
			TRACE_OPCODE("pref");
			break;
		case OPCODE_LDC1:
			TRACE_OPCODE("ldc1");
			break;
		case OPCODE_LDC2:
			TRACE_OPCODE("ldc2");
			break;
#endif
		case OPCODE_LD:
			TRACE_OPCODE("ld");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = be64toh(*(int64_t *)(((char *)reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
#if 0
		case OPCODE_SC:
			TRACE_OPCODE("sc");
			TRACE_RT();
			TRACE_IMM_RS();
			break;
		case OPCODE_SWC1:
			TRACE_OPCODE("swc1");
			TRACE_RT();
			break;
		case OPCODE_SWC2:
			TRACE_OPCODE("swc2");
			TRACE_RT();
			break;
		case OPCODE_SDC1:
			TRACE_OPCODE("sdc1");
			break;
		case OPCODE_SDC2:
			TRACE_OPCODE("sdc2");
			break;
#endif
		case OPCODE_SD:
			TRACE_OPCODE("sd");
			TRACE_RT();
			TRACE_IMM_RS();
			*((int64_t *)((char *)(reg[rs]) + immediate)) = htobe64(reg[rt]);
			break;
		default:
#ifdef DIE_ON_UNKNOWN
			fprintf(stderr, "\n");
			errx(1, "unknown opcode %#x at address %p", opcode, (void *)pc);
#else
			TRACE_OPCODE("UNKNOWN");
			fprintf(stderr, "(opcode %#x, function %#x)", opcode, funct);
#endif
		}

		pc = next_pc;
		next_pc++;
	}

	return (0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: tmips binary-path\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	Elf *elf;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	const char *path;
	int *binary;
	size_t nsections;
	ssize_t nread;
	int fd, error, i;

	if (argc != 2)
		usage();

	path = argv[1];
	fd = open(path, O_RDONLY);
	if (fd < 0)
		err(1, "%s", path);

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "ELF library too old");

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL)
		errx(1, "elf_begin: %s", elf_errmsg(-1));

	ehdr = elf64_getehdr(elf);
	if (ehdr == NULL)
		errx(1, "elf64_getehdr: %s", elf_errmsg(-1));

	printf("entry point at %#lx\n", ehdr->e_entry);

	phdr = elf64_getphdr(elf);
	if (phdr == NULL)
		errx(1, "elf64_getphdr: %s", elf_errmsg(-1));

	error = elf_getphdrnum(elf, &nsections);
	if (error != 0)
		errx(1, "elf_getphdrnum: %s", elf_errmsg(-1));

	for (i = 0; (size_t)i < nsections; i++) {
		if (phdr[i].p_type != PT_LOAD)
		       continue;

		printf("section %d: p_offset %ld, p_vaddr %#lx, p_filesz %ld, p_memsz %ld, p_flags %#x\n",
		    i, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_flags);

		/*
		 * The fact that p_memsz is often different from p_filesz
		 * makes mmap(2) rather non-trivial.
		 */
		binary = mmap((void *)phdr[i].p_vaddr, phdr[i].p_memsz, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_FIXED | MAP_EXCL | MAP_PRIVATE, -1, 0);
		if (binary == MAP_FAILED)
			err(1, "cannot map %s at %p", path, (void *)phdr[i].p_vaddr);

		nread = pread(fd, binary, phdr[i].p_filesz, phdr[i].p_offset);
		if (nread != (ssize_t)phdr[i].p_filesz)
			err(1, "read");
	}

	return (run((int *)ehdr->e_entry));
}

