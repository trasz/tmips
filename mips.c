#include <sys/param.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

#ifdef TRACE
#define	RUN run_trace
#define	DO_SYSCALL do_syscall_trace
#else /* !TRACE */
#undef	RUN
#define	RUN run
#undef	DO_SYSCALL
#define	DO_SYSCALL do_syscall
#endif

#define	STACK_PAGES	3
#define	DIE_ON_UNKNOWN

#define	nitems(x)	(sizeof((x)) / sizeof((x)[0]))

#ifdef TRACE
#define	TRACE_OPCODE(STR)	do {								\
		linelen = fprintf(stderr, "\n%12llx:   %08x        %-7s ",			\
		    (unsigned long long)pc, instruction, STR);					\
		had_args = false;								\
	} while (0)

#define	TRACE_REG(REG)	do {									\
		if (had_args == true)								\
			linelen += fprintf(stderr, ",");					\
		linelen += fprintf(stderr, "%s", register_name(REG));				\
		had_args = true;								\
	} while (0)

#define	TRACE_RD()	TRACE_REG(rd)
#define	TRACE_RS()	TRACE_REG(rs)
#define	TRACE_RT()	TRACE_REG(rt)

#define	TRACE_RESULT_REG(REG)	do {								\
		const char *str;								\
		str = fetch_string(reg[REG]);							\
		fprintf(stderr, "%*s", 55 - linelen, "");					\
		if (str != NULL) {								\
			fprintf(stderr, "# %s := %#018lx (\"%s\")",				\
			     register_name(REG), reg[REG], str);				\
		} else if (REG != 0) {								\
			fprintf(stderr, "# %s := %#018lx (%ld)",				\
			     register_name(REG), reg[REG], reg[REG]);				\
		}										\
	} while (0)

#define	TRACE_RESULT_RD()	TRACE_RESULT_REG(rd)
#define	TRACE_RESULT_RS()	TRACE_RESULT_REG(rs)
#define	TRACE_RESULT_RT()	TRACE_RESULT_REG(rt)

#define	TRACE_IMM_REG(REG)	do {								\
		if (had_args == true)								\
			linelen += fprintf(stderr, ",");					\
		linelen += fprintf(stderr, "%d(%s)", immediate, register_name(REG));		\
		had_args = true;								\
	} while (0)

#define	TRACE_IMM_RS()	TRACE_IMM_REG(rs)

#define	TRACE_IMM()	do {									\
		if (had_args == true)								\
			linelen += fprintf(stderr, ",");					\
		linelen += fprintf(stderr, "%d", immediate);					\
		had_args = true;								\
	} while (0)

#define	TRACE_SA()	do {									\
		if (had_args == true)								\
			linelen += fprintf(stderr, ",");					\
		linelen += fprintf(stderr, "%d", sa);						\
		had_args = true;								\
	} while (0)

#define	TRACE_STR(STR)	do {									\
		fprintf(stderr, "%*s", 55 - linelen, "");					\
		fprintf(stderr, "# %s", STR);							\
	} while (0)

static const char *register_names[32] = {
	"zero", "at",   "v0",   "v1",   "a0",   "a1",   "a2",   "a3",
	"a4",   "a5",   "a6",   "a7",   "t0",   "t1",   "t2",   "t3",
	"s0",   "s1",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
	"t8",   "t9",   "k0",   "k1",   "gp",   "sp",   "s8",   "ra"
};

static const char *
register_name(int i)
{

	assert(i >= 0 && (unsigned long)i < nitems(register_names));

	return (register_names[i]);
}

static jmp_buf fetch_jmp;

static const char *
fetch_string_x(int64_t addr)
{
	static char buf[18]; // NB: Making it wider would break the visual layout.
	const char *p;
	char *q;

	q = buf;
	p = (const char *)addr;

	if (setjmp(fetch_jmp) != 1)
		for (; isprint(*p) && q < buf + sizeof(buf); p++, q++)
			*q = *p;

	if (q == buf)
		return (NULL);

	*q = '\0';
	return (buf);
}

static void __dead2
fetch_string_sig(int meh __unused)
{

	longjmp(fetch_jmp, 1);
}

static const char *
fetch_string(int64_t addr)
{
	const char *str;
	sig_t previous_sigsegv, previous_sigbus;

	/*
	 * XXX: This shouldn't be needed, right?  But without it, it dies occasionaly.
	 */
	if (addr < 9000000)
		return (NULL);

	previous_sigbus = signal(SIGBUS, fetch_string_sig);
	if (previous_sigbus == SIG_ERR)
		err(1, "signal");
	previous_sigsegv = signal(SIGSEGV, fetch_string_sig);
	if (previous_sigsegv == SIG_ERR)
		err(1, "signal");

	str = fetch_string_x(addr);

	if (signal(SIGBUS, previous_sigbus) == SIG_ERR)
		err(1, "signal");
	if (signal(SIGSEGV, previous_sigsegv) == SIG_ERR)
		err(1, "signal");

	return (str);
}

#else /* !TRACE */
#undef	TRACE_OPCODE
#define TRACE_OPCODE(X)
#undef	TRACE_RD
#define TRACE_RD()
#undef	TRACE_RS
#define TRACE_RS()
#undef	TRACE_RT
#define TRACE_RT()
#undef	TRACE_SA
#define TRACE_SA()
#undef	TRACE_RESULT_REG
#define TRACE_RESULT_REG(X)
#undef	TRACE_RESULT_RT
#define TRACE_RESULT_RT()
#undef	TRACE_RESULT_RD
#define TRACE_RESULT_RD()
#undef	TRACE_IMM_REG
#define TRACE_IMM_REG(X)
#undef	TRACE_IMM_RS
#define TRACE_IMM_RS()
#undef	TRACE_IMM
#define TRACE_IMM()
#undef	TRACE_JUMP
#define TRACE_JUMP()
#undef	TRACE_STR
#define TRACE_STR(X)
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
#define	FUNCT_REGIMM_BGEZ	0x01
#define	FUNCT_REGIMM_BGEZL	0x03
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
#define	OPCODE_BGTZL	0x17
#define	OPCODE_DADDIU	0x19

#define	OPCODE_LDL	0x1a
#define	OPCODE_LDR	0x1b
#define	OPCODE_SPECIAL3	0x1f

#define	FUNCT_SPECIAL3_RDHWR	0x3b

#define	OPCODE_LB	0x20
#define	OPCODE_LH	0x21
#define	OPCODE_LWL	0x22
#define	OPCODE_LW	0x23

#define	OPCODE_LBU	0x24
#define	OPCODE_LHU	0x25
#define	OPCODE_LWR	0x26
#define	OPCODE_LWU	0x27

#define	OPCODE_SB	0x28
#define	OPCODE_SH	0x29
#define	OPCODE_SWL	0x2a
#define	OPCODE_SW	0x2b

#define	OPCODE_SDL	0x2c
#define	OPCODE_SDR	0x2d
#define	OPCODE_SWR	0x2e
#define	OPCODE_CACHE	0x2f

#define	OPCODE_LL	0x30
#define	OPCODE_LWC1	0x31
#define	OPCODE_LWC2	0x32
#define	OPCODE_PREF	0x33

#define	OPCODE_LLD	0x34
#define	OPCODE_LDC1	0x35
#define	OPCODE_LDC2	0x36
#define	OPCODE_LD	0x37

#define	OPCODE_SC	0x38
#define	OPCODE_SWC1	0x39
#define	OPCODE_SWC2	0x3a

#define	OPCODE_SCD	0x3c
#define	OPCODE_SDC1	0x3d
#define	OPCODE_SDC2	0x3e
#define	OPCODE_SD	0x3f

#ifndef	MIPS_C
#define	MIPS_C

// CPU context.
static int64_t	reg[32];
static int64_t	hi;
static int64_t	lo;
static int	*pc;

static bool	had_args = false;
static int	linelen;

// Value taken from FreeBSD running on QEMU; that's what ends up in a0 at the beginning of executieon.
#define	STACK_ADDRESS	0x7fffffebb0

// This shouldn't really be needed.
#define	STACK_SIZE	4096 * 1024

static int64_t
initial_stack_pointer(void)
{
	void *p;

	p = (void *)roundup2(STACK_ADDRESS - STACK_SIZE, PAGE_SIZE);

	fprintf(stderr, "stack: mapping %d bytes at %p\n", STACK_SIZE, p);
	p = mmap(p, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_STACK | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED)
		err(1, "cannot map stack");

	// Adjust the pointer to be equal to what gets returned on native MIPS kernel.
	p = (void *)STACK_ADDRESS;	// Best kind of adjustment.

	return (int64_t)p;
}

static void
htobe32_addr(uint32_t *addr)
{

	*((uint32_t *)addr) = htobe32(*((uint32_t *)addr));
}

static void
htobe64_addr(uint64_t *addr)
{

	*((uint64_t *)addr) = htobe64(*((uint64_t *)addr));
}

static void
be32toh_addr(uint32_t *addr)
{

	*((uint32_t *)addr) = be32toh(*((uint32_t *)addr));
}

static void
be64toh_addr(uint64_t *addr)
{

	*((uint64_t *)addr) = be64toh(*((uint64_t *)addr));
}

static void
crash(int meh __unused)
{

#ifdef TRACE
	fprintf(stderr, "\n\n");
#endif
	warnx("crashed at pc %#lx", (uint64_t)pc);
	warnx("$0 = %-#18lx at = %-#18lx v0 = %-#18lx v1 = %-#18lx", reg[0], reg[1], reg[2], reg[3]);
	warnx("a0 = %-#18lx a1 = %-#18lx a2 = %-#18lx a3 = %-#18lx", reg[4], reg[5], reg[6], reg[7]);
	warnx("a4 = %-#18lx a5 = %-#18lx a6 = %-#18lx a7 = %-#18lx", reg[8], reg[9], reg[10], reg[11]);
	warnx("t0 = %-#18lx t1 = %-#18lx t2 = %-#18lx t3 = %-#18lx", reg[12], reg[13], reg[14], reg[15]);
	warnx("s0 = %-#18lx s1 = %-#18lx s2 = %-#18lx s3 = %-#18lx", reg[16], reg[17], reg[18], reg[19]);
	warnx("s4 = %-#18lx s5 = %-#18lx s6 = %-#18lx s7 = %-#18lx", reg[20], reg[21], reg[22], reg[23]);
	warnx("t8 = %-#18lx t9 = %-#18lx k0 = %-#18lx k1 = %-#18lx", reg[24], reg[25], reg[26], reg[27]);
	warnx("gp = %-#18lx sp = %-#18lx s8 = %-#18lx ra = %-#18lx", reg[28], reg[29], reg[30], reg[31]);

	signal(SIGBUS, SIG_DFL);
	signal(SIGSEGV, SIG_DFL);
}

static void
crash_handlers(void)
{

	if (signal(SIGBUS, crash) == SIG_ERR)
		err(1, "signal");
	if (signal(SIGSEGV, crash) == SIG_ERR)
		err(1, "signal");
}

#endif /* !MIPS_C */

static inline int64_t
DO_SYSCALL(int64_t number, int64_t a0, int64_t a1, int64_t a2,
    int64_t a3, int64_t a4, int64_t a5)
{
	off_t rv;
	int i;

#ifdef TRACE
	fprintf(stderr, "              # syscall(%ld, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx)",
	    number, a0, a1, a2, a3, a4, a5);
#endif
	switch (number) {
	case SYS___sysctl:
		for (i = 0; i < a1; i++)
			be32toh_addr((uint32_t *)a0 + i);
		be64toh_addr((uint64_t *)a3);
		break;
	case SYS_sigaction:
		if (a1 != 0) {
			be64toh_addr((uint64_t *)a1);
			be64toh_addr((uint64_t *)(a1 + 7));
			be32toh_addr((uint32_t *)(a1 + 15));
			be32toh_addr((uint32_t *)(a1 + 19));
		}
		break;
	case SYS_sigprocmask:
		if (a1 != 0)
			be32toh_addr((uint32_t *)a1);
		break;
	}

	rv = __syscall(number, a0, a1, a2, a3, a4, a5);

	switch (number) {
	case SYS___sysctl:
		if (a1 == 2 && *((uint32_t *)a0) == 0 && *((uint32_t *)a0 + 1) == 3) {
			/* It's sysctl.name2oid, used by sysctlnametomib(3).  Yeah, sorry. */
			for (i = 0; i < *(int64_t *)a3 / 4; i++)
				htobe32_addr((uint32_t *)a2 + i);
		} else if (*(uint64_t *)a3 == 4) {
			htobe32_addr((uint32_t *)a2);
		} else if (*(uint64_t *)a3 == 8) {
			htobe64_addr((uint64_t *)a2);
		}
		for (i = 0; i < a1; i++)
			htobe32_addr((uint32_t *)a0 + i);
		htobe64_addr((uint64_t *)a3);
		break;
	case SYS_sigaction:
		if (a1 != 0) {
			htobe64_addr((uint64_t *)a1);
			htobe64_addr((uint64_t *)(a1 + 7));
			htobe32_addr((uint32_t *)(a1 + 15));
			htobe32_addr((uint32_t *)(a1 + 19));
		}
		if (a2 != 0) {
			htobe64_addr((uint64_t *)a2);
			htobe64_addr((uint64_t *)(a2 + 7));
			htobe32_addr((uint32_t *)(a2 + 15));
			htobe32_addr((uint32_t *)(a2 + 19));
		}
		break;
	case SYS_sigprocmask:
		if (a2 != 0)
			htobe32_addr((uint32_t *)a2);
		break;
	case SYS_thr_self:
		htobe64_addr((uint64_t *)a0);
		break;
	}
#ifdef TRACE
	fprintf(stderr, " = %#018lx (%ld); errno %d", rv, rv, errno);
#endif
	return (rv);
}

static int
RUN(int *pcc, int argc, char **argv)
{
	char **ps_strings;
	uint32_t rs, rt, rd, sa, instruction, opcode, funct;
	uint16_t uimmediate;
	int16_t immediate;
	int i, j, *next_pc;

	// Set up the strings.
	i = 0;
	ps_strings = (char **)initial_stack_pointer();
	fprintf(stderr, "ps_strings at %p, argc %d\n", (void *)ps_strings, argc);
	ps_strings[i++] = (char *)htobe64((uint64_t)argc);
	for (j = 0; j < argc; j++)
		ps_strings[i++] = (char *)htobe64((uint64_t)argv[j]);
	ps_strings[i++] = 0;
	for (j = 0; environ[j] != '\0'; j++)
		ps_strings[i++] = (char *)htobe64((uint64_t)environ[j]);
	ps_strings[i++] = 0;

	// Set up the initial CPU state.
	memset(reg, 0, sizeof(reg));
	hi = 0;
	lo = 0;
	pc = pcc;
	reg[0] = 0;
	reg[4] = (int64_t)ps_strings;		// a0, should be 0x7fffffebb0
	reg[25] = (int64_t)pc;			// t9
	reg[29] = (int64_t)ps_strings - 128;	// sp

	next_pc = pc + 1;

	// Just in case.
	crash_handlers();

	// Run!
	for (;;) {
		reg[0] = 0;

		instruction = be32toh(*pc);

		opcode = (instruction & (0x3Ful << 26)) >> 26;

		rs = (instruction & (0x1F << 21)) >> 21;
		rt = (instruction & (0x1F << 16)) >> 16;
		rd = (instruction & (0x1F << 11)) >> 11;
		sa = (instruction & (0x1F << 6)) >> 6;

		immediate = (instruction << 16) >> 16;
		uimmediate = (immediate << 16) >> 16;

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
				reg[rd] = (int32_t)reg[rt] >> sa;
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_SLLV:
				TRACE_OPCODE("sllv");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				reg[rd] = (uint32_t)reg[rt] << reg[rs];
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_SRLV:
				TRACE_OPCODE("srlv");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				reg[rd] = (uint32_t)reg[rt] > reg[rs];
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
				errno = 0;
				if (reg[2] == 0) {
					// XXX: Without this special case, things die with ENOSYS.
					reg[7] = DO_SYSCALL(reg[4], reg[5], reg[6], reg[7], reg[8], reg[9], 0);
				} else {
					reg[7] = DO_SYSCALL(reg[2], reg[4], reg[5], reg[6], reg[7], reg[8], reg[9]);
				}
				// po mmap wartosc ma byc w reg[2]
				//if (reg[7] != 0)
				if (errno != 0) {
					reg[2] = errno;
				} else {
					reg[2] = reg[7];
					reg[7] = 0;
				}
				break;
#if 0
			case FUNCT_SPECIAL_BREAK:
				TRACE_OPCODE("break");
				break;
#endif
			case FUNCT_SPECIAL_SYNC:
				TRACE_OPCODE("sync");
				break;
			case FUNCT_SPECIAL_MFHI:
				TRACE_OPCODE("mfhi");
				TRACE_RD();
				reg[rd] = hi;
				TRACE_RESULT_RD();
				break;
#if 0
			case FUNCT_SPECIAL_MTHI:
				TRACE_OPCODE("mthi");
				TRACE_RS();
				break;
#endif
			case FUNCT_SPECIAL_MFLO:
				TRACE_OPCODE("mflo");
				TRACE_RD();
				reg[rd] = lo;
				TRACE_RESULT_RD();
				break;
#if 0
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
#endif
			case FUNCT_SPECIAL_MULT:
				TRACE_OPCODE("mult");
				TRACE_RS();
				TRACE_RT();
				lo = (int64_t)((int32_t)reg[rs]) * (uint32_t)reg[rt];
				hi = lo & (0xffffffffull << 32);
				lo = hi & 0xffffffff;
				break;
			case FUNCT_SPECIAL_MULTU:
				TRACE_OPCODE("multu");
				TRACE_RS();
				TRACE_RT();
				lo = (uint64_t)(int32_t)reg[rs] * (uint32_t)reg[rt];
				hi = lo & (0xffffffffull << 32);
				lo = hi & 0xffffffff;
				break;
#if 0
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
#endif
			case FUNCT_SPECIAL_DMULT:
				TRACE_OPCODE("dmult");
				TRACE_RS();
				TRACE_RT();
				lo = reg[rs] * reg[rt];
				hi = 0; // XXX
				break;
			case FUNCT_SPECIAL_DMULTU:
				TRACE_OPCODE("dmultu");
				TRACE_RS();
				TRACE_RT();
				lo = (uint64_t)reg[rs] * (uint64_t)reg[rt];
				hi = 0; // XXX
				break;
#if 0
			case FUNCT_SPECIAL_DDIV:
				TRACE_OPCODE("ddiv");
				TRACE_RS();
				TRACE_RT();
				break;
#endif
			case FUNCT_SPECIAL_DDIVU:
				TRACE_OPCODE("ddivu");
				TRACE_RS();
				TRACE_RT();
				lo = (uint64_t)reg[rs] / (uint64_t)reg[rt];
				hi = (uint64_t)reg[rs] % (uint64_t)reg[rt];
				break;
			case FUNCT_SPECIAL_ADD:
				TRACE_OPCODE("add");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] + reg[rt];
				TRACE_RESULT_RD();
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
			case FUNCT_SPECIAL_SLT:
				TRACE_OPCODE("slt");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				if (reg[rs] < reg[rt])
					reg[rd] = 1;
				else
					reg[rd] = 0;
				TRACE_RESULT_RD();
				break;
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
				reg[rd] = (uint64_t)reg[rs] - (uint64_t)reg[rt];
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
#endif
			case FUNCT_SPECIAL_TEQ:
				TRACE_OPCODE("teq");
				TRACE_RS();
				TRACE_RT();
				TRACE_STR("dummy");
				break;
#if 0
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
				reg[rd] = (uint64_t)reg[rt] >> (sa + 32);
				TRACE_RESULT_RD();
				break;
			case FUNCT_SPECIAL_DSRA32:
				TRACE_OPCODE("dsra32");
				TRACE_RD();
				TRACE_RT();
				TRACE_SA();
				reg[rd] = reg[rt] >> (sa + 32);
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
					TRACE_STR("taken");
					continue;
				}
				break;
			case FUNCT_REGIMM_BGEZ:
				TRACE_OPCODE("bgez");
				TRACE_RS();
				TRACE_IMM();
				if (reg[rs] >= 0) {
					pc++;
					// We're not shifting left by two, because pc is already an (int *).
					next_pc = next_pc + immediate;
					TRACE_STR("taken");
					continue;
				}
				break;
			case FUNCT_REGIMM_BGEZL:
				TRACE_OPCODE("bgezl");
				TRACE_RS();
				TRACE_IMM();
				if (reg[rs] >= 0) {
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
		case OPCODE_BGTZ:
			TRACE_OPCODE("bgtz");
			TRACE_RS();
			TRACE_IMM();
			if (reg[rs] > 0) {
				pc++;
				// We're not shifting left by two, because pc is already an (int *).
				next_pc = next_pc + immediate;
				TRACE_STR("taken");
				continue;
			}
			TRACE_STR("not taken");
			break;
		case OPCODE_ADDI:
			TRACE_OPCODE("addi");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			reg[rt] = (int64_t)((int32_t)reg[rs]) + immediate;
			break;
		case OPCODE_ADDIU:
			TRACE_OPCODE("addiu");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			reg[rt] = (int64_t)((int32_t)reg[rs]) + immediate;
			TRACE_RESULT_RT();
			break;
		case OPCODE_SLTI:
			TRACE_OPCODE("slti");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			if (reg[rs] < immediate)
				reg[rt] = 1;
			else
				reg[rt] = 0;
			TRACE_RESULT_RT();
			break;
		case OPCODE_SLTIU:
			TRACE_OPCODE("sltiu");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			if ((uint64_t)reg[rs] < (uint64_t)immediate)
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
		case OPCODE_BGTZL:
			TRACE_OPCODE("bgtzl");
			TRACE_RS();
			TRACE_IMM();
			if (reg[rs] > 0) {
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
		case OPCODE_LDL:
			TRACE_OPCODE("ldl");
			TRACE_RT();
			TRACE_IMM_RS();
			// XXX: Questionable.
			reg[rt] = be64toh(*((volatile int64_t *)(reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
		case OPCODE_LDR:
			TRACE_OPCODE("ldr");
			TRACE_RT();
			TRACE_IMM_RS();
			/*
			 * This is a highly optimized implementation that depends
			 * on ldl doing all the work.
			 */
			TRACE_RESULT_RT();
			break;
		case OPCODE_SPECIAL3:
			funct = instruction & 0x3F;

			switch (funct) {
			case FUNCT_SPECIAL3_RDHWR:
				TRACE_OPCODE("rdhwr");
				TRACE_RT();
				reg[rt] = 0; // XXX
				TRACE_RESULT_RT();
			break;
			default:
#ifdef DIE_ON_UNKNOWN
				fprintf(stderr, "\n");
				errx(1, "unknown special3 opcode %#x, function %#x at address %p", opcode, funct, (void *)pc);
#else
				TRACE_OPCODE("SPECIAL");
				fprintf(stderr, "(opcode %#x, function %#x)", opcode, funct);
#endif
				break;
			}
			break;
		case OPCODE_LB:
			TRACE_OPCODE("lb");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = *((volatile int8_t *)(reg[rs] + immediate));
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
			reg[rt] = be32toh(*((volatile int32_t *)(reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
		case OPCODE_LBU:
			TRACE_OPCODE("lbu");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = *((volatile uint8_t *)(reg[rs] + immediate));
			TRACE_RESULT_RT();
			break;
		case OPCODE_LHU:
			TRACE_OPCODE("lhu");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = be16toh(*((volatile uint16_t *)(reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
#if 0
		case OPCODE_LWR:
			TRACE_OPCODE("lwr");
			TRACE_RT();
			break;
#endif
		case OPCODE_LWU:
			TRACE_OPCODE("lwu");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = be32toh(*((volatile uint32_t *)(reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
		case OPCODE_SB:
			TRACE_OPCODE("sb");
			TRACE_RT();
			TRACE_IMM_RS();
			*((volatile int8_t *)(reg[rs] + immediate)) = (int8_t)reg[rt];
			break;
		case OPCODE_SH:
			TRACE_OPCODE("sh");
			TRACE_RT();
			TRACE_IMM_RS();
			*((volatile uint16_t *)(reg[rs] + immediate)) = htobe16(reg[rt]);
			break;
#if 0
		case OPCODE_SWL:
			TRACE_OPCODE("swl");
			TRACE_RT();
			break;
#endif
		case OPCODE_SW:
			TRACE_OPCODE("sw");
			TRACE_RT();
			TRACE_IMM_RS();
			*((volatile int32_t *)(reg[rs] + immediate)) = htobe32(reg[rt]);
			break;
		case OPCODE_SDL:
			TRACE_OPCODE("sdl");
			TRACE_RT();
			TRACE_IMM_RS();
			// XXX: Questionable.
			*((volatile int64_t *)(reg[rs] + immediate)) = htobe64(reg[rt]);
			break;
		case OPCODE_SDR:
			TRACE_OPCODE("sdr");
			TRACE_RT();
			TRACE_IMM_RS();
			/*
			 * This is a highly optimized implementation that depends
			 * on sdl doing all the work.
			 */
			break;
#if 0
		case OPCODE_SWR:
			TRACE_OPCODE("swr");
			TRACE_RT();
			break;
		case OPCODE_CACHE:
			TRACE_OPCODE("cache");
			break;
#endif
		case OPCODE_LL:
			TRACE_OPCODE("ll");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = be32toh(*((volatile int32_t *)(reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
#if 0
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
#endif
		case OPCODE_LLD:
			TRACE_OPCODE("lld");
			TRACE_RT();
			TRACE_IMM_RS();
			reg[rt] = be64toh(*((int64_t *)(reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
#if 0
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
			reg[rt] = be64toh(*((volatile int64_t *)(reg[rs] + immediate)));
			TRACE_RESULT_RT();
			break;
		case OPCODE_SC:
			TRACE_OPCODE("sc");
			TRACE_RT();
			TRACE_IMM_RS();
			*((volatile int32_t *)(reg[rs] + immediate)) = htobe32(reg[rt]);
			reg[rt] = 1;
			TRACE_RESULT_RT();
			break;
#if 0
		case OPCODE_SWC1:
			TRACE_OPCODE("swc1");
			TRACE_RT();
			break;
		case OPCODE_SWC2:
			TRACE_OPCODE("swc2");
			TRACE_RT();
			break;
#endif
		case OPCODE_SCD:
			TRACE_OPCODE("scd");
			TRACE_RT();
			TRACE_IMM_RS();
			*((int64_t *)(reg[rs] + immediate)) = htobe64(reg[rt]);
			reg[rt] = 1;
			TRACE_RESULT_RT();
			break;
#if 0
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
			*((volatile int64_t *)(reg[rs] + immediate)) = htobe64(reg[rt]);
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
