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

#include "opcodes.h"

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
		if ((instruction & 0x3) == 0x3) {						\
			linelen = fprintf(stderr, "\n%12llx:   %08x        %-7s ",		\
			    (unsigned long long)pc, instruction, STR);				\
		} else {									\
			linelen = fprintf(stderr, "\n%12llx:   %04x            %-7s ",		\
			    (unsigned long long)pc, instruction, STR);				\
		}										\
		had_args = false;								\
	} while (0)

#define	TRACE_REG(REG)	do {									\
		if (had_args == true)								\
			linelen += fprintf(stderr, ",");					\
		linelen += fprintf(stderr, "%s", register_name(REG));				\
		had_args = true;								\
	} while (0)

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

#define	TRACE_IMM_REG(REG)	do {								\
		if (had_args == true)								\
			linelen += fprintf(stderr, ",");					\
		linelen += fprintf(stderr, "%d(%s)", immediate, register_name(REG));		\
		had_args = true;								\
	} while (0)

#define	TRACE_IMM(IMM)	do {									\
		if (had_args == true)								\
			linelen += fprintf(stderr, ",");					\
		linelen += fprintf(stderr, "%d", IMM);						\
		had_args = true;								\
	} while (0)

#define	TRACE_STR(STR)	do {									\
		fprintf(stderr, "%*s", 55 - linelen, "");					\
		fprintf(stderr, "# %s", STR);							\
	} while (0)

static const char *register_names[32] = {
	"zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t2",   "t3",
	"s0",   "s1",   "a0",   "a1",   "a2",   "a3",   "a4",   "a5",
	"a6",   "a7",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
	"s8",   "s9",   "s10",  "s11",  "t3",   "t4",   "t5",   "t6"
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
#undef	TRACE_RESULT_REG
#define TRACE_RESULT_REG(X)
#undef	TRACE_IMM_REG
#define TRACE_IMM_REG(X)
#undef	TRACE_IMM
#define TRACE_IMM(X)
#undef	TRACE_JUMP
#define TRACE_JUMP()
#undef	TRACE_STR
#define TRACE_STR(X)
#endif /* !TRACE */

/*
 * RV32I Base Instruction Set
 */
#define	OP_LUI		0x37
#define	OP_AUIPC	0x17
#define	OP_JAL		0x6f

/*
 * Most opcodes are defined in "opcodes.h".
 */

/*
 * RV64C
 */
#define	OP_C0		0x00
#define		OP_CADDI4SPN	(OP_C0)
#define		OP_CFLD		(OP_C0 | (0x1 << 13))
#define		OP_CLW		(OP_C0 | (0x2 << 13))
#define		OP_CLD		(OP_C0 | (0x3 << 13))
				/* (Reserved.) */
#define		OP_CFSD		(OP_C0 | (0x5 << 13))
#define		OP_CSW		(OP_C0 | (0x6 << 13))
#define		OP_CSD		(OP_C0 | (0x7 << 13))

#define	OP_C1		0x01
#define		OP_CNOP_ET_AL	(OP_C1)
#define		OP_CADDIW	(OP_C1 | (0x1 << 13))
#define		OP_CLI		(OP_C1 | (0x2 << 13))
#define		OP_CADDI16SP_ET_AL	(OP_C1 | (0x3 << 13))
#define		OP_CSRLI_ET_AL	(OP_C1 | (0x4 << 13))
#define		OP_CJ		(OP_C1 | (0x5 << 13))
#define		OP_CBEQZ	(OP_C1 | (0x6 << 13))
#define		OP_CBNEZ	(OP_C1 | (0x7 << 13))

#define	OP_C2		0x02
#define		OP_CSLLI_ET_AL	(OP_C2)
#define		OP_CFLDSP	(OP_C2 | (0x1 << 13))
#define		OP_CLWSP	(OP_C2 | (0x2 << 13))
#define		OP_CLDSP	(OP_C2 | (0x3 << 13))
#define		OP_CJR_ET_AL	(OP_C2 | (0x4 << 13))
#define		OP_CFSDSP	(OP_C2 | (0x5 << 13))
#define		OP_CSWSP	(OP_C2 | (0x6 << 13))
#define		OP_CSDSP	(OP_C2 | (0x7 << 13))

#ifndef	MIPS_C
#define	MIPS_C

// CPU context.
static int64_t	reg[32];
static int64_t	hi;
static int64_t	lo;
static int	*pc;

static bool	had_args = false;
static int	linelen;

// Values taken from FreeBSD running on QEMU.
#define	STACK_TOP	0x7ffffff000
#define	STACK_BOTTOM	0x7ffffdf000

#define	PS_STRINGS	0x7fffffebb0

static void
map_stack(void)
{
	void *p;

	fprintf(stderr, "stack top at %#lx, bottom at %#lx\n", STACK_TOP, STACK_BOTTOM);
	p = mmap((void *)STACK_BOTTOM, STACK_TOP - STACK_BOTTOM, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_STACK | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED)
		err(1, "cannot map stack");
}

static int64_t
push_string(int64_t sp, const char *str)
{
	size_t len;

	len = strlen(str) + 1;
	sp -= len;
	memcpy((void *)sp, str, len);

	return (sp);
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
	warnx("$0 = %-#18lx ra = %-#18lx sp = %-#18lx gp = %-#18lx", reg[0], reg[1], reg[2], reg[3]);
	warnx("tp = %-#18lx t0 = %-#18lx t2 = %-#18lx t3 = %-#18lx", reg[4], reg[5], reg[6], reg[7]);
	warnx("s0 = %-#18lx s1 = %-#18lx a0 = %-#18lx a1 = %-#18lx", reg[8], reg[9], reg[10], reg[11]);
	warnx("a2 = %-#18lx a3 = %-#18lx a4 = %-#18lx a5 = %-#18lx", reg[12], reg[13], reg[14], reg[15]);
	warnx("a6 = %-#18lx a7 = %-#18lx s2 = %-#18lx s3 = %-#18lx", reg[16], reg[17], reg[18], reg[19]);
	warnx("s4 = %-#18lx s5 = %-#18lx s6 = %-#18lx s7 = %-#18lx", reg[20], reg[21], reg[22], reg[23]);
	warnx("s8 = %-#18lx s9 = %-#18lx s10= %-#18lx s11= %-#18lx", reg[24], reg[25], reg[26], reg[27]);
	warnx("t3 = %-#18lx t4 = %-#18lx t5 = %-#18lx t6 = %-#18lx", reg[28], reg[29], reg[30], reg[31]);

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

static int
unprime(int prime)
{
	/*
	 * Table 12.2: Registers specified by the three-bit rs1’, rs2’, and rd’ fields of the CIW, CL, CS, and CB formats.
	 */
	assert(prime >= 0 && prime <= 7);
	return (prime + 8);
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

#define	PICK(VAR, NBITS, SHIFT)	(VAR & (~0U >> (32 - NBITS)) << SHIFT) >> SHIFT

static int
RUN(int *pcc, int argc, char **argv)
{
	char **ps_strings;
	int instruction, imm_11_0, opcode, rd, rs1, rd_rs1, rs2;
	uint64_t sp;
	unsigned char *pc;
	int i, j;

	map_stack();

	// Set up the strings.
	sp = STACK_TOP;
	i = 0;

	// Adjust the pointer to be equal to what gets returned on native MIPS kernel.
	ps_strings = (void *)PS_STRINGS;

	fprintf(stderr, "ps_strings at %p, argc %d\n", (void *)ps_strings, argc);
	ps_strings[i++] = (char *)(uint64_t)argc;
	for (j = 0; j < argc; j++) {
		sp = push_string(sp, argv[j]);
		ps_strings[i++] = (char *)(uint64_t)sp;
	}
	ps_strings[i++] = 0;
	for (j = 0; environ[j] != '\0'; j++) {
		sp = push_string(sp, environ[j]);
		ps_strings[i++] = (char *)sp;
	}
	ps_strings[i++] = 0;

	// Set up the initial CPU state.
	memset(reg, 0, sizeof(reg));
	hi = 0;
	lo = 0;
	pc = pcc;
	reg[0] = 0;
	reg[4] = (int64_t)ps_strings;		// a0, should be 0x7fffffebb0
	reg[25] = (int64_t)pc;			// t9
	reg[29] = (int64_t)0x7fffffebb0;	// sp, should be 0x7fffffeb70

	// Just in case.
	crash_handlers();

	// Run!
	for (;;) {
		reg[0] = 0;

		instruction = *(uint32_t *)pc;

		if ((instruction & 0x3) == 0x3) {
			opcode = instruction & 0x383f /* 0b11100000111111 */;
			rd = PICK(instruction, 5, 7);
			rs1 = PICK(instruction, 5, 15);
			rs2 = PICK(instruction, 5, 20);
			imm_11_0 = PICK(instruction, 12, 20);

			switch (opcode) {
			case OP_ADDI:
				TRACE_OPCODE("addi");
				TRACE_REG(rd);
				TRACE_REG(rs1);
				TRACE_IMM(imm_11_0);
				break;
			case OP_SLLI:
				TRACE_OPCODE("slli");
				TRACE_REG(rd);
				TRACE_REG(rs1);
				TRACE_IMM(imm_11_0);
				break;
			case OP_ADD:
				TRACE_OPCODE("add");
				TRACE_REG(rd);
				TRACE_REG(rs1);
				TRACE_REG(rs2);
				break;

			default:
				opcode = instruction & 0x7f /* 0b1111111 */;
				switch (opcode) {
				case OP_LUI:
					TRACE_OPCODE("lui");
					TRACE_REG(rd);
					// XXX: Offset
					break;
				case OP_AUIPC:
					TRACE_OPCODE("auipc");
					TRACE_REG(rd);
					// XXX: Offset
					break;
				case OP_JAL:
					TRACE_OPCODE("jal");
					TRACE_REG(rd);
					// XXX: Offset
					break;
				default:
#ifdef DIE_ON_UNKNOWN
					fprintf(stderr, "\n");
					errx(1, "unknown instruction %#x (opcode %#x) at address %p", instruction, opcode, (void *)pc);
#else
					TRACE_OPCODE("UNKNOWN");
					fprintf(stderr, "(opcode %#x, function %#x)", opcode, funct);
#endif
				}
			}

			pc += 4;
		} else {
			int rd_prime, rs1_prime, rs1_prime_rd_prime, rs2_prime;

			instruction &= 0xffff;

			opcode = instruction & 0xe003 /* 0b1110000000000011 */;
			rd_rs1 = PICK(instruction, 5, 7);
			rs2 = PICK(instruction, 5, 2);
			rs2_prime = rd_prime = unprime(PICK(instruction, 3, 2));
			rs1_prime_rd_prime = rs1_prime = unprime(PICK(instruction, 3, 7));

			switch (opcode) {
			case OP_CLD:
				TRACE_OPCODE("c.ld");
				TRACE_REG(rd_prime);
				TRACE_REG(rs1_prime);
				// XXX: Offset
				break;
			case OP_CNOP_ET_AL:
				if (rd_rs1 == 0) {
					TRACE_OPCODE("c.nop");
					break;
				} else {
					TRACE_OPCODE("c.addi");
					TRACE_REG(rd_rs1);
					// XXX: Offset
					break;
				}
			case OP_CSRLI_ET_AL:
				switch (PICK(instruction, 2, 10)) {
				case 0x3:
					switch (PICK(instruction, 2, 5)) {
					case 0x0:
						TRACE_OPCODE("c.sub");
						TRACE_REG(rs1_prime_rd_prime);
						TRACE_REG(rs2_prime);
						break;
					}
				}
			case OP_CJR_ET_AL:
				if (PICK(instruction, 1, 12) == 0) {
					if (rs2 == 0) {
						TRACE_OPCODE("c.jr");
						break;
					} else {
						TRACE_OPCODE("c.mv");
						TRACE_REG(rd_rs1);
						TRACE_REG(rs2);
						break;
					}
				} else {
					if (rs2 == 0) {
						if (rd_rs1 == 0) {
							TRACE_OPCODE("c.ebreak");
							break;
						} else {
							TRACE_OPCODE("c.jalr");
							break;
						}
					} else {
						TRACE_OPCODE("c.add");
						break;
					}
				}
			case OP_CSDSP:
				TRACE_OPCODE("c.sdsp");
				TRACE_REG(rs2);
				// XXX: Offset, sp
				break;
			default:
#ifdef DIE_ON_UNKNOWN
				fprintf(stderr, "\n");
				errx(1, "unknown instruction %#x (opcode %#x) at address %p", instruction, opcode, (void *)pc);
#else
				TRACE_OPCODE("UNKNOWN");
				fprintf(stderr, "(opcode %#x, function %#x)", opcode, funct);
#endif
			}

			pc += 2;
		}
	}

	return (0);
}
