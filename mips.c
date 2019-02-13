#include <sys/param.h>
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

#define	nitems(x)	(sizeof((x)) / sizeof((x)[0]))

#ifdef TRACE
#define	TRACE_OPCODE(STR)	do {							\
		if ((instruction & 0x3) == 0x3) {					\
			linelen = fprintf(stderr, "\n%12lx:\t%08x        \t%-7s ",	\
			    pc, instruction, STR);					\
		} else {								\
			linelen = fprintf(stderr, "\n%12lx:\t%04x            \t%-7s ",	\
			    pc, instruction & 0xffff, STR);				\
		}									\
		had_args = false;							\
	} while (0)

#define	TRACE_REG(REG)	do {								\
		if (had_args == true)							\
			linelen += fprintf(stderr, ",");				\
		linelen += fprintf(stderr, "%s", register_name(REG));			\
		had_args = true;							\
	} while (0)

#define	TRACE_RESULT_REG(REG)	do {							\
		const char *str;							\
		str = fetch_string(x[REG]);						\
		fprintf(stderr, "%*s", 55 - linelen, "");				\
		if (str != NULL) {							\
			fprintf(stderr, "# %s := %#018lx (\"%s\")",			\
			     register_name(REG), x[REG], str);				\
		} else if (REG != 0) {							\
			fprintf(stderr, "# %s := %#018lx (%ld)",			\
			     register_name(REG), x[REG], x[REG]);			\
		}									\
	} while (0)

#define	TRACE_IMM_REG(IMM, REG)	do {							\
		if (had_args == true)							\
			linelen += fprintf(stderr, ",");				\
		linelen += fprintf(stderr, "%ld(%s)", IMM, register_name(REG));		\
		had_args = true;							\
	} while (0)

#define	TRACE_IMM(IMM)	do {								\
		if (had_args == true)							\
			linelen += fprintf(stderr, ",");				\
		linelen += fprintf(stderr, "%#lx", IMM);				\
		had_args = true;							\
	} while (0)

#define	TRACE_STR(STR)	do {								\
		fprintf(stderr, "%*s", 55 - linelen, "");				\
		fprintf(stderr, "# %s", STR);						\
	} while (0)

static const char *register_names[32] = {
	"zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t1",   "t2",
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
#undef	TRACE_REG
#define TRACE_REG(X)
#undef	TRACE_RESULT_REG
#define TRACE_RESULT_REG(X)
#undef	TRACE_IMM_REG
#define TRACE_IMM_REG(IMM, X)
#undef	TRACE_IMM
#define TRACE_IMM(X)
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
static uint64_t	x[32];
static uint64_t	pc;

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
crash(int meh __unused)
{

#ifdef TRACE
	fprintf(stderr, "\n\n");
#endif
	warnx("crashed at pc %lx", pc);
	warnx("$0: %-#18lx ra: %-#18lx  sp: %-#18lx  gp: %-#18lx", x[0],  x[1],  x[2],  x[3]);
	warnx("tp: %-#18lx t0: %-#18lx  t1: %-#18lx  t2: %-#18lx", x[4],  x[5],  x[6],  x[7]);
	warnx("s0: %-#18lx s1: %-#18lx  a0: %-#18lx  a1: %-#18lx", x[8],  x[9],  x[10], x[11]);
	warnx("a2: %-#18lx a3: %-#18lx  a4: %-#18lx  a5: %-#18lx", x[12], x[13], x[14], x[15]);
	warnx("a6: %-#18lx a7: %-#18lx  s2: %-#18lx  s3: %-#18lx", x[16], x[17], x[18], x[19]);
	warnx("s4: %-#18lx s5: %-#18lx  s6: %-#18lx  s7: %-#18lx", x[20], x[21], x[22], x[23]);
	warnx("s8: %-#18lx s9: %-#18lx s10: %-#18lx s11: %-#18lx", x[24], x[25], x[26], x[27]);
	warnx("t3: %-#18lx t4: %-#18lx  t5: %-#18lx  t6: %-#18lx", x[28], x[29], x[30], x[31]);

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

#ifdef TRACE
	fprintf(stderr, "              # syscall(%ld, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx)",
	    number, a0, a1, a2, a3, a4, a5);
#endif

	rv = __syscall(number, a0, a1, a2, a3, a4, a5);

#ifdef TRACE
	fprintf(stderr, " = %#018lx (%ld); errno %d", rv, rv, errno);
#endif
	return (rv);
}

#define	PICK(VAR, NBITS, SHIFT)	((VAR & (~0U >> (32 - NBITS)) << SHIFT) >> SHIFT)

/*
 * From sys/riscv/include/param.h
 */
#define	STACKALIGNBYTES	(16 - 1)
#define	STACKALIGN(p)	((uint64_t)(p) & ~STACKALIGNBYTES)

static int
RUN(int *pcc, int argc, char **argv)
{
	char **ps_strings;
	int instruction, opcode;
	uint64_t sp;
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

	// Set up the initial CPU state.  This needs to match
	// sys/riscv/riscv/machdep.c:exec_setregs().
	memset(x, 0, sizeof(x));
	pc = (uint64_t)pcc;

	x[10] = sp; /* a0 */
	x[2] = STACKALIGN(sp); /* sp */
	x[1] = (uintptr_t)pcc; /* ra */

	// Just in case.
	crash_handlers();

	// Run!
	for (;;) {
		x[0] = 0;

		instruction = *(int *)pc;

		if ((instruction & 0x3) == 0x3) {
			int rd, rs1, rs2;
			intptr_t imm_i, imm_s, imm_b, imm_u, imm_j;

			/*
			 * Give CPU something to do during all those loads.
			 */
			opcode = instruction & 0x707f /* 0b111000001111111 */;
			rd = PICK(instruction, 5, 7);
			rs1 = PICK(instruction, 5, 15);
			rs2 = PICK(instruction, 5, 20);
			imm_i = PICK(instruction, 12, 20);
			imm_s = PICK(instruction, 4, 7) | PICK(instruction, 12, 25) << 5;
			imm_b = pc + (PICK(instruction, 1, 31) << 12 | PICK(instruction, 6, 25) << 5 | PICK(instruction, 4, 8) << 1 | PICK(instruction, 1, 7) << 11);
			imm_u = PICK(instruction, 20, 12);
			imm_j = pc + (PICK(instruction, 1, 31) << 20 | PICK(instruction, 10, 21) << 1 | PICK(instruction, 1, 20) << 11 | PICK(instruction, 8, 12) << 12); /* srsly */

			/*
			 * Opcodes from "opcodes.h" go here.
			 */
			switch (opcode) {
			case OP_BEQ:
				TRACE_OPCODE("beq");
				TRACE_REG(rs1);
				TRACE_REG(rs2);
				TRACE_IMM(imm_b);
				if (x[rs1] == x[rs2]) {
					TRACE_STR("taken");
					// Note that imm_b already includes pc.  It's done that way for compatibility
					// with GNU objdump.
					pc = imm_b;
					continue;
				}
				TRACE_STR("not taken");
				break;
			case OP_BNE:
				TRACE_OPCODE("bne");
				TRACE_REG(rs1);
				TRACE_REG(rs2);
				TRACE_IMM(imm_b);
				if (x[rs1] != x[rs2]) {
					TRACE_STR("taken");
					pc = imm_b;
					continue;
				}
				TRACE_STR("not taken");
				break;
			case OP_BGE:
				TRACE_OPCODE("bge");
				TRACE_REG(rs1);
				TRACE_REG(rs2);
				TRACE_IMM(imm_b);
				if (x[rs1] >= x[rs2]) {
					TRACE_STR("taken");
					pc = imm_b;
					continue;
				}
				TRACE_STR("not taken");
				break;
			case OP_BLTU:
				TRACE_OPCODE("bltu");
				TRACE_REG(rs1);
				TRACE_REG(rs2);
				TRACE_IMM(imm_b);
				break;
			case OP_BGEU:
				TRACE_OPCODE("bgeu");
				TRACE_REG(rs1);
				TRACE_REG(rs2);
				TRACE_IMM(imm_b);
				break;
			case OP_ADDI:
				TRACE_OPCODE("addi");
				TRACE_REG(rd);
				TRACE_REG(rs1);
				TRACE_IMM(imm_i);
				x[rd] = x[rs1] + imm_i;
				TRACE_RESULT_REG(rd);
				break;
			case OP_SLLI:
				TRACE_OPCODE("slli");
				TRACE_REG(rd);
				TRACE_REG(rs1);
				TRACE_IMM(imm_i);
				x[rd] = x[rs1] << imm_i;
				TRACE_RESULT_REG(rd);
				break;
			case OP_SRAI:
				TRACE_OPCODE("srai");
				TRACE_REG(rd);
				TRACE_REG(rs1);
				TRACE_IMM(imm_i);
				break;
			case OP_ADD:
				TRACE_OPCODE("add");
				TRACE_REG(rd);
				TRACE_REG(rs1);
				TRACE_REG(rs2);
				x[rd] = x[rs1] + x[rs2];
				TRACE_RESULT_REG(rd);
				break;
			case OP_LD:
				TRACE_OPCODE("ld");
				TRACE_REG(rd);
				TRACE_IMM_REG(imm_i, rs1);
				// XXX: Something's fishy here.
				x[rd] = (uint64_t)(x[rs1] + imm_i);
				TRACE_RESULT_REG(rd);
				break;
			case OP_LBU:
				TRACE_OPCODE("lbu");
				TRACE_REG(rd);
				TRACE_IMM_REG(imm_i, rs1);
				break;
			case OP_SB:
				TRACE_OPCODE("sb");
				TRACE_REG(rs2);
				TRACE_REG(rs1);
				TRACE_IMM_REG(imm_s, rs1);
				break;
			case OP_SD:
				TRACE_OPCODE("sd");
				TRACE_REG(rs2);
				TRACE_IMM_REG(imm_s, rs1);
				break;
			default:
				opcode = instruction & 0x7f /* 0b1111111 */;
				switch (opcode) {

				/*
				 * Opcodes with undefined 14..12 go here.
				 */
				case OP_LUI:
					TRACE_OPCODE("lui");
					TRACE_REG(rd);
					TRACE_IMM(imm_u);
					x[rd] = (uint64_t)imm_u << 12;
					TRACE_RESULT_REG(rd);
					break;
				case OP_AUIPC:
					TRACE_OPCODE("auipc");
					TRACE_REG(rd);
					TRACE_IMM(imm_u);
					x[rd] = pc + ((uint64_t)imm_u << 12);
					TRACE_RESULT_REG(rd);
					break;
				case OP_JAL:
					TRACE_OPCODE("jal");
					TRACE_REG(rd);
					TRACE_IMM(imm_j);
					x[rd] = pc + 4;
					// Note that imm_j already includes pc.  It's done that way for compatibility
					// with GNU objdump.
					pc = imm_j;
					TRACE_RESULT_REG(rd);
					continue;
				default:
					crash(42);
					errx(1, "unknown instruction %#010x (14..12=%d 6..2=%#x 1..0=%d)",
					    instruction, PICK(instruction, 3, 12), PICK(instruction, 6, 2), PICK(instruction, 2, 0));
				}
				break;
			}

			pc += 4;
		} else {
			int rd_prime, rd_rs1, rs1_prime, rs1_prime_rd_prime, rs2, rs2_prime;

			opcode = instruction & 0xe003 /* 0b1110000000000011 */;
			rd_rs1 = PICK(instruction, 5, 7);
			rs2 = PICK(instruction, 5, 2);
			rs2_prime = rd_prime = unprime(PICK(instruction, 3, 2));
			rs1_prime_rd_prime = rs1_prime = unprime(PICK(instruction, 3, 7));

			/*
			 * RV64C opcodes go here.
			 */
			switch (opcode) {
			/*
			 * Quadrant 0.
			 */
			case OP_CADDI4SPN:
				TRACE_OPCODE("c.addi4spn");
				TRACE_REG(rd_prime);
				break;
			case OP_CLD:
				TRACE_OPCODE("c.ld");
				TRACE_REG(rd_prime);
				TRACE_IMM_REG(0, rs1_prime);
				x[rd_prime] = *((uint64_t *)x[rs1_prime]);
				// XXX: Offset
				TRACE_RESULT_REG(rd_prime);
				break;

			/*
			 * Quadrant 1.
			 */
			case OP_CNOP_ET_AL:
				if (rd_rs1 == 0) {
					TRACE_OPCODE("c.nop");
					break;
				} else {
					int64_t nzimm;

					TRACE_OPCODE("c.addi");
					TRACE_REG(rd_rs1);
					nzimm = (PICK(instruction, 1, 12) << 5) + PICK(instruction, 5, 2);
					TRACE_IMM(nzimm);
					x[rd_rs1] = x[rd_rs1] + nzimm;
					// XXX: Offset
					TRACE_RESULT_REG(rd_rs1);
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
				break;
			case OP_CLI:
				TRACE_OPCODE("c.li");
				TRACE_REG(rd_rs1);
				// XXX: Offset
				break;
			case OP_CADDI16SP_ET_AL:
				if (rd_rs1 == 2) {
					uint16_t nzimm;

					TRACE_OPCODE("c.addi16sp");
					nzimm = PICK(instruction, 1, 12) << 9 | PICK(instruction, 1, 6) << 4 | PICK(instruction, 1, 5) << 6 | PICK(instruction, 2, 3) << 7 | PICK(instruction, 1, 2) << 5;
					TRACE_IMM(nzimm);
					x[2] = x[2] + nzimm;
					TRACE_RESULT_REG(2); // Implied.
					break;
				} else {
					// c.lui
					break;
				}
			case OP_CJ:
				TRACE_OPCODE("c.j");
				break;
			case OP_CBEQZ:
				TRACE_OPCODE("c.beqz");
				TRACE_REG(rs1_prime_rd_prime);
				// XXX: Offset
				break;
			case OP_CBNEZ:
				TRACE_OPCODE("c.bnez");
				TRACE_REG(rs1_prime_rd_prime);
				// XXX: Offset
				break;
			/*
			 * Quadrant 2.
			 */
			case OP_CJR_ET_AL:
				if (PICK(instruction, 1, 12) == 0) {
					if (rs2 == 0) {
						TRACE_OPCODE("c.jr");
						break;
					} else {
						TRACE_OPCODE("c.mv");
						x[rd_rs1] = x[rs2];
						TRACE_REG(rd_rs1);
						TRACE_REG(rs2);
						TRACE_RESULT_REG(rd_rs1);
						break;
					}
				} else {
					if (rs2 == 0) {
						if (rd_rs1 == 0) {
							TRACE_OPCODE("c.ebreak");
							break;
						} else {
							TRACE_OPCODE("c.jalr");
							TRACE_REG(rd_rs1);
							break;
						}
					} else {
						TRACE_OPCODE("c.add");
						TRACE_REG(rd_rs1);
						TRACE_REG(rs2);
						break;
					}
				}
			case OP_CLDSP:
				TRACE_OPCODE("c.ldsp");
				TRACE_REG(rd_rs1);
				// XXX: Offset, sp
				break;
			case OP_CSDSP:
				TRACE_OPCODE("c.sdsp");
				TRACE_REG(rs2);
				// XXX: Offset, sp
				break;
			default:
				crash(42);
				errx(1, "unknown compressed instruction %#4x (1..0=%d 15..13=%d)",
				    instruction, PICK(instruction, 2, 0), PICK(instruction, 3, 13));
			}

			pc += 2;
		}
	}

	return (0);
}
