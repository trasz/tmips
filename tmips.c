#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define	nitems(x)	(sizeof((x)) / sizeof((x)[0]))

static const char *register_names[32] = {
	"zero", "at",   "v0",   "v1",   "a0",   "a1",   "a2",   "a3",
	"a4",   "a5",   "a6",   "a7",   "t0",   "t1",   "t2",   "t3",
	"s0",   "s1",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
	"t8",   "t9",   "k0",   "k1",   "gp",   "sp",   "s8",   "ra"
};

static const char *op_names[64] = {
	/* 0 */ "spec", "bcond","j",    "jal",  "beq",  "bne",  "blez", "bgtz",
	/* 8 */ "addi", "addiu","slti", "sltiu","andi", "ori",  "xori", "lui",
	/*16 */ "cop0", "cop1", "cop2", "cop3", "beql", "bnel", "blezl","bgtzl",
	/*24 */ "daddi","daddiu","ldl", "ldr",  "op34", "op35", "op36", "op37",
	/*32 */ "lb",   "lh",   "lwl",  "lw",   "lbu",  "lhu",  "lwr",  "lwu",
	/*40 */ "sb",   "sh",   "swl",  "sw",   "sdl",  "sdr",  "swr",  "cache",
	/*48 */ "ll",   "lwc1", "lwc2", "lwc3", "lld",  "ldc1", "ldc2", "ld",
	/*56 */ "sc",   "swc1", "swc2", "swc3", "scd",  "sdc1", "sdc2", "sd"
};

static const char *
register_name(int i)
{

	if (i < 0 || (unsigned long)i >= nitems(register_names))
		return ("?");
	return (register_names[i]);
}

static const char *
op_name(int i)
{

	if (i < 0 || (unsigned long)i >= nitems(op_names))
		return ("?");
	return (op_names[i]);
}

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
#define	FUNCT_SPECIAL_MOVZ	0x0A
#define	FUNCT_SPECIAL_MOVN	0x0B

#define	FUNCT_SPECIAL_SYSCALL	0x0C
#define	FUNCT_SPECIAL_BREAK	0x0D
#define	FUNCT_SPECIAL_SYNC	0x0F

#define	FUNCT_SPECIAL_MFHI	0x10
#define	FUNCT_SPECIAL_MTHI	0x11
#define	FUNCT_SPECIAL_MFLO	0x12
#define	FUNCT_SPECIAL_MTLO	0x13

#define	FUNCT_SPECIAL_MULT	0x18
#define	FUNCT_SPECIAL_MULTU	0x19
#define	FUNCT_SPECIAL_DIV	0x1A
#define	FUNCT_SPECIAL_DIVU	0x1B

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

#define	FUNCT_SPECIAL_TGE	0x30
#define	FUNCT_SPECIAL_TGEU	0x31
#define	FUNCT_SPECIAL_TLT	0x32
#define	FUNCT_SPECIAL_TLTU	0x33

#define	FUNCT_SPECIAL_TEQ	0x34

#define	FUNCT_SPECIAL_TNE	0x36

#define	OPCODE_J	0x02
#define	OPCODE_JAL	0x03

#define	OPCODE_BEQ	0x04
#define	OPCODE_BNE	0x05
#define	OPCODE_BLEZ	0x06
#define	OPCODE_BGTZ	0x07

#define	OPCODE_ADDI	0x08
#define	OPCODE_ADDIU	0x09
#define	OPCODE_SLTI	0x0A
#define	OPCODE_SLTIU	0x0B

#define	OPCODE_ANDI	0x0C
#define	OPCODE_ORI	0x0D
#define	OPCODE_XORI	0x0E
#define	OPCODE_LUI	0x0F

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
#define	OPCODE_SW	0x2B

#define	OPCODE_SWR	0x2E
#define	OPCODE_CACHE	0x2F

#define	OPCODE_LL	0x30
#define	OPCODE_LWC1	0x31
#define	OPCODE_LWC2	0x32
#define	OPCODE_PREF	0x33

#define	OPCODE_LDC1	0x35
#define	OPCODE_LDC2	0x36

#define	OPCODE_SC	0x38
#define	OPCODE_SWC1	0x39
#define	OPCODE_SWC2	0x3A

#define	OPCODE_SDC1	0x3D
#define	OPCODE_SDC2	0x3E

static int
run(int *binary)
{
	// CPU context.
	uint32_t reg[32];

	// Temporaries.
	uint32_t rs, rt, rd, instruction, jump, opcode, funct;
	int16_t immediate;

	for (;;) {
		instruction = *binary;

		opcode = (instruction & (0x3F << 26)) >> 26;

		rs = (instruction & (0x1F << 21)) >> 21;
		rt = (instruction & (0x1F << 16)) >> 16;
		rd = (instruction & (0x1F << 11)) >> 11;

		immediate = (instruction << 16) >> 16;

		jump = instruction & 0x3FFFFFF;

		fprintf(stdout, "%8llx:\t%08x\t%s (%#x), rs %s ($%d), rt %s ($%d), rd %s ($%d), imm %d, addr %#x\n",
		    (unsigned long long)binary, instruction, op_name(opcode), opcode, register_name(rs), rs, register_name(rt), rt, register_name(rd), rd, immediate, jump);

		switch (opcode) {
		case OPCODE_SPECIAL:
			funct = instruction & 0x1F;
			switch (funct) {
			case FUNCT_SPECIAL_SLL:
			case FUNCT_SPECIAL_SRL:
			case FUNCT_SPECIAL_SRA:
			case FUNCT_SPECIAL_SLLV:
			case FUNCT_SPECIAL_SRLV:
			case FUNCT_SPECIAL_SRAV:
			case FUNCT_SPECIAL_JR:
			case FUNCT_SPECIAL_JALR:
			case FUNCT_SPECIAL_MOVZ:
			case FUNCT_SPECIAL_MOVN:
			case FUNCT_SPECIAL_SYSCALL:
			case FUNCT_SPECIAL_BREAK:
			case FUNCT_SPECIAL_SYNC:
			case FUNCT_SPECIAL_MFHI:
			case FUNCT_SPECIAL_MTHI:
			case FUNCT_SPECIAL_MFLO:
			case FUNCT_SPECIAL_MTLO:
			case FUNCT_SPECIAL_MULT:
			case FUNCT_SPECIAL_MULTU:
			case FUNCT_SPECIAL_DIV:
			case FUNCT_SPECIAL_DIVU:
			case FUNCT_SPECIAL_ADD:
			case FUNCT_SPECIAL_ADDU:
			case FUNCT_SPECIAL_SUB:
			case FUNCT_SPECIAL_SUBU:
			case FUNCT_SPECIAL_AND:
			case FUNCT_SPECIAL_OR:
			case FUNCT_SPECIAL_XOR:
			case FUNCT_SPECIAL_NOR:
			case FUNCT_SPECIAL_SLT:
			case FUNCT_SPECIAL_SLTU:
			case FUNCT_SPECIAL_TGE:
			case FUNCT_SPECIAL_TGEU:
			case FUNCT_SPECIAL_TLT:
			case FUNCT_SPECIAL_TLTU:
			case FUNCT_SPECIAL_TEQ:
			case FUNCT_SPECIAL_TNE:
			default:
				break;
			}

		case OPCODE_J:
		case OPCODE_JAL:
		case OPCODE_BEQ:
		case OPCODE_BNE:
		case OPCODE_BLEZ:
		case OPCODE_BGTZ:
		case OPCODE_ADDI:
		case OPCODE_ADDIU:
		case OPCODE_SLTI:
		case OPCODE_SLTIU:
		case OPCODE_ANDI:
		case OPCODE_ORI:
		case OPCODE_XORI:
		case OPCODE_LUI:
		case OPCODE_LB:
		case OPCODE_LH:
		case OPCODE_LWL:
		case OPCODE_LW:
		case OPCODE_LBU:
		case OPCODE_LHU:
		case OPCODE_LWR:
		case OPCODE_SB:
		case OPCODE_SH:
		case OPCODE_SWL:
		case OPCODE_SW:
		case OPCODE_SWR:
		case OPCODE_CACHE:
		case OPCODE_LL:
		case OPCODE_LWC1:
		case OPCODE_LWC2:
		case OPCODE_PREF:
		case OPCODE_LDC1:
		case OPCODE_LDC2:
		case OPCODE_SC:
		case OPCODE_SWC1:
		case OPCODE_SWC2:
		case OPCODE_SDC1:
		case OPCODE_SDC2:
		default:
			//fprintf(stderr, "unknown opcode %x, instruction %llx\n", opcode, instruction);
			break;
		}

		binary++;
	}

	return (0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: tmips base-in-hex binary-path\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	struct stat sb;
	unsigned long long base;
	int *binary;
	char *endptr;
	const char *path;
	int fd, error;

	if (argc != 3)
		usage();

	base = strtoull(argv[1], &endptr, 16);
	if (*endptr != '\0')
		errx(1, "malformed hex number \"%s\"", argv[1]);

	path = argv[2];
	fd = open(path, O_RDONLY);
	if (fd < 0)
		err(1, "%s", path);

	error = fstat(fd, &sb);
	if (error != 0)
		err(1, "cannot stat %s", path);

	binary = mmap((void *)base, sb.st_size, PROT_READ, MAP_FIXED | MAP_EXCL | MAP_SHARED | MAP_PREFAULT_READ, fd, 0);
	if (binary == MAP_FAILED)
		err(1, "cannot map %s at %p", path, (void *)base);

	return (run(binary));
}

