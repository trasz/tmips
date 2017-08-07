#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define	nitems(x)	(sizeof((x)) / sizeof((x)[0]))

#define	TRACE_OPCODE(STR)	do {								\
		fprintf(stdout, "\n%8llx:\t%08x\t%-7s ",					\
		    (unsigned long long)pc, ntohl(instruction), STR);			\
	} while (0)

#define	TRACE_REG(REG)	do {									\
		if (register_name(REG) != NULL)							\
			fprintf(stdout, "%s,", register_name(REG));				\
		else										\
			fprintf(stdout, "$%d,", REG);						\
	} while (0)

#define	TRACE_RD()	TRACE_REG(rd)
#define	TRACE_RS()	TRACE_REG(rs)
#define	TRACE_RT()	TRACE_REG(rt)

#define	TRACE_IMM_REG(REG)	do {								\
		if (register_name(REG) != NULL)							\
			fprintf(stdout, "%d(%s)", immediate, register_name(REG));		\
		else										\
			fprintf(stdout, "%d($%d)", immediate, REG);				\
	} while (0)

#define	TRACE_IMM_RS()	TRACE_IMM_REG(rs)

#define	TRACE_IMM()	do {									\
		fprintf(stdout, "%d", immediate);						\
	} while (0)

#define	TRACE_JUMP()	do {									\
		fprintf(stdout, "%x", jump);							\
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

	if (i < 0 || (unsigned long)i >= nitems(register_names))
		return (NULL);
	return (register_names[i]);
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
#define	FUNCT_SPECIAL_DSRA32	0x3F

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

#define	OPCODE_BEQL	0x14

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
run(int *pc)
{
	// CPU context.
	uint32_t reg[32];

	// Temporaries.
	uint32_t rs, rt, rd, instruction, jump, opcode, funct;
	uint16_t uimmediate;
	int16_t immediate;

	for (;;) {
		instruction = *pc;

		opcode = (instruction & (0x3F << 26)) >> 26;

		rs = (instruction & (0x1F << 21)) >> 21;
		rt = (instruction & (0x1F << 16)) >> 16;
		rd = (instruction & (0x1F << 11)) >> 11;

		immediate = (instruction << 16) >> 16;

		jump = instruction & 0x3FFFFFF;

#if 0
		fprintf(stdout, "%8llx:\t%08x\t%s (%#x), rs %s ($%d), rt %s ($%d), rd %s ($%d), imm %d, addr %#x\n",
		    (unsigned long long)pc, instruction, op_name(opcode), opcode, register_name(rs), rs, register_name(rt), rt, register_name(rd), rd, immediate, jump);
#endif

		switch (opcode) {
		case OPCODE_SPECIAL:
			funct = instruction & 0x3F;

			switch (funct) {
			case FUNCT_SPECIAL_SLL:
				TRACE_OPCODE("sll");
				TRACE_RD();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_SRL:
				TRACE_OPCODE("srl");
				TRACE_RD();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_SRA:
				TRACE_OPCODE("sra");
				TRACE_RD();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_SLLV:
				TRACE_OPCODE("sllv");
				TRACE_RD();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_SRLV:
				TRACE_OPCODE("srlv");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				break;
			case FUNCT_SPECIAL_SRAV:
				TRACE_OPCODE("srav");
				TRACE_RD();
				TRACE_RT();
				TRACE_RS();
				break;
			case FUNCT_SPECIAL_JR:
				TRACE_OPCODE("jr");
				TRACE_RS();
				break;
			case FUNCT_SPECIAL_JALR:
				TRACE_OPCODE("jalr");
				break;
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
			case FUNCT_SPECIAL_SYSCALL:
				TRACE_OPCODE("syscall");
				break;
			case FUNCT_SPECIAL_BREAK:
				TRACE_OPCODE("break");
				break;
			case FUNCT_SPECIAL_SYNC:
				TRACE_OPCODE("sync");
				break;
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
				break;
			case FUNCT_SPECIAL_SUB:
				TRACE_OPCODE("sub");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_SUBU:
				TRACE_OPCODE("subu");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_AND:
				TRACE_OPCODE("and");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				reg[rd] = reg[rs] & reg[rt];
				break;
			case FUNCT_SPECIAL_OR:
				TRACE_OPCODE("or");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_XOR:
				TRACE_OPCODE("xor");
				break;
			case FUNCT_SPECIAL_NOR:
				TRACE_OPCODE("nor");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_SLT:
				TRACE_OPCODE("slt");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
			case FUNCT_SPECIAL_SLTU:
				TRACE_OPCODE("sltu");
				TRACE_RD();
				TRACE_RS();
				TRACE_RT();
				break;
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
			case FUNCT_SPECIAL_DSRA32:
				TRACE_OPCODE("dsra32");
				TRACE_RD();
				TRACE_RT();
				TRACE_IMM();
				break;
			default:
				TRACE_OPCODE("SPECIAL");
				fprintf(stdout, "(unknown opcode %x, function %x)", opcode, funct);
				break;
			}
			break;
		case OPCODE_J:
			TRACE_OPCODE("j");
			TRACE_JUMP();
			break;
		case OPCODE_JAL:
			TRACE_OPCODE("jal");
			TRACE_RS();
			break;
		case OPCODE_BEQ:
			TRACE_OPCODE("beq");
beq:
			TRACE_RS();
			TRACE_RT();
			TRACE_JUMP();
			if (reg[rs] != reg[rt])
				break;
			//pc += jump << 2;
			break;
		case OPCODE_BNE:
			TRACE_OPCODE("bne");
			TRACE_RS();
			TRACE_RT();
			break;
		case OPCODE_BLEZ:
			TRACE_OPCODE("blez");
			TRACE_RS();
			TRACE_IMM();
			break;
		case OPCODE_BGTZ:
			TRACE_OPCODE("bgtz");
			TRACE_RS();
			break;
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
			reg[rt] = reg[rs] + immediate;
			break;
		case OPCODE_SLTI:
			TRACE_OPCODE("slti");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			break;
		case OPCODE_SLTIU:
			TRACE_OPCODE("sltiu");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			break;
		case OPCODE_ANDI:
			TRACE_OPCODE("andi");
			TRACE_RT();
			TRACE_RS();
			TRACE_IMM();
			uimmediate = immediate;
			uimmediate = (immediate << 16) >> 16;
			reg[rt] = reg[rs] & uimmediate;
			break;
		case OPCODE_ORI:
			TRACE_OPCODE("ori");
			TRACE_RD();
			TRACE_RS();
			break;
		case OPCODE_XORI:
			TRACE_OPCODE("xori");
			TRACE_RD();
			TRACE_RS();
			TRACE_RT();
			break;
		case OPCODE_LUI:
			TRACE_OPCODE("lui");
			TRACE_RT();
			break;
		case OPCODE_BEQL:
			TRACE_OPCODE("beql");
			goto beq;
		case OPCODE_LB:
			TRACE_OPCODE("lb");
			TRACE_RT();
			break;
		case OPCODE_LH:
			TRACE_OPCODE("lh");
			break;
		case OPCODE_LWL:
			TRACE_OPCODE("lwl");
			TRACE_RT();
			break;
		case OPCODE_LW:
			TRACE_OPCODE("lw");
			TRACE_RT();
			TRACE_IMM();
			break;
		case OPCODE_LBU:
			TRACE_OPCODE("lbu");
			TRACE_RT();
			TRACE_IMM_RS();
			break;
		case OPCODE_LHU:
			TRACE_OPCODE("lhu");
			TRACE_RT();
			TRACE_IMM();
			break;
		case OPCODE_LWR:
			TRACE_OPCODE("lwr");
			TRACE_RT();
			break;
		case OPCODE_SB:
			TRACE_OPCODE("sb");
			TRACE_RT();
			TRACE_IMM();
			break;
		case OPCODE_SH:
			TRACE_OPCODE("sh");
			TRACE_RT();
			break;
		case OPCODE_SWL:
			TRACE_OPCODE("swl");
			TRACE_RT();
			break;
		case OPCODE_SW:
			TRACE_OPCODE("sw");
			TRACE_RT();
			TRACE_IMM();
			break;
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
		default:
			TRACE_OPCODE("UNKNOWN");
			//fprintf(stderr, "unknown opcode %x, instruction %llx\n", opcode, instruction);
			break;
		}

		pc++;
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

