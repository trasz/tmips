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

static int
run(int *binary)
{
	// CPU context.
	uint32_t reg[32], hi, lo;

	// Temporaries.
	uint32_t rs, rt, rd, instruction, immediate, jump, opcode;

	for (;;) {
		instruction = *binary;

		opcode = (instruction & (0x3F << 26)) >> 26;

		rs = (instruction & (0x1F << 21)) >> 21;
		rt = (instruction & (0x1F << 16)) >> 16;
		rd = (instruction & (0x1F << 11)) >> 11;

		immediate = instruction & 0xFF;

		jump = instruction & 0x3FFFFFF;

		fprintf(stdout, "%8llx:\t%08x\t%s (%#x), rs %s ($%d), rt %s ($%d), rd %s ($%d), imm %u, addr %#x\n",
		    (unsigned long long)binary, instruction, op_name(opcode), opcode, register_name(rs), rs, register_name(rt), rt, register_name(rd), rd, immediate, jump);
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

