#include <sys/mman.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <unistd.h>

#define	TRACE
#include "mips.c"
#undef	TRACE
#include "mips.c"

static void __dead2
usage(void)
{
	fprintf(stderr, "usage: tmips [-t] binary-path [binary-args ...]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	Elf *elf;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	const char *path;
	void *addr;
	size_t len, nsections;
	ssize_t nread;
	bool tflag = false;
	int ch, fd, error, i;

	while ((ch = getopt(argc, argv, "t")) != -1) {
		switch (ch) {
		case 't':
			tflag = true;
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	path = argv[0];
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

	fprintf(stderr, "entry point at %#lx\n", ehdr->e_entry);

	phdr = elf64_getphdr(elf);
	if (phdr == NULL)
		errx(1, "elf64_getphdr: %s", elf_errmsg(-1));

	error = elf_getphdrnum(elf, &nsections);
	if (error != 0)
		errx(1, "elf_getphdrnum: %s", elf_errmsg(-1));

	for (i = 0; (size_t)i < nsections; i++) {
		if (phdr[i].p_type != PT_LOAD)
		       continue;

		fprintf(stderr, "section %d: p_offset %ld, p_vaddr %#lx, p_filesz %ld, p_memsz %ld, p_flags %#x\n",
		    i, phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_flags);

		addr = (void *)rounddown2(phdr[i].p_vaddr, PAGE_SIZE);
		len = roundup2(phdr[i].p_memsz + ((char *)phdr[i].p_vaddr - (char *)addr), PAGE_SIZE);

		fprintf(stderr, "section %d: mapping %zd bytes at %p\n", i, len, addr);

		/*
		 * The fact that p_memsz is often different from p_filesz
		 * makes mmap(2) rather non-trivial.
		 */
		addr = mmap(addr, len, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_FIXED | MAP_EXCL | MAP_PRIVATE, -1, 0);
		if (addr == MAP_FAILED)
			err(1, "cannot map %zd bytes at %p", len, addr);

		nread = pread(fd, (void *)phdr[i].p_vaddr, phdr[i].p_filesz, (off_t)phdr[i].p_offset);
		if (nread != (ssize_t)phdr[i].p_filesz)
			err(1, "read");
	}

	close(fd);

	if (tflag)
		return (run_trace((int *)ehdr->e_entry, argc, argv));

	return (run((int *)ehdr->e_entry, argc, argv));
}

