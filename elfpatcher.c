// elfpatcher.c
#include "elfpatcher.h"

#include <stdio.h>
#include <sys/fcntl.h>
#include <string.h>
#include <unistd.h>

int patch_auto(const char* path, const char* prefix) {
	int fd = open(path, O_RDWR);
    if (fd < 0) return FALSE;

    /* 1) read ELF header */
    Elf32_Ehdr eh;
    if (read(fd, &eh, sizeof(eh)) != sizeof(eh)
     || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
     	printf("%s\n", "Failed to load ELF! Is the ELF valid?");
        close(fd);
        return FALSE;
    }

	printf("Loaded ELF with class : %i\n", eh.e_ident[EI_CLASS]);
	switch (eh.e_ident[EI_CLASS]) {
		case ELFCLASS32:
			return patch32(fd, prefix);
		case ELFCLASS64:
			return patch64(fd, prefix);
		default:
			return FALSE;
			
	}
}
