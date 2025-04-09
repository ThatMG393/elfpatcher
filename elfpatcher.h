// elfpatcher.h
#pragma once

#include <linux/elf.h>
#include <stddef.h>
#include <stdint.h>

#define TRUE  1
#define FALSE 0

/**
 * Patch all DT_NEEDED entries by prefixing them with 'prefix'.
 *   - In‑place if the new string fits.
 *   - Otherwise grows .dynstr at EOF and updates DT_STRTAB/DT_STRSZ.
 *
 * @param path   path to the ELF file (must be writable)
 * @param prefix string to prepend to each DT_NEEDED name
 * @return TRUE on success, FALSE on error
 */
int patch_auto(const char* path, const char* prefix);

// same as patch_auto but architecture implementation
int patch32(int fd, const char* prefix);
int patch64(int fd, const char* prefix);

