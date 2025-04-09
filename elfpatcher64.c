// elfpatcher32.c
#include "elfpatcher.h"

#include <sys/stat.h>
#include <sys/endian.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    Elf64_Sword tag;
    Elf64_Word  val;
    off_t       val_offset;  // file‑offset of d_un.d_val
} DynEntryInfo64;

static inline uint32_t to_host64(uint32_t x, int swap) {
    return swap ? be64toh(x) : x;
}
static inline uint32_t to_file64(uint32_t x, int swap) {
    return swap ? htobe64(x) : x;
}

/* Read all dynamic entries into an array, stop at DT_NULL */
static DynEntryInfo64* collect_dyn_entries(
	int fd,
	Elf64_Off dyn_off,
	Elf64_Word dyn_size,
	int swap,
	size_t *out_count
) {
    size_t max = dyn_size / sizeof(Elf64_Dyn);
    DynEntryInfo64 *arr = calloc(max, sizeof(*arr));
    if (!arr) return NULL;

    off_t cur = dyn_off;
    size_t cnt = 0;
    while (cur < dyn_off + dyn_size) {
        Elf64_Dyn d;
        if (lseek(fd, cur, SEEK_SET)==-1 ||
            read(fd, &d, sizeof(d))!=sizeof(d)) {
            free(arr);
            return NULL;
        }
        uint32_t tag = to_host64(d.d_tag, swap);
        uint32_t val = to_host64(d.d_un.d_val, swap);

        arr[cnt].tag        = tag;
        arr[cnt].val        = val;
        arr[cnt].val_offset = cur + offsetof(Elf64_Dyn, d_un);

        cnt++;
        if (tag == DT_NULL) break;
        cur += sizeof(d);
    }
    *out_count = cnt;
    return arr;
}

/* Find the PT_DYNAMIC segment in the program headers */
static int find_dynamic_segment(
	int fd,
	Elf64_Ehdr *eh,
	int swap,
	Elf64_Off *out_off,
	Elf64_Word *out_size)
{
    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr ph;
        off_t phoff = eh->e_phoff + i*eh->e_phentsize;
        if (lseek(fd, phoff, SEEK_SET)==-1 ||
            read(fd, &ph, sizeof(ph))!=sizeof(ph)) return FALSE;

        if (swap) {
            ph.p_type   = be32toh(ph.p_type);
            ph.p_offset = be32toh(ph.p_offset);
            ph.p_filesz = be32toh(ph.p_filesz);
        }
        if (ph.p_type == PT_DYNAMIC) {
            *out_off  = ph.p_offset;
            *out_size = ph.p_filesz;
            return TRUE;
        }
    }
    return FALSE;
}

/* Translate a virtual address to a file offset via the PT_LOAD headers */
static off_t vaddr_to_offset(
	int fd,
	Elf64_Ehdr *eh,
	uint32_t vaddr,
	int swap
) {
    for (int i = 0; i < eh->e_phnum; i++) {
        Elf64_Phdr ph;
        off_t phoff = eh->e_phoff + i*eh->e_phentsize;
        if (lseek(fd, phoff, SEEK_SET)==-1 ||
            read(fd, &ph, sizeof(ph))!=sizeof(ph)) return -1;

        if (swap) {
            ph.p_type   = be32toh(ph.p_type);
            ph.p_vaddr  = be32toh(ph.p_vaddr);
            ph.p_memsz  = be32toh(ph.p_memsz);
            ph.p_offset = be32toh(ph.p_offset);
        }

        if (ph.p_type == PT_LOAD &&
            vaddr >= ph.p_vaddr &&
            vaddr <  ph.p_vaddr + ph.p_memsz)
        {
            return ph.p_offset + (vaddr - ph.p_vaddr);
        }
    }
    return -1;
}

int patch64(int fd, const char* prefix) {
    if (fd < 0) return FALSE;

    /* 1) read ELF header */
    Elf64_Ehdr eh;
    if (read(fd, &eh, sizeof(eh)) != sizeof(eh)
     || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return FALSE;
    }
    int swap = (eh.e_ident[EI_DATA] != ELFDATA2LSB);

    /* 2) find PT_DYNAMIC */
    Elf64_Off  dyn_off;
    Elf64_Word dyn_size;
    if (!find_dynamic_segment(fd, &eh, swap, &dyn_off, &dyn_size)) {
        close(fd);
        return FALSE;
    }

    /* 3) collect all dynamic entries */
    size_t      dyn_count;
    DynEntryInfo64 *dyn = collect_dyn_entries(fd, dyn_off, dyn_size, swap, &dyn_count);
    if (!dyn) {
        close(fd);
        return FALSE;
    }

    /* 4) find DT_STRTAB and DT_STRSZ */
    uint32_t strtab_vaddr = 0, strtab_size = 0;
    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn[i].tag == DT_STRTAB) strtab_vaddr = dyn[i].val;
        if (dyn[i].tag == DT_STRSZ ) strtab_size  = dyn[i].val;
    }
    if (!strtab_vaddr || !strtab_size) {
        free(dyn);
        close(fd);
        return FALSE;
    }

    /* 5) compute file offset of .dynstr */
    off_t strtab_off = vaddr_to_offset(fd, &eh, strtab_vaddr, swap);
    if (strtab_off < 0) {
        free(dyn);
        close(fd);
        return FALSE;
    }

    /* 6) decide if we can patch in-place or must grow */
    size_t total_extra = 0;
    for (size_t i = 0; i < dyn_count; i++) {
        if (dyn[i].tag != DT_NEEDED) continue;
        off_t name_off = strtab_off + dyn[i].val;
        lseek(fd, name_off, SEEK_SET);
        char orig[256]; ssize_t len = 0;
        while (len < (ssize_t)sizeof(orig)-1 &&
               read(fd, orig+len, 1)==1 && orig[len]!='\0') len++;
        orig[len] = '\0';

        size_t newlen = strlen(prefix) + len + 1;
        if (newlen > (size_t)(len+1)) total_extra += (newlen - (len+1));
    }

    if (total_extra == 0) {
        /* All fit in-place */
        for (size_t i = 0; i < dyn_count; i++) {
            if (dyn[i].tag != DT_NEEDED) continue;
            off_t name_off = strtab_off + dyn[i].val;
            lseek(fd, name_off, SEEK_SET);
            char orig[256]; ssize_t len = 0;
            while (len < (ssize_t)sizeof(orig)-1 &&
                   read(fd, orig+len, 1)==1 && orig[len]!='\0') len++;
            orig[len] = '\0';

            char buf[512];
            snprintf(buf, sizeof(buf), "%s%s", prefix, orig);
            size_t buflen = strlen(buf)+1;

            lseek(fd, name_off, SEEK_SET);
            write(fd, buf, buflen);
            if (buflen < (size_t)(len+1)) {
                size_t pad = (len+1) - buflen;
                static const char zeros[16] = {0};
                while (pad) {
                    size_t w = pad>sizeof(zeros)?sizeof(zeros):pad;
                    write(fd, zeros, w);
                    pad -= w;
                }
            }
        }
    } else {
        /* Must grow .dynstr at EOF */
        char *old = malloc(strtab_size);
        lseek(fd, strtab_off, SEEK_SET);
        read(fd, old, strtab_size);

        size_t new_size = strtab_size + total_extra;
        char *newtab  = malloc(new_size);
        memcpy(newtab, old, strtab_size);
        size_t write_ptr = strtab_size;

        for (size_t i = 0; i < dyn_count; i++) {
            if (dyn[i].tag != DT_NEEDED) continue;
            char *orig = old + dyn[i].val;
            size_t orig_len = strlen(orig)+1;

            char buf[512];
            snprintf(buf, sizeof(buf), "%s%s", prefix, orig);
            size_t buflen = strlen(buf)+1;

            if (buflen <= orig_len) {
                memcpy(newtab + dyn[i].val, buf, buflen);
                if (buflen < orig_len)
                    memset(newtab + dyn[i].val + buflen, 0, orig_len - buflen);
            } else {
                memcpy(newtab + write_ptr, buf, buflen);
                dyn[i].val = write_ptr;
                write_ptr += buflen;
            }
        }
        free(old);

        off_t eof = lseek(fd, 0, SEEK_END);
        write(fd, newtab, new_size);
        free(newtab);

        uint32_t new_strtab_vaddr = strtab_vaddr + (eof - strtab_off);

        for (size_t i = 0; i < dyn_count; i++) {
            uint32_t newval = dyn[i].val;
            if (dyn[i].tag == DT_STRTAB) newval = new_strtab_vaddr;
            if (dyn[i].tag == DT_STRSZ ) newval = new_size;

            uint32_t on_disk = to_file64(newval, swap);
            lseek(fd, dyn[i].val_offset, SEEK_SET);
            write(fd, &on_disk, sizeof(on_disk));
        }
    }

    free(dyn);
    close(fd);
    return TRUE;
}

