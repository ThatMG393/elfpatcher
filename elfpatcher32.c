// elfpatcher32.c
#include "elfpatcher.h"

#include <linux/elf.h>
#include <sys/stat.h>
#include <sys/endian.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	Elf32_Off offset;
	Elf32_Word size;
} Elf32_LocInfo;

typedef struct {
	Elf32_Addr virtual_address;
	Elf32_Word size;
} Elf32_LocVAddrInfo;

typedef struct {
	Elf32_Dyn entry;
	char* library;
} Elf32_DtNeeded;

char* insert_at_replace_old(char* src, char* ins, int pos) {
	size_t src_length = strlen(src);
	size_t ins_length = strlen(ins);
	size_t cur_val_length = strlen(&src[pos]);

	printf("%i %i %i\n", src_length, ins_length, cur_val_length);

	if (pos > src_length) return NULL;

	char* buf = malloc((src_length - cur_val_length) + ins_length + 1); // +1 for null term

	// copy src[0 -> pos] to buf[0]
	memcpy(buf, src, pos);

	// copy ins to buf[pos]
	memcpy(buf + pos, ins, ins_length);

	// copy the rest
	// copy src[pos + ins_length -> (src_length - cur_val_length)] to buf[src_length + ins_length]
	memcpy(
		buf + pos + ins_length,
		src + pos + cur_val_length,
		src_length - (pos + cur_val_length)
	);

	return buf;
}

// free the returned value as it was allocated using malloc
Elf32_DtNeeded* collect_dt_needed(int fd, Elf32_Ehdr* header, int* dt_needed_size) {
	Elf32_Phdr* program_tables = malloc(header->e_phnum * sizeof(Elf32_Phdr));
	lseek(fd, header->e_phoff, SEEK_SET);
	read(fd, program_tables, header->e_phnum * sizeof(Elf32_Phdr));

	Elf32_LocInfo pt_dynamic_locinfo = { 0, 0 }; 
	for (int i = 0; i < header->e_phnum; ++i) {
		Elf32_Phdr program_table = program_tables[i];
		if (program_table.p_type == PT_DYNAMIC) {
			pt_dynamic_locinfo.offset = program_table.p_offset;
			pt_dynamic_locinfo.size = program_table.p_filesz;
			break;
		}
	}

	if (pt_dynamic_locinfo.size == 0 || pt_dynamic_locinfo.offset == 0) {
		printf("%s\n", "Failed to find PT_DYNAMIC");
		free(program_tables);
		return NULL;
	}

	Elf32_Word dynamic_entries_size = pt_dynamic_locinfo.size / sizeof(Elf32_Dyn);
	Elf32_Dyn* dynamic_entries = malloc(dynamic_entries_size);
	lseek(fd, pt_dynamic_locinfo.offset, SEEK_SET);
	read(fd, dynamic_entries, pt_dynamic_locinfo.size);

	(*dt_needed_size) = 0;

	Elf32_LocVAddrInfo string_table_locinfo = { 0, 0 };
	for (int i = 0; i < dynamic_entries_size; ++i) {
		Elf32_Dyn dynamic_entry = dynamic_entries[i];
        switch (dynamic_entry.d_tag) {
        	case DT_NEEDED:
        		(*dt_needed_size)++;
        		break;
        	case DT_STRTAB:
        		string_table_locinfo.virtual_address = dynamic_entry.d_un.d_val;
        		break;
        	case DT_STRSZ:
        		string_table_locinfo.size = dynamic_entry.d_un.d_val;
        		break;
        }
    }

	if ((*dt_needed_size) == 0) {
		printf("Did not find any DT_NEEDED! Is the ELF a static library?");
		goto fail;
	}

    if (string_table_locinfo.size == 0 || string_table_locinfo.virtual_address == 0) {
    	printf("%s\n", "Failed to locate ELF's string table!");
    	goto fail;
    }

    Elf32_Off string_table_offset = 0;
    for (int i = 0; i < header->e_phnum; ++i) {
    	Elf32_Phdr program_table = program_tables[i];
    	if (program_tables[i].p_type == PT_LOAD
    	 && string_table_locinfo.virtual_address >= program_table.p_paddr
    	 && string_table_locinfo.virtual_address < program_table.p_paddr + program_table.p_memsz) {
    	 	string_table_offset = program_table.p_offset + (string_table_locinfo.virtual_address - program_table.p_vaddr);
    	 	break;
    	}
    }

    if (string_table_offset == 0) {
    	printf("%s\n", "Failed to get ELF's string table file offset!");
    	goto fail;
    }

	// load string table
    char* string_table = malloc(string_table_locinfo.size);
    lseek(fd, string_table_offset, SEEK_SET);
    read(fd, string_table, string_table_locinfo.size);

    Elf32_DtNeeded* dt_neededs = malloc((*dt_needed_size) * sizeof(Elf32_DtNeeded));
    int current_dt_needed_index = 0;
    for (int i = 0; i < dynamic_entries_size; ++i) {
    	Elf32_Dyn dynamic_entry = dynamic_entries[i];
    	if (dynamic_entry.d_tag == DT_NEEDED) {
    		dt_neededs[current_dt_needed_index].entry = dynamic_entry;
    		dt_neededs[current_dt_needed_index].library = strdup(&string_table[dynamic_entry.d_un.d_val]);

    		current_dt_needed_index++;
    	}
    }

    free(program_tables);
    free(dynamic_entries);

	return dt_neededs;

fail:
	free(program_tables);
    free(dynamic_entries);
    return NULL;
}

int write_dt_neededs(int fd, Elf32_Ehdr* header, Elf32_DtNeeded* dt_neededs, int dt_needed_size) {
	Elf32_Phdr* program_tables = malloc(header->e_phnum * sizeof(Elf32_Phdr));
	lseek(fd, header->e_phoff, SEEK_SET);
	read(fd, program_tables, header->e_phnum * sizeof(Elf32_Phdr));

	Elf32_LocInfo pt_dynamic_locinfo = { 0, 0 }; 
	for (int i = 0; i < header->e_phnum; ++i) {
		Elf32_Phdr program_table = program_tables[i];
		if (program_table.p_type == PT_DYNAMIC) {
			pt_dynamic_locinfo.offset = program_table.p_offset;
			pt_dynamic_locinfo.size = program_table.p_filesz;
			break;
		}
	}

	if (pt_dynamic_locinfo.size == 0 || pt_dynamic_locinfo.offset == 0) {
		printf("%s\n", "Failed to find PT_DYNAMIC");
		free(program_tables);
		return FALSE;
	}

	Elf32_Word dynamic_entries_size = pt_dynamic_locinfo.size / sizeof(Elf32_Dyn);
	Elf32_Dyn* dynamic_entries = malloc(dynamic_entries_size);
	lseek(fd, pt_dynamic_locinfo.offset, SEEK_SET);
	read(fd, dynamic_entries, pt_dynamic_locinfo.size);

	Elf32_Dyn* strsz_entry = NULL;

	Elf32_LocVAddrInfo string_table_locinfo = { 0, 0 };
	for (int i = 0; i < dynamic_entries_size; ++i) {
		Elf32_Dyn dynamic_entry = dynamic_entries[i];
        switch (dynamic_entry.d_tag) {
        	case DT_STRTAB:
        		string_table_locinfo.virtual_address = dynamic_entry.d_un.d_val;
        		break;
        	case DT_STRSZ:
        		string_table_locinfo.size = dynamic_entry.d_un.d_val;
        		strsz_entry = &dynamic_entries[i];
        		break;
        }
    }

    if (string_table_locinfo.size == 0 || string_table_locinfo.virtual_address == 0) {
    	printf("%s\n", "Failed to locate ELF's string table!");
    	goto fail;
    }

    printf("strtab size : %i\n", strsz_entry->d_un.d_val);

	Elf32_Off string_table_offset = 0;
    for (int i = 0; i < header->e_phnum; ++i) {
    	Elf32_Phdr program_table = program_tables[i];
    	if (program_tables[i].p_type == PT_LOAD
    	 && string_table_locinfo.virtual_address >= program_table.p_paddr
    	 && string_table_locinfo.virtual_address < program_table.p_paddr + program_table.p_memsz) {
    	 	string_table_offset = program_table.p_offset + (string_table_locinfo.virtual_address - program_table.p_vaddr);
    	 	break;
    	}
    }

    if (string_table_offset == 0) {
    	printf("%s\n", "Failed to get ELF's string table file offset!");
    	goto fail;
    }

	// load string table
	// an array of char*, std::array<char*, string_table_locinfo.size>
    char* string_table = malloc(string_table_locinfo.size);
    lseek(fd, string_table_offset, SEEK_SET);
    read(fd, string_table, string_table_locinfo.size);

	printf("Original String Table:\n");
    for (int i = 0; i < dt_needed_size; ++i) {
    	printf("Original: %s\n", &string_table[dt_neededs[i].entry.d_un.d_val]);
    }

	int current_entry_index = 0;
    for (int i = 0; i < dt_needed_size; ++i) {
    	Elf32_DtNeeded dt_needed = dt_neededs[i];
    	if (current_entry_index < dt_needed_size) {
    		size_t library_len = strlen(dt_needed.library) + 1;	
    		size_t current_len = strlen(&string_table[dt_needed.entry.d_un.d_val]);

			printf("Changing: %s to %s\n", &string_table[dt_needed.entry.d_un.d_val], dt_needed.library);
			printf("String '%s' at index %i\n", &string_table[dt_needed.entry.d_un.d_val], dt_needed.entry.d_un.d_val);
			char* e = &string_table[0];
			char* buf = insert_at_replace_old(&string_table[dt_needed.entry.d_un.d_val], dt_needed.library, 0);
			strcpy(&string_table[dt_needed.entry.d_un.d_val], buf);

            dynamic_entries[i].d_un.d_val = string_table_locinfo.virtual_address + (string_table_locinfo.size - library_len + current_len);

            string_table_locinfo.size += library_len;
            current_entry_index++;
    	}
    }

    strsz_entry->d_un.d_val =  string_table_locinfo.size;

    printf("Modified String Table:\n");
    for (int i = 0; i < dt_needed_size; ++i) {
    	printf("Modified: %s\n", &string_table[dt_neededs[i].entry.d_un.d_val]);
    }

	lseek(fd, string_table_offset, SEEK_SET);
    write(fd, string_table, string_table_locinfo.size);

    lseek(fd, pt_dynamic_locinfo.offset, SEEK_SET);
    write(fd, dynamic_entries, pt_dynamic_locinfo.size);

    free(program_tables);
    free(dynamic_entries);
    free(string_table);

    return TRUE;

fail:
	free(program_tables);
	free(dynamic_entries);
	return FALSE;
}

int patch32(int fd, const char* prefix) {
	if (fd < 0) return FALSE;
	lseek(fd, 0, SEEK_SET);

	Elf32_Ehdr header;
	if (read(fd, &header, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
		printf("Failed to load ELF! Is the path a valid ELF?\n");
		close(fd);
		return FALSE;
	}

	int dt_needed_size = 0;
	Elf32_DtNeeded* dt_neededs = collect_dt_needed(fd, &header, &dt_needed_size);

	if (!dt_neededs || dt_needed_size == 0) {
		close(fd);
		return FALSE;
	}

	for (int i = 0; i < dt_needed_size; ++i) {
		Elf32_DtNeeded* dt_needed = &dt_neededs[i];
		
		char buf[strlen(dt_needed->library) + strlen(prefix) + 1];

		sprintf(buf, "%s%s", prefix, dt_needed->library);

		printf("Replacing '%s' to '%s'\n", dt_needed->library, buf);

		char* buf1 = insert_at_replace_old(dt_needed->library, buf, 0);
		strcpy(dt_needed->library, buf1);
	}

	if (write_dt_neededs(fd, &header, dt_neededs, dt_needed_size) != TRUE) {
		printf("%s\n", "Failed to write modified DT_NEEDED!");

		free(dt_neededs);
		close(fd);
		return FALSE;
	}

	free(dt_neededs);
	close(fd);
	return TRUE;
}

