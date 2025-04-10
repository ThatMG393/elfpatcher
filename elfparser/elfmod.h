/**
 * elfmod.h - In-memory ELF manipulation library
 * 
 * This library focuses on modifying DT_NEEDED entries in ELF files.
 */

#ifndef ELFMOD_H
#define ELFMOD_H

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    // ELF file metadata
    char* filename;
    void* mapped_data;
    size_t file_size;
    
    // ELF header pointers for 32/64 bit
    union {
        Elf32_Ehdr* ehdr32;
        Elf64_Ehdr* ehdr64;
    };
    
    // Program headers
    union {
        Elf32_Phdr* phdr32;
        Elf64_Phdr* phdr64;
    };
    
    // Section headers
    union {
        Elf32_Shdr* shdr32;
        Elf64_Shdr* shdr64;
    };
    
    // Dynamic section 
    size_t dyn_section_idx;
    size_t dyn_count;
    union {
        Elf32_Dyn* dyn32;
        Elf64_Dyn* dyn64;
    };
    
    // String tables
    char* dynstr;
    size_t dynstr_size;
    size_t dynstr_idx;
    
    // ELF identification
    unsigned char* e_ident;
    
    // ELF properties
    bool is_64bit;
    size_t section_count;
    size_t program_header_count;
    
    // Section header string table
    char* shstrtab;
    
    // For expanded file handling
    bool is_expanded;
    size_t original_size;
    void* extended_data;
    size_t extended_size;
} ElfContext;

/**
 * Load an ELF file into memory
 *
 * @param filename Path to the ELF file
 * @param ctx Pointer to an ElfContext structure that will be initialized
 * @return 0 on success, non-zero error code on failure
 */
int elf_load(const char* filename, ElfContext* ctx);

/**
 * Write the modified ELF file back to disk
 *
 * @param ctx Pointer to an initialized ElfContext
 * @param output_filename Path where the modified ELF will be saved
 * @return 0 on success, non-zero error code on failure
 */
int elf_save(ElfContext* ctx, const char* output_filename);

/**
 * Free resources associated with an ELF context
 *
 * @param ctx Pointer to an initialized ElfContext
 */
void elf_close(ElfContext* ctx);

/**
 * Get a list of all DT_NEEDED entries
 *
 * @param ctx Pointer to an initialized ElfContext
 * @param count Pointer to store the number of entries found
 * @return Array of strings (must be freed by caller), NULL on error
 */
char** elf_get_needed_libs(ElfContext* ctx, size_t* count);

/**
 * Replace a DT_NEEDED entry with a new library name
 *
 * @param ctx Pointer to an initialized ElfContext
 * @param old_lib The library name to replace
 * @param new_lib The new library name
 * @return 0 on success, non-zero error code on failure
 */
int elf_replace_needed_lib(ElfContext* ctx, const char* old_lib, const char* new_lib);

/**
 * Get error message for the last error
 *
 * @return String describing the last error
 */
const char* elf_get_error(void);

#endif /* ELFMOD_H */
