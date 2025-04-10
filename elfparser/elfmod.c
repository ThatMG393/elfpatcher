/**
 * elfmod.c - Implementation of the ELF manipulation library
 * Focused on modifying DT_NEEDED entries
 */

#include "elfmod.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// Error handling
static char error_buffer[256] = {0};

const char* elf_get_error(void) {
    return error_buffer;
}

static void set_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(error_buffer, sizeof(error_buffer), format, args);
    va_end(args);
}

int elf_load(const char* filename, ElfContext* ctx) {
    if (!filename || !ctx) {
        set_error("Invalid parameters");
        return -1;
    }
    
    // Initialize context
    memset(ctx, 0, sizeof(ElfContext));
    
    // Open the file
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        set_error("Failed to open file: %s", strerror(errno));
        return -1;
    }
    
    // Get file size
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        set_error("Failed to get file stats: %s", strerror(errno));
        return -1;
    }
    
    ctx->file_size = st.st_size;
    ctx->original_size = st.st_size;
    
    // Map file into memory
    ctx->mapped_data = mmap(NULL, ctx->file_size, PROT_READ | PROT_WRITE, 
                           MAP_PRIVATE, fd, 0);
    if (ctx->mapped_data == MAP_FAILED) {
        close(fd);
        set_error("Failed to map file: %s", strerror(errno));
        return -1;
    }
    
    // Close the file - we've mapped it to memory
    close(fd);
    
    // Store filename
    ctx->filename = strdup(filename);
    if (!ctx->filename) {
        munmap(ctx->mapped_data, ctx->file_size);
        set_error("Memory allocation failed");
        return -1;
    }
    
    // Check ELF magic number
    ctx->e_ident = (unsigned char*)ctx->mapped_data;
    if (ctx->e_ident[EI_MAG0] != ELFMAG0 || ctx->e_ident[EI_MAG1] != ELFMAG1 ||
        ctx->e_ident[EI_MAG2] != ELFMAG2 || ctx->e_ident[EI_MAG3] != ELFMAG3) {
        elf_close(ctx);
        set_error("Not a valid ELF file");
        return -1;
    }
    
    // Determine if it's 32 or 64 bit
    ctx->is_64bit = (ctx->e_ident[EI_CLASS] == ELFCLASS64);
    
    // Set up header pointers
    if (ctx->is_64bit) {
        ctx->ehdr64 = (Elf64_Ehdr*)ctx->mapped_data;
        ctx->phdr64 = (Elf64_Phdr*)((uint8_t*)ctx->mapped_data + ctx->ehdr64->e_phoff);
        ctx->shdr64 = (Elf64_Shdr*)((uint8_t*)ctx->mapped_data + ctx->ehdr64->e_shoff);
        ctx->section_count = ctx->ehdr64->e_shnum;
        ctx->program_header_count = ctx->ehdr64->e_phnum;
        
        // Get section header string table
        if (ctx->ehdr64->e_shstrndx != SHN_UNDEF) {
            Elf64_Shdr* shstrtab_hdr = &ctx->shdr64[ctx->ehdr64->e_shstrndx];
            ctx->shstrtab = (char*)((uint8_t*)ctx->mapped_data + shstrtab_hdr->sh_offset);
        }
    } else {
        ctx->ehdr32 = (Elf32_Ehdr*)ctx->mapped_data;
        ctx->phdr32 = (Elf32_Phdr*)((uint8_t*)ctx->mapped_data + ctx->ehdr32->e_phoff);
        ctx->shdr32 = (Elf32_Shdr*)((uint8_t*)ctx->mapped_data + ctx->ehdr32->e_shoff);
        ctx->section_count = ctx->ehdr32->e_shnum;
        ctx->program_header_count = ctx->ehdr32->e_phnum;
        
        // Get section header string table
        if (ctx->ehdr32->e_shstrndx != SHN_UNDEF) {
            Elf32_Shdr* shstrtab_hdr = &ctx->shdr32[ctx->ehdr32->e_shstrndx];
            ctx->shstrtab = (char*)((uint8_t*)ctx->mapped_data + shstrtab_hdr->sh_offset);
        }
    }
    
    // Find dynamic section and dynamic string table
    for (size_t i = 0; i < ctx->section_count; i++) {
        const char* name;
        uint32_t type;
        uint64_t offset, size;
        
        if (ctx->is_64bit) {
            name = ctx->shstrtab + ctx->shdr64[i].sh_name;
            type = ctx->shdr64[i].sh_type;
            offset = ctx->shdr64[i].sh_offset;
            size = ctx->shdr64[i].sh_size;
        } else {
            name = ctx->shstrtab + ctx->shdr32[i].sh_name;
            type = ctx->shdr32[i].sh_type;
            offset = ctx->shdr32[i].sh_offset;
            size = ctx->shdr32[i].sh_size;
        }
        
        // Find dynamic section
        if (type == SHT_DYNAMIC) {
            if (ctx->is_64bit) {
                ctx->dyn64 = (Elf64_Dyn*)((uint8_t*)ctx->mapped_data + offset);
                ctx->dyn_count = size / sizeof(Elf64_Dyn);
                ctx->dyn_section_idx = i;
            } else {
                ctx->dyn32 = (Elf32_Dyn*)((uint8_t*)ctx->mapped_data + offset);
                ctx->dyn_count = size / sizeof(Elf32_Dyn);
                ctx->dyn_section_idx = i;
            }
        }
        
        // Find dynamic string table
        if (type == SHT_STRTAB && strcmp(name, ".dynstr") == 0) {
            ctx->dynstr = (char*)((uint8_t*)ctx->mapped_data + offset);
            ctx->dynstr_size = size;
            ctx->dynstr_idx = i;
        }
    }
    
    if (!ctx->dynstr || (!ctx->dyn32 && !ctx->dyn64) || ctx->dyn_count == 0) {
        elf_close(ctx);
        set_error("Could not find dynamic section or dynamic string table");
        return -1;
    }
    
    return 0;
}

void elf_close(ElfContext* ctx) {
    if (!ctx) return;
    
    if (ctx->is_expanded && ctx->extended_data) {
        free(ctx->extended_data);
    } else if (ctx->mapped_data && ctx->file_size > 0) {
        munmap(ctx->mapped_data, ctx->file_size);
    }
    
    if (ctx->filename) {
        free(ctx->filename);
    }
    
    memset(ctx, 0, sizeof(ElfContext));
}

char** elf_get_needed_libs(ElfContext* ctx, size_t* count) {
    if (!ctx || !count) {
        set_error("Invalid parameters");
        return NULL;
    }
    
    *count = 0;
    
    // First, count the number of DT_NEEDED entries
    size_t needed_count = 0;
    
    if (ctx->is_64bit) {
        for (size_t i = 0; i < ctx->dyn_count; i++) {
            if (ctx->dyn64[i].d_tag == DT_NEEDED) {
                needed_count++;
            } else if (ctx->dyn64[i].d_tag == DT_NULL) {
                // End of dynamic section
                break;
            }
        }
    } else {
        for (size_t i = 0; i < ctx->dyn_count; i++) {
            if (ctx->dyn32[i].d_tag == DT_NEEDED) {
                needed_count++;
            } else if (ctx->dyn32[i].d_tag == DT_NULL) {
                // End of dynamic section
                break;
            }
        }
    }
    
    if (needed_count == 0) {
        return NULL; // No needed libraries
    }
    
    // Allocate array for the strings
    char** needed_libs = malloc(sizeof(char*) * needed_count);
    if (!needed_libs) {
        set_error("Memory allocation failed");
        return NULL;
    }
    
    // Fill the array with strings
    size_t idx = 0;
    
    if (ctx->is_64bit) {
        for (size_t i = 0; i < ctx->dyn_count && idx < needed_count; i++) {
            if (ctx->dyn64[i].d_tag == DT_NEEDED) {
                const char* lib_name = ctx->dynstr + ctx->dyn64[i].d_un.d_val;
                needed_libs[idx] = strdup(lib_name);
                if (!needed_libs[idx]) {
                    // Clean up on error
                    for (size_t j = 0; j < idx; j++) {
                        free(needed_libs[j]);
                    }
                    free(needed_libs);
                    set_error("Memory allocation failed");
                    return NULL;
                }
                idx++;
            } else if (ctx->dyn64[i].d_tag == DT_NULL) {
                break;
            }
        }
    } else {
        for (size_t i = 0; i < ctx->dyn_count && idx < needed_count; i++) {
            if (ctx->dyn32[i].d_tag == DT_NEEDED) {
                const char* lib_name = ctx->dynstr + ctx->dyn32[i].d_un.d_val;
                needed_libs[idx] = strdup(lib_name);
                if (!needed_libs[idx]) {
                    // Clean up on error
                    for (size_t j = 0; j < idx; j++) {
                        free(needed_libs[j]);
                    }
                    free(needed_libs);
                    set_error("Memory allocation failed");
                    return NULL;
                }
                idx++;
            } else if (ctx->dyn32[i].d_tag == DT_NULL) {
                break;
            }
        }
    }
    
    *count = needed_count;
    return needed_libs;
}

// Helper function to relocate all pointers after file expansion
static void relocate_pointers(ElfContext* ctx, void* new_data) {
    uint64_t base_offset = (uint64_t)ctx->mapped_data;
    uint64_t new_base = (uint64_t)new_data;
    
    // Update ELF header pointers
    if (ctx->is_64bit) {
        ctx->ehdr64 = (Elf64_Ehdr*)new_data;
        // Adjust program headers if they exist
        if (ctx->ehdr64->e_phnum > 0) {
            ctx->phdr64 = (Elf64_Phdr*)(new_base + ctx->ehdr64->e_phoff);
        }
        // Adjust section headers
        ctx->shdr64 = (Elf64_Shdr*)(new_base + ctx->ehdr64->e_shoff);
        
        // Update dynamic section pointer
        if (ctx->dyn64) {
            uint64_t dyn_offset = (uint64_t)ctx->dyn64 - base_offset;
            ctx->dyn64 = (Elf64_Dyn*)(new_base + dyn_offset);
        }
    } else {
        ctx->ehdr32 = (Elf32_Ehdr*)new_data;
        // Adjust program headers if they exist
        if (ctx->ehdr32->e_phnum > 0) {
            ctx->phdr32 = (Elf32_Phdr*)(new_base + ctx->ehdr32->e_phoff);
        }
        // Adjust section headers
        ctx->shdr32 = (Elf32_Shdr*)(new_base + ctx->ehdr32->e_shoff);
        
        // Update dynamic section pointer
        if (ctx->dyn32) {
            uint64_t dyn_offset = (uint64_t)ctx->dyn32 - base_offset;
            ctx->dyn32 = (Elf32_Dyn*)(new_base + dyn_offset);
        }
    }
    
    // Update string table pointers
    if (ctx->shstrtab) {
        uint64_t shstrtab_offset = (uint64_t)ctx->shstrtab - base_offset;
        ctx->shstrtab = (char*)(new_base + shstrtab_offset);
    }
    
    if (ctx->dynstr) {
        uint64_t dynstr_offset = (uint64_t)ctx->dynstr - base_offset;
        ctx->dynstr = (char*)(new_base + dynstr_offset);
    }
}

// Helper function to expand the dynamic string table if needed
static int expand_dynstr(ElfContext* ctx, size_t additional_size) {
    if (!ctx || additional_size == 0) {
        return -1;
    }
    
    // Get current dynstr section info
    uint64_t dynstr_offset, dynstr_size;
    uint64_t dynstr_addr = 0;
    
    if (ctx->is_64bit) {
        dynstr_offset = ctx->shdr64[ctx->dynstr_idx].sh_offset;
        dynstr_size = ctx->shdr64[ctx->dynstr_idx].sh_size;
        dynstr_addr = ctx->shdr64[ctx->dynstr_idx].sh_addr;
    } else {
        dynstr_offset = ctx->shdr32[ctx->dynstr_idx].sh_offset;
        dynstr_size = ctx->shdr32[ctx->dynstr_idx].sh_size;
        dynstr_addr = ctx->shdr32[ctx->dynstr_idx].sh_addr;
    }
    
    // Approach: We will add the new string at the end of the file,
    // then update the dynstr section header to include this area
    
    // Calculate new file size with padding for alignment
    size_t padding = 16 - (ctx->file_size % 16);
    if (padding == 16) padding = 0;
    size_t new_size = ctx->file_size + padding + additional_size;
    
    // Allocate memory for the expanded file
    void* new_data = calloc(1, new_size);
    if (!new_data) {
        set_error("Memory allocation failed for expanded file");
        return -1;
    }
    
    // Copy the original file content
    memcpy(new_data, ctx->is_expanded ? ctx->extended_data : ctx->mapped_data, ctx->file_size);
    
    // Update context to use the expanded memory
    if (!ctx->is_expanded) {
        // First expansion, keep original mmap for cleanup
        ctx->is_expanded = true;
        ctx->extended_data = new_data;
        ctx->extended_size = new_size;
    } else {
        // Already expanded, free previous extended data
        free(ctx->extended_data);
        ctx->extended_data = new_data;
        ctx->extended_size = new_size;
    }
    
    // Update all pointers to reference the new memory
    relocate_pointers(ctx, new_data);
    
    // Update the dynstr section to include the appended data
    if (ctx->is_64bit) {
        // Store the original end of the dynstr section as the offset where we'll put our new string
        uint64_t new_string_offset = dynstr_offset + dynstr_size;
        
        // Update the size of the dynstr section to include the new space
        ctx->shdr64[ctx->dynstr_idx].sh_size += additional_size;
        
        // Return the updated file size
        ctx->file_size = new_size;
        ctx->dynstr_size += additional_size;
        
        return 0;
    } else {
        // Store the original end of the dynstr section as the offset where we'll put our new string
        uint32_t new_string_offset = dynstr_offset + dynstr_size;
        
        // Update the size of the dynstr section to include the new space
        ctx->shdr32[ctx->dynstr_idx].sh_size += additional_size;
        
        // Return the updated file size
        ctx->file_size = new_size;
        ctx->dynstr_size += additional_size;
        
        return 0;
    }
}

int elf_replace_needed_lib(ElfContext* ctx, const char* old_lib, const char* new_lib) {
    if (!ctx || !old_lib || !new_lib) {
        set_error("Invalid parameters");
        return -1;
    }
    
    // Find the DT_NEEDED entry with the old_lib name
    bool found = false;
    size_t dynamic_index = 0;
    uint64_t string_offset = 0;
    
    if (ctx->is_64bit) {
        for (size_t i = 0; i < ctx->dyn_count; i++) {
            if (ctx->dyn64[i].d_tag == DT_NEEDED) {
                uint64_t str_idx = ctx->dyn64[i].d_un.d_val;
                if (str_idx < ctx->dynstr_size) {  // Sanity check
                    const char* lib_name = ctx->dynstr + str_idx;
                    if (strcmp(lib_name, old_lib) == 0) {
                        found = true;
                        dynamic_index = i;
                        string_offset = str_idx;
                        break;
                    }
                }
            } else if (ctx->dyn64[i].d_tag == DT_NULL) {
                // End of dynamic section
                break;
            }
        }
    } else {
        for (size_t i = 0; i < ctx->dyn_count; i++) {
            if (ctx->dyn32[i].d_tag == DT_NEEDED) {
                uint32_t str_idx = ctx->dyn32[i].d_un.d_val;
                if (str_idx < ctx->dynstr_size) {  // Sanity check
                    const char* lib_name = ctx->dynstr + str_idx;
                    if (strcmp(lib_name, old_lib) == 0) {
                        found = true;
                        dynamic_index = i;
                        string_offset = str_idx;
                        break;
                    }
                }
            } else if (ctx->dyn32[i].d_tag == DT_NULL) {
                // End of dynamic section
                break;
            }
        }
    }
    
    if (!found) {
        set_error("Library not found in DT_NEEDED: %s", old_lib);
        return -1;
    }
    
    size_t old_len = strlen(old_lib);
    size_t new_len = strlen(new_lib);
    
    // Case 1: New string fits in the old string space (including NULL terminator)
    if (new_len <= old_len) {
        // Just replace the string in place
        strcpy(ctx->dynstr + string_offset, new_lib);
        return 0;
    }
    
    // Case 2: New string is longer, need to add it to the end of the dynstr table
    
    // First, expand the file to make room for the new string
    if (expand_dynstr(ctx, new_len + 1) != 0) {
        set_error("Failed to expand dynamic string table");
        return -1;
    }
    
    // Calculate the offset for the new string (at the end of the original dynstr section)
    uint64_t dynstr_offset;
    if (ctx->is_64bit) {
        dynstr_offset = ctx->shdr64[ctx->dynstr_idx].sh_offset;
    } else {
        dynstr_offset = ctx->shdr32[ctx->dynstr_idx].sh_offset;
    }
    
    // Original dynstr size before expansion
    uint64_t orig_dynstr_size = ctx->dynstr_size - (new_len + 1);
    
    // Add the new string at the end of the original dynstr
    uint64_t new_offset = orig_dynstr_size;
    
    // Ensure we're writing within bounds
    if (new_offset + new_len >= ctx->dynstr_size) {
        set_error("String offset calculation error");
        return -1;
    }
    
    // Copy the new string to the end of the dynstr section
    strcpy(ctx->dynstr + new_offset, new_lib);
    
    // Update the DT_NEEDED entry to point to the new string
    if (ctx->is_64bit) {
        ctx->dyn64[dynamic_index].d_un.d_val = new_offset;
    } else {
        ctx->dyn32[dynamic_index].d_un.d_val = new_offset;
    }
    
    return 0;
}

int elf_save(ElfContext* ctx, const char* output_filename) {
    if (!ctx || !output_filename) {
        set_error("Invalid parameters");
        return -1;
    }
    
    // Open output file
    int fd = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        set_error("Failed to open output file: %s", strerror(errno));
        return -1;
    }
    
    // Write the entire modified elf to disk
    void* data_to_write;
    size_t size_to_write;
    
    if (ctx->is_expanded) {
        data_to_write = ctx->extended_data;
        size_to_write = ctx->extended_size;
    } else {
        data_to_write = ctx->mapped_data;
        size_to_write = ctx->file_size;
    }
    
    ssize_t written = write(fd, data_to_write, size_to_write);
    if (written != (ssize_t)size_to_write) {
        close(fd);
        set_error("Failed to write entire file: %s", strerror(errno));
        return -1;
    }
    
    close(fd);
    return 0;
}
