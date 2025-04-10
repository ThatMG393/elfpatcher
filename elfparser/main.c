/**
 * example.c - Example usage of the ELF DT_NEEDED modification library
 */

#include "elfmod.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: %s <elf_file> <old_library> <new_library>\n", argv[0]);
        printf("Example: %s ./myprogram.so libc.so.6 libcustom.so\n", argv[0]);
        return 1;
    }
    
    const char* filename = argv[1];
    const char* old_lib = argv[2];
    const char* new_lib = argv[3];
    ElfContext ctx;
    
    // Load the ELF file
    if (elf_load(filename, &ctx) != 0) {
        fprintf(stderr, "Failed to load ELF file: %s\n", elf_get_error());
        return 1;
    }
    
    printf("Successfully loaded ELF file: %s\n", filename);
    printf("ELF format: %s\n", ctx.is_64bit ? "64-bit" : "32-bit");
    
    // Get and display current DT_NEEDED entries
    size_t needed_count;
    char** needed_libs = elf_get_needed_libs(&ctx, &needed_count);
    
    if (needed_libs) {
        printf("\nCurrent DT_NEEDED libraries (%zu entries):\n", needed_count);
        for (size_t i = 0; i < needed_count; i++) {
            printf("%2zu. %s\n", i + 1, needed_libs[i]);
        }
        
        // Try to find the old library in the list
        bool found = false;
        for (size_t i = 0; i < needed_count; i++) {
            if (strcmp(needed_libs[i], old_lib) == 0) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            printf("\nWARNING: The specified library '%s' wasn't found in DT_NEEDED entries.\n", old_lib);
        }
        
        // Free the allocated strings
        for (size_t i = 0; i < needed_count; i++) {
            free(needed_libs[i]);
        }
        free(needed_libs);
    } else {
        printf("\nNo DT_NEEDED entries found in the ELF file.\n");
    }
    
    // Replace the library
    printf("\nReplacing '%s' with '%s'...\n", old_lib, new_lib);
    if (elf_replace_needed_lib(&ctx, old_lib, new_lib) != 0) {
        fprintf(stderr, "Failed to replace library: %s\n", elf_get_error());
        elf_close(&ctx);
        return 1;
    }
    
    // Create output filename
    char output_filename[256];
    snprintf(output_filename, sizeof(output_filename), "%s.modified", filename);
    
    // Save the modified ELF
    if (elf_save(&ctx, output_filename) != 0) {
        fprintf(stderr, "Failed to save modified ELF: %s\n", elf_get_error());
        elf_close(&ctx);
        return 1;
    }
    
    printf("Successfully saved modified ELF to: %s\n", output_filename);
    
    // Check the modifications
    ElfContext new_ctx;
    if (elf_load(output_filename, &new_ctx) == 0) {
        needed_libs = elf_get_needed_libs(&new_ctx, &needed_count);
        if (needed_libs) {
            printf("\nVerifying modified DT_NEEDED libraries (%zu entries):\n", needed_count);
            for (size_t i = 0; i < needed_count; i++) {
                printf("%2zu. %s\n", i + 1, needed_libs[i]);
            }
            
            // Free the allocated strings
            for (size_t i = 0; i < needed_count; i++) {
                free(needed_libs[i]);
            }
            free(needed_libs);
        }
        elf_close(&new_ctx);
    }
    
    // Clean up
    elf_close(&ctx);
    printf("\nELF context closed\n");
    
    return 0;
}
