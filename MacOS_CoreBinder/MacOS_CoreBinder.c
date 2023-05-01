//
//  MacOS_CoreBinder.c
//  MacOS_CoreBinder
//
//  Created by Junjie on 31/03/2023.
//

#include <libkern/libkern.h>
#include <mach-o/loader.h>
#include <mach/mach_types.h>
#include <ptrauth.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

// Only for Darwin Kernel Version 22.4.0: Mon Mar  6 20:59:28 PST 2023; root:xnu-8796.101.5~3/RELEASE_ARM64_T6000

// TODO: Find offset from the binary instead of hardcoding it
#define bound_processor_offset 0x260

uint64_t kernel_slide = -1;
processor_array_t processor_array = NULL;
typedef struct thread *thread_t;

thread_t current_thread(void);

kern_return_t MacOS_CoreBinder_start(kmod_info_t * ki, void *d);
kern_return_t MacOS_CoreBinder_stop(kmod_info_t *ki, void *d);

// Modify from https://github.com/saagarjha/TSOEnabler/blob/master/TSOEnabler/TSOEnabler.c
static int find_bound_processor_in_text_exec(char *text_exec, uint64_t text_exec_size) {
    /*
     Find this pattern
     str        x20, [x8, w19, sxtw #3]
     ldp        fp, lr, [sp, #0x30]
     ldp        x20, x19, [sp, #0x20]
     ldp        x22, x21, [sp, #0x10]
     ldp        x24, x23, [sp], #0x40
     */

    uint32_t *instructions = (uint32_t *)text_exec;
    for (uint64_t i = 0; i < text_exec_size / sizeof(uint32_t) - 5; ++i) {
        if (instructions[i + 0] == 0xF833D914 &&
            instructions[i + 1] == 0xA9437BFD &&
            instructions[i + 2] == 0xA9424FF4 &&
            instructions[i + 3] == 0xA94157F6 &&
            instructions[i + 4] == 0xA8C45FF8) {
            printf("MacOS_CoreBinder: Found processor_array pointer read at %p\n", instructions + i - 2);
            // Extract the low 4 bits from the immediate of add.
            long offset = (instructions[i - 1] >> 10) & 0b111111111111;
            printf("MacOS_CoreBinder: add immediate: %lx\n", offset);
            
            // Extract the top 21 bits from the immediate of adrp
            uint64_t bit18_0 = (instructions[i - 2] >> 5) & 0x7FFFF;
            long imm = (bit18_0 << 2) | ((instructions[i - 2] >> 29) & 0b11);
            imm = imm << 12;
            // add the imm with the current pc(zero out the low 12 bits)
            long intermediate_address = (((long)&instructions[i - 2]) & ~(0xFFF)) + imm;
            processor_array = (processor_array_t)intermediate_address + offset;
            
            printf("MacOS_CoreBinder: processor_array address is %lx\n", processor_array);
            return 0;
        }
    }
    return -1;
}

static int find_txet_exec_base(void) {
    // Find the kernel base. First, get the address of a function in __TEXT_EXEC:
    uintptr_t unauthenticated_printf = (uintptr_t)ptrauth_strip((void *)printf, ptrauth_key_function_pointer);
    // Then, iterate backwards to find the kernel Mach-O header.
    uintptr_t address = unauthenticated_printf & ~(PAGE_SIZE - 1);
    uint32_t magic;
    while ((void)memcpy(&magic, (void *)address, sizeof(magic)), magic != MH_MAGIC_64) {
        address -= PAGE_SIZE;
    }

    printf("MacOS_CoreBinder: found kernel base at %p\n", (void *)address);

    ptrdiff_t slide = -1;
    uintptr_t text_exec_base = 0;
    uint64_t text_exec_size = 0;
    struct mach_header_64 *header = (struct mach_header_64 *)address;
    address += sizeof(*header);
    
    printf("header->ncmds: %d\n", header->ncmds);
    for (int i = 0; i < header->ncmds; ++i) {
        struct load_command *command = (struct load_command *)address;
        if (command->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segment = (struct segment_command_64 *)command;
            if (!strcmp(segment->segname, "__TEXT")) {
                slide = (uintptr_t)header - segment->vmaddr;
            } else if (!strcmp(segment->segname, "__TEXT_EXEC")) {
                text_exec_base = segment->vmaddr;
                text_exec_size = segment->vmsize;
            }
        }
        address += command->cmdsize;
    }

    if (slide < 0 || !text_exec_base) {
        return -1;
    }

    char *text_exec = (char *)(text_exec_base + slide);

    printf("MacOS_CoreBinder: kernel slide is 0x%llx, and __TEXT_EXEC is at %p\n", (long long)slide, text_exec);

    return find_bound_processor_in_text_exec(text_exec, text_exec_size);
}


static int sysctl_pincore SYSCTL_HANDLER_ARGS {
    int cpuid = -1;
    SYSCTL_IN(req, &cpuid, sizeof(cpuid));
    if(cpuid == -1) {
        return -1;
    }
    
    thread_t thread = current_thread();
    
    for(int i = 0; i < 15; i++) {
        printf("MacOS_CoreBinder: processor_array[%d]: %lx\n", i, processor_array[i]);
    }
    
    processor_t* bound_processor = (processor_t*)((char*)thread + bound_processor_offset);
    printf("MacOS_CoreBinder: thread->bound_processor: %lx\n", *bound_processor);
    *bound_processor = processor_array[0];;
    
    return 0;
}


SYSCTL_PROC(_kern, OID_AUTO, pin_core, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY,
            NULL, 0, &sysctl_pincore, "I", "bind thread on core");

kern_return_t MacOS_CoreBinder_start(kmod_info_t * ki, void *d)
{
    printf("MacOS_CoreBinder_start\n");
    if(find_txet_exec_base() == -1) {
        printf("MacOS_CoreBinder: couldn't find kernel slide!");
    } else {
        sysctl_register_oid(&sysctl__kern_pin_core);
    }
    return KERN_SUCCESS;
}

kern_return_t MacOS_CoreBinder_stop(kmod_info_t *ki, void *d)
{
    if(kernel_slide != -1) {
        sysctl_unregister_oid(&sysctl__kern_pin_core);
    }
    printf("MacOS_CoreBinder_stop\n");
    return KERN_SUCCESS;
}
