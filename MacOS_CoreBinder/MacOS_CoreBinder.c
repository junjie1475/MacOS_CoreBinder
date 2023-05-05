#include <libkern/libkern.h>
#include <mach-o/loader.h>
#include <mach/mach_types.h>
#include <ptrauth.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <machine/machine_routines.h>

// Tested on Darwin Kernel Version 22.4.0: Mon Mar  6 20:59:28 PST 2023; root:xnu-8796.101.5~3/RELEASE_ARM64_T6000
// Should work on all the Apple silicon

// TODO: Find offset from the binary instead of hardcoding it
#ifdef T8112
#define bound_processor_offset 0x268
#else
#define bound_processor_offset 0x260
#endif

// To bypass kernel address checking may come handy when debugging
#define DEBUG_PRINT_PTR(ptr) (uint32_t)(((uint64_t)ptr) >> 32), (uint32_t)(((uint64_t)ptr) & 0xFFFFFFFF)

uint64_t kernel_slide = -1;
// processor_array[0] to processor_array[ecore_number - 1] is for E-CORE
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
            printf("MacOS_CoreBinder: Found processor_array pointer read at %x%x\n", DEBUG_PRINT_PTR(instructions + i - 2));
            // Extract the low 4 bits from the immediate of add.
            long offset = (instructions[i - 1] >> 10) & 0b111111111111;
            printf("MacOS_CoreBinder: add immediate: %lx\n", offset);
            
            // Extract the top 21 bits from the immediate of adrp
            uint64_t bit18_0 = (instructions[i - 2] >> 5) & 0x7FFFF;
            long imm = (bit18_0 << 2) | ((instructions[i - 2] >> 29) & 0b11);
            // 4kb page size
            imm = imm << 12;
            
            // Add the imm with the current pc(zero out the low 12 bits)
            long intermediate_address = (((long)&instructions[i - 2]) & ~(0xFFF)) + imm;
            processor_array = (processor_array_t)(intermediate_address + offset);

            printf("MacOS_CoreBinder: processor_array address is at 0x%x%x\n", DEBUG_PRINT_PTR(processor_array));
            for(int i = 0; i < 64; i++) {
                printf("MacOS_CoreBinder: processor_array[%d]: %x%x\n", i, DEBUG_PRINT_PTR(processor_array[i]));
            }
            return 0;
        }
    }
    return -1;
}


static int find_text_exec_base(void) {
    // get printf in __TEXT_EXEC.__text section
    uintptr_t unauthenticated_printf = (uintptr_t)ptrauth_strip((void *)printf, ptrauth_key_function_pointer);

    printf("MacOS_CoreBinder: unauthenticated_printf at 0x%x%x\n", DEBUG_PRINT_PTR(unauthenticated_printf));
    
    // search start from printf address
    return find_bound_processor_in_text_exec((char*)unauthenticated_printf, 0x700000);
}


static int sysctl_pincore SYSCTL_HANDLER_ARGS {
    int cpuid = -1;
    SYSCTL_IN(req, &cpuid, sizeof(cpuid));
    if(cpuid == -1) {
        return -1;
    }

    thread_t thread = current_thread();

    processor_t* bound_processor = (processor_t*)((char*)thread + bound_processor_offset);
    printf("MacOS_CoreBinder: thread->bound_processor: 0x%x%x\n", DEBUG_PRINT_PTR(*bound_processor));
    *bound_processor = processor_array[cpuid];;

    return 0;
}


SYSCTL_PROC(_kern, OID_AUTO, pin_core, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY,
            NULL, 0, &sysctl_pincore, "I", "bind thread on core");

kern_return_t MacOS_CoreBinder_start(kmod_info_t * ki, void *d)
{
    printf("MacOS_CoreBinder_start\n");
    if(find_text_exec_base() == -1) {
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
