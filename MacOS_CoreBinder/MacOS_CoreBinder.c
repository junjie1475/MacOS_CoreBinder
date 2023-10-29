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
#include <sys/proc.h>
#include <kern/sched_prim.h>
#include <sys/resource.h>

// Tested on Darwin Kernel Version 22.4.0: Mon Mar  6 20:59:28 PST 2023; root:xnu-8796.101.5~3/RELEASE_ARM64_T6000
// Should work on all the Apple silicon machines

// TODO: Find offset from the binary instead of hardcoding it
#ifdef T8112
#define bound_processor_offset 0x268
#elif T6020
#define bound_processor_offset 0x270
#else
#define bound_processor_offset 0x260
#endif

#define task__threads 0x58
#define thread__task_threads 0x3b8
#define proc_iterate_offset 0x475094

// To bypass kernel address checking may come handy when debugging
#define DEBUG_PRINT_PTR(ptr) (uint32_t)(((uint64_t)ptr) >> 32), (uint32_t)(((uint64_t)ptr) & 0xFFFFFFFF)

// processor_array[0] to processor_array[ecore_number - 1] is for E-COREs
processor_array_t processor_array = NULL;
uintptr_t unauthenticated_printf = NULL;

thread_t current_thread(void);

kern_return_t MacOS_CoreBinder_start(kmod_info_t * ki, void *d);
kern_return_t MacOS_CoreBinder_stop(kmod_info_t *ki, void *d);


// https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/bsd/sys/proc_internal.h
typedef int (*proc_iterate_fn_t)(proc_t, void *);
#define PROC_ALLPROCLIST  (1U << 0) /* walk the allproc list (processes not yet exited) */
#define PROC_ZOMBPROCLIST (1U << 1) /* walk the zombie list */
#define PROC_NOWAITTRANS  (1U << 2) /* do not wait for transitions (checkdirs only) */
task_t (*proc_task)(void*);
void (*proc_iterate)(unsigned int flags, proc_iterate_fn_t callout, void *arg, proc_iterate_fn_t filterfn, void *filterarg);

int proc_callback(proc_t proc, void *arg) {
    printf("MacOS_CoreBinder: found process with PID %d\n", proc_pid(proc));
    // start from 0 to last process
    task_t task;
    thread_t thread;
    queue_head_t *head;

    task = proc_task(proc);
    // get &(task->threads)
    head = (queue_head_t*)((char *)task + task__threads);

    // get the address of next thread
    for (thread = (thread_t)head->next; thread != (thread_t)head; thread = (thread_t)(((queue_chain_t*)((char*)thread+thread__task_threads))->next)) {
      processor_t* bound_processor = (processor_t*)((char*)thread + bound_processor_offset);
      printf("MacOS_CoreBinder: thread->bound_processor: 0x%x%x\n", DEBUG_PRINT_PTR(*bound_processor));
      *bound_processor = processor_array[*(int*)arg];
    }
    return 0;
}

int proc_filter(proc_t proc, void *arg) {
    pid_t pid = *(pid_t *)arg;
    if(pid == -1) return 1;
    else if(proc_pid(proc) == pid) return 1;
    else return 0;
}

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
//            for(int i = 0; i < 64; i++) {
//                printf("MacOS_CoreBinder: processor_array[%d]: %x%x\n", i, DEBUG_PRINT_PTR(processor_array[i]));
//            }
            return 0;
        }
    }
    return -1;
}


static int find_text_exec_base(void) {
    // get printf in __TEXT_EXEC.__text section
    unauthenticated_printf = (uintptr_t)ptrauth_strip((void *)printf, ptrauth_key_function_pointer);

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
    printf("MacOS_CoreBinder: ^^^thread->bound_processor^^^: 0x%x%x\n", DEBUG_PRINT_PTR(*bound_processor));
    *bound_processor = processor_array[cpuid];
    thread_block(THREAD_CONTINUE_NULL); // force the scheduler to switch the thread
    return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, pin_core, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY,
            NULL, 0, &sysctl_pincore, "I", "bind thread on core");

static int sysctl_pincore_pid SYSCTL_HANDLER_ARGS {
    // use top 32 bits as pid, bottom 32 bits as cpuid
    // if pid = -1, then bind all the threads on the system to that core
    uint64_t pid_cpu = LONG_MAX;
    SYSCTL_IN(req, &pid_cpu, sizeof(pid_cpu));
    if(pid_cpu == LONG_MAX) {
        return -1;
    }
    else {
        // bind all threads
        int cpuid = pid_cpu & 0xFF;
        pid_t pid = (int)(pid_cpu >> 32);
        proc_iterate(PROC_ALLPROCLIST, proc_callback, &cpuid, proc_filter, &pid);
    }
    return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, pin_core_pid, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_ANYBODY,
            NULL, 0, &sysctl_pincore_pid, "I", "bind process with pid on core");

int isreg = -1;
kern_return_t MacOS_CoreBinder_start(kmod_info_t * ki, void *d)
{
    printf("MacOS_CoreBinder_start\n");
    
    if(find_text_exec_base() == -1) {
         printf("MacOS_CoreBinder: couldn't find kernel slide!");
         return KERN_SUCCESS;
    }
    isreg = 1;
    sysctl_register_oid(&sysctl__kern_pin_core);
    sysctl_register_oid(&sysctl__kern_pin_core_pid);
    
    uintptr_t unauthenticated_proc_iterate = (unsigned long long)unauthenticated_printf + proc_iterate_offset;
    void *ptr2 = (void*)ptrauth_sign_unauthenticated((void*)unauthenticated_proc_iterate, ptrauth_key_function_pointer, 0);

    uintptr_t unauthenticated_proc_task = (unsigned long long)unauthenticated_printf + 0x470da0;
    void *ptr3 = (void*)ptrauth_sign_unauthenticated((void*)unauthenticated_proc_task, ptrauth_key_function_pointer, 0);
    proc_iterate = ptr2;
    proc_task = ptr3;
    
    return KERN_SUCCESS;
}

kern_return_t MacOS_CoreBinder_stop(kmod_info_t *ki, void *d)
{
    if(isreg != -1) {
        sysctl_unregister_oid(&sysctl__kern_pin_core);
        sysctl_unregister_oid(&sysctl__kern_pin_core_pid);
    }
    printf("MacOS_CoreBinder_stop\n");
    return KERN_SUCCESS;
}
