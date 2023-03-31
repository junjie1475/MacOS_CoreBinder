//
//  MacOS_CoreBinder.c
//  MacOS_CoreBinder
//
//  Created by Junjie on 31/03/2023.
//

#include <mach/mach_types.h>

kern_return_t MacOS_CoreBinder_start(kmod_info_t * ki, void *d);
kern_return_t MacOS_CoreBinder_stop(kmod_info_t *ki, void *d);

kern_return_t MacOS_CoreBinder_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t MacOS_CoreBinder_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
