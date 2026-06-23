#include "basebin_instructions.h"
#include "basebin_memory.h"

int mem_set_rw(void *addr, uint32_t size) {
    return mem_set_prot(addr, size, VM_RW);
}

int mem_set_rx(void *addr, uint32_t size) {
    return mem_set_prot(addr, size, VM_RX);
}

int mem_set_ro(void *addr, uint32_t size) {
    return mem_set_prot(addr, size, VM_RO);
}

void *mem_allocate(uint32_t size) {
    return mem_allocate_internal(NULL, size, VM_FLAGS_ANYWHERE);
}

void *mem_allocate_fixed(void *addr, uint32_t size) {
    return mem_allocate_internal(addr, size, VM_FLAGS_FIXED);
}

void *mem_allocate_near(void *target, uint64_t range) {
    uintptr_t base_addr = (uintptr_t)VM_PAGE_OF(target);
    uintptr_t min_alloc_addr = base_addr - (uintptr_t)range;
    uintptr_t max_alloc_addr = base_addr + (uintptr_t)range;
    mach_port_t task = mach_task_self();

    if ((uint64_t)base_addr < range) min_alloc_addr = 0;

    mach_vm_address_t min_addr = 0x100000000;
    mach_vm_address_t max_addr = 0x300000000;
    mach_vm_address_t current_addr = min_addr;
    mach_vm_address_t last_addr = min_addr;
    
    while (current_addr < max_addr) {
        mach_vm_size_t size = 0;
        mach_port_t object = MACH_PORT_NULL;
        vm_region_basic_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;

        if (mach_vm_region(task, &current_addr, &size, flavor, (vm_region_info_t)&info, (uint64_t *)&count, &object) != 0) break;
        if (current_addr > last_addr) {
            uintptr_t available_start = (uintptr_t)last_addr;
            uintptr_t available_end = (uintptr_t)current_addr;
            if (available_end > max_addr) available_end = max_addr;

            uint32_t available_size = (uint32_t)(available_end - available_start);
            if (available_start < max_addr && available_size >= vm_page_size) {
                if (available_start >= min_alloc_addr) {
                    for (uint32_t i = 0; i < available_size; i+=vm_page_size) {
                        if ((available_start + i) >= max_alloc_addr) break;
                        
                        void *addr = (void *)(available_start + i);
                        addr = mem_allocate_fixed(addr, (uint32_t)vm_page_size);
                        if (addr != NULL) return addr;
                    }
                }
            }
        }

        last_addr = current_addr + size;
        current_addr = last_addr;
    }

    if (last_addr < max_addr) {
        uintptr_t available_start = (uintptr_t)last_addr;
        uintptr_t available_end = (uintptr_t)max_addr;
        uint32_t available_size = (uint32_t)(available_end - available_start);
        
        if (available_start < max_addr && available_size >= vm_page_size) {
            if (available_start >= min_alloc_addr) {
                for (uint32_t i = 0; i < available_size; i+=vm_page_size) {
                    if ((available_start + i) >= max_alloc_addr) break;
                    
                    void *addr = (void *)(available_start + i);
                    addr = mem_allocate_fixed(addr, (uint32_t)vm_page_size);
                    if (addr != NULL) return addr;
                }
            }
        }
    }
    return NULL;
}