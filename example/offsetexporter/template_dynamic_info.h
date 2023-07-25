/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef dynamic_info_h
#define dynamic_info_h

struct dynamic_info {
    const char* kern_version;
    // struct fileglob
    u64 fileglob__fg_ops;
    u64 fileglob__fg_data;
    // struct fileops
    u64 fileops__fo_kqfilter;
    // struct fileproc
    // u64 fileproc__fp_iocount;
    // u64 fileproc__fp_vflags;
    // u64 fileproc__fp_flags;
    // u64 fileproc__fp_guard_attrs;
    // u64 fileproc__fp_glob;
    // u64 fileproc__fp_guard;
    // u64 fileproc__object_size;
    // struct fileproc_guard
    u64 fileproc_guard__fpg_guard;
    // struct kqworkloop
    u64 kqworkloop__kqwl_state;
    u64 kqworkloop__kqwl_p;
    u64 kqworkloop__kqwl_owner;
    u64 kqworkloop__kqwl_dynamicid;
    u64 kqworkloop__object_size;
    // struct pmap
    u64 pmap__tte;
    u64 pmap__ttep;
    // struct proc
    u64 proc__p_list__le_next;
    u64 proc__p_list__le_prev;
    u64 proc__p_pid;
    u64 proc__p_fd__fd_ofiles;
    u64 proc__object_size;
    // struct pseminfo
    u64 pseminfo__psem_usecount;
    u64 pseminfo__psem_uid;
    u64 pseminfo__psem_gid;
    u64 pseminfo__psem_name;
    u64 pseminfo__psem_semobject;
    // struct psemnode
    // u64 psemnode__pinfo;
    // u64 psemnode__padding;
    // u64 psemnode__object_size;
    // struct semaphore
    u64 semaphore__owner;
    // struct specinfo
    u64 specinfo__si_rdev;
    // struct task
    u64 task__map;
    u64 task__threads__next;
    u64 task__threads__prev;
    u64 task__itk_space;
    u64 task__object_size;
    // struct thread
    u64 thread__task_threads__next;
    u64 thread__task_threads__prev;
    u64 thread__map;
    u64 thread__thread_id;
    u64 thread__object_size;
    // struct uthread
    u64 uthread__object_size;
    // struct vm_map_entry
    u64 vm_map_entry__links__prev;
    u64 vm_map_entry__links__next;
    u64 vm_map_entry__links__start;
    u64 vm_map_entry__links__end;
    u64 vm_map_entry__store__entry__rbe_left;
    u64 vm_map_entry__store__entry__rbe_right;
    u64 vm_map_entry__store__entry__rbe_parent;
    // struct vnode
    u64 vnode__v_un__vu_specinfo;
    // struct _vm_map
    u64 _vm_map__hdr__links__prev;
    u64 _vm_map__hdr__links__next;
    u64 _vm_map__hdr__links__start;
    u64 _vm_map__hdr__links__end;
    u64 _vm_map__hdr__nentries;
    u64 _vm_map__hdr__rb_head_store__rbh_root;
    u64 _vm_map__pmap;
    u64 _vm_map__hint;
    u64 _vm_map__hole_hint;
    u64 _vm_map__holes_list;
    u64 _vm_map__object_size;
    // kernelcache static addresses
    u64 kernelcache__kernel_base;
    u64 kernelcache__cdevsw;
    u64 kernelcache__gPhysBase;
    u64 kernelcache__gPhysSize;
    u64 kernelcache__gVirtBase;
    u64 kernelcache__perfmon_devices;
    u64 kernelcache__perfmon_dev_open;
    u64 kernelcache__ptov_table;
    u64 kernelcache__vm_first_phys_ppnum;
    u64 kernelcache__vm_pages;
    u64 kernelcache__vm_page_array_beginning_addr;
    u64 kernelcache__vm_page_array_ending_addr;
    u64 kernelcache__vn_kqfilter;
};

const struct dynamic_info kern_versions[] = {
    {
        .kern_version = "%kern_version%",
        .fileglob__fg_ops = %fileglob__fg_ops%,
        .fileglob__fg_data = %fileglob__fg_vn_data% - 8,
        .fileops__fo_kqfilter = %fileops__fo_kqfilter%,
        // .fileproc__fp_iocount = 0x0000,
        // .fileproc__fp_vflags = 0x0004,
        // .fileproc__fp_flags = 0x0008,
        // .fileproc__fp_guard_attrs = 0x000a,
        // .fileproc__fp_glob = 0x0010,
        // .fileproc__fp_guard = 0x0018,
        // .fileproc__object_size = 0x0020,
        .fileproc_guard__fpg_guard = %fileproc_guard__fpg_guard%,
        .kqworkloop__kqwl_state = %kqworkloop__kqwl_state%,
        .kqworkloop__kqwl_p = %kqworkloop__kqwl_p%,
        .kqworkloop__kqwl_owner = %kqworkloop__kqwl_owner%,
        .kqworkloop__kqwl_dynamicid = %kqworkloop__kqwl_owner% + 0x18,
        .kqworkloop__object_size = %kqworkloop__object_size%,
        .pmap__tte = %pmap__tte%,
        .pmap__ttep = %pmap__ttep%,
        .proc__p_list__le_next = %proc__p_list__le_next%,
        .proc__p_list__le_prev = %proc__p_list__le_prev%,
        .proc__p_pid = %proc__p_pid%,
        .proc__p_fd__fd_ofiles = %proc__p_fd__fd_ofiles%,
        .proc__object_size = %proc__object_size%,
        .pseminfo__psem_usecount = %pseminfo__psem_usecount%,
        .pseminfo__psem_uid = %pseminfo__psem_uid%,
        .pseminfo__psem_gid = %pseminfo__psem_gid%,
        .pseminfo__psem_name = %pseminfo__psem_name%,
        .pseminfo__psem_semobject = %pseminfo__psem_semobject%,
        // .psemnode__pinfo = 0x0000,
        // .psemnode__padding = 0x0008,
        // .psemnode__object_size = 0x0010,
        .semaphore__owner = %semaphore__owner%,
        .specinfo__si_rdev = %specinfo__si_rdev%,
        .task__map = %task__map%,
        .task__threads__next = %task__thread_count% - 0x28,
        .task__threads__prev = %task__thread_count% - 0x28 + 8,
        .task__itk_space = %task__itk_space%,
        .task__object_size = %task__object_size%,
        .thread__task_threads__next = %thread__map% - 0x18,
        .thread__task_threads__prev = %thread__map% - 0x18 + 8,
        .thread__map = %thread__map%,
        .thread__thread_id = %thread__thread_id%,
        .thread__object_size = %thread__object_size%,
        .uthread__object_size = %uthread__object_size%,
        .vm_map_entry__links__prev = %vm_map_entry__links__prev%,
        .vm_map_entry__links__next = %vm_map_entry__links__next%,
        .vm_map_entry__links__start = %vm_map_entry__links__start%,
        .vm_map_entry__links__end = %vm_map_entry__links__end%,
        .vm_map_entry__store__entry__rbe_left = %vm_map_entry__store__entry__rbe_left%,
        .vm_map_entry__store__entry__rbe_right = %vm_map_entry__store__entry__rbe_right%,
        .vm_map_entry__store__entry__rbe_parent = %vm_map_entry__store__entry__rbe_parent%,
        .vnode__v_un__vu_specinfo = %vnode__v_un__vu_specinfo%,
        ._vm_map__hdr__links__prev = %vm_map_entry__links__prev% + 0x10,
        ._vm_map__hdr__links__next = %vm_map_entry__links__next% + 0x10,
        ._vm_map__hdr__links__start = %vm_map_entry__links__start% + 0x10,
        ._vm_map__hdr__links__end = %vm_map_entry__links__end% + 0x10,
        ._vm_map__hdr__nentries = %_vm_map__hdr__nentries%,
        ._vm_map__hdr__rb_head_store__rbh_root = %_vm_map__hdr__rb_head_store__rbh_root%,
        ._vm_map__pmap = %_vm_map__pmap%,
        ._vm_map__hint = %_vm_map__vmu1_lowest_unnestable_start% + 0x08,
        ._vm_map__hole_hint = %_vm_map__vmu1_lowest_unnestable_start% + 0x10,
        ._vm_map__holes_list = %_vm_map__vmu1_lowest_unnestable_start% + 0x18,
        ._vm_map__object_size = %_vm_map__object_size%,
        .kernelcache__kernel_base = %kernelcache__kernel_base%,
        .kernelcache__cdevsw = %kernelcache__cdevsw%,
        .kernelcache__gPhysBase = %kernelcache__gPhysBase%,
        .kernelcache__gPhysSize = %kernelcache__gPhysBase% + 8,
        .kernelcache__gVirtBase = %kernelcache__gVirtBase%,
        .kernelcache__perfmon_devices = %kernelcache__perfmon_devices%,
        .kernelcache__perfmon_dev_open = %kernelcache__perfmon_dev_open%,
        .kernelcache__ptov_table = %kernelcache__ptov_table%,
        .kernelcache__vm_first_phys_ppnum = %kernelcache__vm_first_phys_ppnum%,
        .kernelcache__vm_pages = %kernelcache__vm_pages%,
        .kernelcache__vm_page_array_beginning_addr = %kernelcache__vm_page_array_beginning_addr%,
        .kernelcache__vm_page_array_ending_addr = %kernelcache__vm_page_array_ending_addr%,
        .kernelcache__vn_kqfilter = %kernelcache__vn_kqfilter%,
    },
};

#endif /* dynamic_info_h */
