//
//  kernelpatchfinder32_base.cpp
//  libpatchfinder
//
//  Created by tihmstar on 09.07.21.
//

#include "kernelpatchfinder32_base.hpp"
#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;

struct mac_policy_ops {
    uint32_t mpo_audit_check_postselect;
    uint32_t mpo_audit_check_preselect;
    uint32_t mpo_bpfdesc_label_associate;
    uint32_t mpo_bpfdesc_label_destroy;
    uint32_t mpo_bpfdesc_label_init;
    uint32_t mpo_bpfdesc_check_receive;
    uint32_t mpo_cred_check_label_update_execve;
    uint32_t mpo_cred_check_label_update;
    uint32_t mpo_cred_check_visible;
    uint32_t mpo_cred_label_associate_fork;
    uint32_t mpo_cred_label_associate_kernel;
    uint32_t mpo_cred_label_associate;
    uint32_t mpo_cred_label_associate_user;
    uint32_t mpo_cred_label_destroy;
    uint32_t mpo_cred_label_externalize_audit;
    uint32_t mpo_cred_label_externalize;
    uint32_t mpo_cred_label_init;
    uint32_t mpo_cred_label_internalize;
    uint32_t mpo_cred_label_update_execve;
    uint32_t mpo_cred_label_update;
    uint32_t mpo_devfs_label_associate_device;
    uint32_t mpo_devfs_label_associate_directory;
    uint32_t mpo_devfs_label_copy;
    uint32_t mpo_devfs_label_destroy;
    uint32_t mpo_devfs_label_init;
    uint32_t mpo_devfs_label_update;
    uint32_t mpo_file_check_change_offset;
    uint32_t mpo_file_check_create;
    uint32_t mpo_file_check_dup;
    uint32_t mpo_file_check_fcntl;
    uint32_t mpo_file_check_get_offset;
    uint32_t mpo_file_check_get;
    uint32_t mpo_file_check_inherit;
    uint32_t mpo_file_check_ioctl;
    uint32_t mpo_file_check_lock;
    uint32_t mpo_file_check_mmap_downgrade;
    uint32_t mpo_file_check_mmap;
    uint32_t mpo_file_check_receive;
    uint32_t mpo_file_check_set;
    uint32_t mpo_file_label_init;
    uint32_t mpo_file_label_destroy;
    uint32_t mpo_file_label_associate;
    uint32_t mpo_ifnet_check_label_update;
    uint32_t mpo_ifnet_check_transmit;
    uint32_t mpo_ifnet_label_associate;
    uint32_t mpo_ifnet_label_copy;
    uint32_t mpo_ifnet_label_destroy;
    uint32_t mpo_ifnet_label_externalize;
    uint32_t mpo_ifnet_label_init;
    uint32_t mpo_ifnet_label_internalize;
    uint32_t mpo_ifnet_label_update;
    uint32_t mpo_ifnet_label_recycle;
    uint32_t mpo_inpcb_check_deliver;
    uint32_t mpo_inpcb_label_associate;
    uint32_t mpo_inpcb_label_destroy;
    uint32_t mpo_inpcb_label_init;
    uint32_t mpo_inpcb_label_recycle;
    uint32_t mpo_inpcb_label_update;
    uint32_t mpo_iokit_check_device;
    uint32_t mpo_ipq_label_associate;
    uint32_t mpo_ipq_label_compare;
    uint32_t mpo_ipq_label_destroy;
    uint32_t mpo_ipq_label_init;
    uint32_t mpo_ipq_label_update;
    uint32_t mpo_file_check_library_validation;
    uint32_t mpo_vnode_notify_setacl;
    uint32_t mpo_vnode_notify_setattrlist;
    uint32_t mpo_vnode_notify_setextattr;
    uint32_t mpo_vnode_notify_setflags;
    uint32_t mpo_vnode_notify_setmode;
    uint32_t mpo_vnode_notify_setowner;
    uint32_t mpo_vnode_notify_setutimes;
    uint32_t mpo_vnode_notify_truncate;
    uint32_t mpo_mbuf_label_associate_bpfdesc;
    uint32_t mpo_mbuf_label_associate_ifnet;
    uint32_t mpo_mbuf_label_associate_inpcb;
    uint32_t mpo_mbuf_label_associate_ipq;
    uint32_t mpo_mbuf_label_associate_linklayer;
    uint32_t mpo_mbuf_label_associate_multicast_encap;
    uint32_t mpo_mbuf_label_associate_netlayer;
    uint32_t mpo_mbuf_label_associate_socket;
    uint32_t mpo_mbuf_label_copy;
    uint32_t mpo_mbuf_label_destroy;
    uint32_t mpo_mbuf_label_init;
    uint32_t mpo_mount_check_fsctl;
    uint32_t mpo_mount_check_getattr;
    uint32_t mpo_mount_check_label_update;
    uint32_t mpo_mount_check_mount;
    uint32_t mpo_mount_check_remount;
    uint32_t mpo_mount_check_setattr;
    uint32_t mpo_mount_check_stat;
    uint32_t mpo_mount_check_umount;
    uint32_t mpo_mount_label_associate;
    uint32_t mpo_mount_label_destroy;
    uint32_t mpo_mount_label_externalize;
    uint32_t mpo_mount_label_init;
    uint32_t mpo_mount_label_internalize;
    uint32_t mpo_netinet_fragment;
    uint32_t mpo_netinet_icmp_reply;
    uint32_t mpo_netinet_tcp_reply;
    uint32_t mpo_pipe_check_ioctl;
    uint32_t mpo_pipe_check_kqfilter;
    uint32_t mpo_pipe_check_label_update;
    uint32_t mpo_pipe_check_read;
    uint32_t mpo_pipe_check_select;
    uint32_t mpo_pipe_check_stat;
    uint32_t mpo_pipe_check_write;
    uint32_t mpo_pipe_label_associate;
    uint32_t mpo_pipe_label_copy;
    uint32_t mpo_pipe_label_destroy;
    uint32_t mpo_pipe_label_externalize;
    uint32_t mpo_pipe_label_init;
    uint32_t mpo_pipe_label_internalize;
    uint32_t mpo_pipe_label_update;
    uint32_t mpo_policy_destroy;
    uint32_t mpo_policy_init;
    uint32_t mpo_policy_initbsd;
    uint32_t mpo_policy_syscall;
    uint32_t mpo_system_check_sysctlbyname;
    uint32_t mpo_proc_check_inherit_ipc_ports;
    uint32_t mpo_vnode_check_rename;
    uint32_t mpo_kext_check_query;
    uint32_t mpo_proc_notify_exec_complete;
    uint32_t mpo_reserved4;
    uint32_t mpo_proc_check_syscall_unix;
    uint32_t mpo_proc_check_expose_task;
    uint32_t mpo_proc_check_set_host_special_port;
    uint32_t mpo_proc_check_set_host_exception_port;
    uint32_t mpo_exc_action_check_exception_send;
    uint32_t mpo_exc_action_label_associate;
    uint32_t mpo_exc_action_label_populate;
    uint32_t mpo_exc_action_label_destroy;
    uint32_t mpo_exc_action_label_init;
    uint32_t mpo_exc_action_label_update;
    uint32_t mpo_vnode_check_trigger_resolve;
    uint32_t mpo_mount_check_mount_late;
    uint32_t mpo_mount_check_snapshot_mount;
    uint32_t mpo_reserved2;
    uint32_t mpo_skywalk_flow_check_connect;
    uint32_t mpo_skywalk_flow_check_listen;
    uint32_t mpo_posixsem_check_create;
    uint32_t mpo_posixsem_check_open;
    uint32_t mpo_posixsem_check_post;
    uint32_t mpo_posixsem_check_unlink;
    uint32_t mpo_posixsem_check_wait;
    uint32_t mpo_posixsem_label_associate;
    uint32_t mpo_posixsem_label_destroy;
    uint32_t mpo_posixsem_label_init;
    uint32_t mpo_posixshm_check_create;
    uint32_t mpo_posixshm_check_mmap;
    uint32_t mpo_posixshm_check_open;
    uint32_t mpo_posixshm_check_stat;
    uint32_t mpo_posixshm_check_truncate;
    uint32_t mpo_posixshm_check_unlink;
    uint32_t mpo_posixshm_label_associate;
    uint32_t mpo_posixshm_label_destroy;
    uint32_t mpo_posixshm_label_init;
    uint32_t mpo_proc_check_debug;
    uint32_t mpo_proc_check_fork;
    uint32_t mpo_proc_check_get_task_name;
    uint32_t mpo_proc_check_get_task;
    uint32_t mpo_proc_check_getaudit;
    uint32_t mpo_proc_check_getauid;
    uint32_t mpo_proc_check_getlcid;
    uint32_t mpo_proc_check_mprotect;
    uint32_t mpo_proc_check_sched;
    uint32_t mpo_proc_check_setaudit;
    uint32_t mpo_proc_check_setauid;
    uint32_t mpo_proc_check_setlcid;
    uint32_t mpo_proc_check_signal;
    uint32_t mpo_proc_check_wait;
    uint32_t mpo_proc_check_dump_core;
    uint32_t mpo_reserved5;
    uint32_t mpo_socket_check_accept;
    uint32_t mpo_socket_check_accepted;
    uint32_t mpo_socket_check_bind;
    uint32_t mpo_socket_check_connect;
    uint32_t mpo_socket_check_create;
    uint32_t mpo_socket_check_deliver;
    uint32_t mpo_socket_check_kqfilter;
    uint32_t mpo_socket_check_label_update;
    uint32_t mpo_socket_check_listen;
    uint32_t mpo_socket_check_receive;
    uint32_t mpo_socket_check_received;
    uint32_t mpo_socket_check_select;
    uint32_t mpo_socket_check_send;
    uint32_t mpo_socket_check_stat;
    uint32_t mpo_socket_check_setsockopt;
    uint32_t mpo_socket_check_getsockopt;
    uint32_t mpo_socket_label_associate_accept;
    uint32_t mpo_socket_label_associate;
    uint32_t mpo_socket_label_copy;
    uint32_t mpo_socket_label_destroy;
    uint32_t mpo_socket_label_externalize;
    uint32_t mpo_socket_label_init;
    uint32_t mpo_socket_label_internalize;
    uint32_t mpo_socket_label_update;
    uint32_t mpo_socketpeer_label_associate_mbuf;
    uint32_t mpo_socketpeer_label_associate_socket;
    uint32_t mpo_socketpeer_label_destroy;
    uint32_t mpo_socketpeer_label_externalize;
    uint32_t mpo_socketpeer_label_init;
    uint32_t mpo_system_check_acct;
    uint32_t mpo_system_check_audit;
    uint32_t mpo_system_check_auditctl;
    uint32_t mpo_system_check_auditon;
    uint32_t mpo_system_check_host_priv;
    uint32_t mpo_system_check_nfsd;
    uint32_t mpo_system_check_reboot;
    uint32_t mpo_system_check_settime;
    uint32_t mpo_system_check_swapoff;
    uint32_t mpo_system_check_swapon;
    uint32_t mpo_socket_check_ioctl;
    uint32_t mpo_sysvmsg_label_associate;
    uint32_t mpo_sysvmsg_label_destroy;
    uint32_t mpo_sysvmsg_label_init;
    uint32_t mpo_sysvmsg_label_recycle;
    uint32_t mpo_sysvmsq_check_enqueue;
    uint32_t mpo_sysvmsq_check_msgrcv;
    uint32_t mpo_sysvmsq_check_msgrmid;
    uint32_t mpo_sysvmsq_check_msqctl;
    uint32_t mpo_sysvmsq_check_msqget;
    uint32_t mpo_sysvmsq_check_msqrcv;
    uint32_t mpo_sysvmsq_check_msqsnd;
    uint32_t mpo_sysvmsq_label_associate;
    uint32_t mpo_sysvmsq_label_destroy;
    uint32_t mpo_sysvmsq_label_init;
    uint32_t mpo_sysvmsq_label_recycle;
    uint32_t mpo_sysvsem_check_semctl;
    uint32_t mpo_sysvsem_check_semget;
    uint32_t mpo_sysvsem_check_semop;
    uint32_t mpo_sysvsem_label_associate;
    uint32_t mpo_sysvsem_label_destroy;
    uint32_t mpo_sysvsem_label_init;
    uint32_t mpo_sysvsem_label_recycle;
    uint32_t mpo_sysvshm_check_shmat;
    uint32_t mpo_sysvshm_check_shmctl;
    uint32_t mpo_sysvshm_check_shmdt;
    uint32_t mpo_sysvshm_check_shmget;
    uint32_t mpo_sysvshm_label_associate;
    uint32_t mpo_sysvshm_label_destroy;
    uint32_t mpo_sysvshm_label_init;
    uint32_t mpo_sysvshm_label_recycle;
    uint32_t mpo_proc_notify_exit;
    uint32_t mpo_mount_check_snapshot_revert;
    uint32_t mpo_vnode_check_getattr;
    uint32_t mpo_mount_check_snapshot_create;
    uint32_t mpo_mount_check_snapshot_delete;
    uint32_t mpo_vnode_check_clone;
    uint32_t mpo_proc_check_get_cs_info;
    uint32_t mpo_proc_check_set_cs_info;
    uint32_t mpo_iokit_check_hid_control;
    uint32_t mpo_vnode_check_access;
    uint32_t mpo_vnode_check_chdir;
    uint32_t mpo_vnode_check_chroot;
    uint32_t mpo_vnode_check_create;
    uint32_t mpo_vnode_check_deleteextattr;
    uint32_t mpo_vnode_check_exchangedata;
    uint32_t mpo_vnode_check_exec;
    uint32_t mpo_vnode_check_getattrlist;
    uint32_t mpo_vnode_check_getextattr;
    uint32_t mpo_vnode_check_ioctl;
    uint32_t mpo_vnode_check_kqfilter;
    uint32_t mpo_vnode_check_label_update;
    uint32_t mpo_vnode_check_link;
    uint32_t mpo_vnode_check_listextattr;
    uint32_t mpo_vnode_check_lookup;
    uint32_t mpo_vnode_check_open;
    uint32_t mpo_vnode_check_read;
    uint32_t mpo_vnode_check_readdir;
    uint32_t mpo_vnode_check_readlink;
    uint32_t mpo_vnode_check_rename_from;
    uint32_t mpo_vnode_check_rename_to;
    uint32_t mpo_vnode_check_revoke;
    uint32_t mpo_vnode_check_select;
    uint32_t mpo_vnode_check_setattrlist;
    uint32_t mpo_vnode_check_setextattr;
    uint32_t mpo_vnode_check_setflags;
    uint32_t mpo_vnode_check_setmode;
    uint32_t mpo_vnode_check_setowner;
    uint32_t mpo_vnode_check_setutimes;
    uint32_t mpo_vnode_check_stat;
    uint32_t mpo_vnode_check_truncate;
    uint32_t mpo_vnode_check_unlink;
    uint32_t mpo_vnode_check_write;
    uint32_t mpo_vnode_label_associate_devfs;
    uint32_t mpo_vnode_label_associate_extattr;
    uint32_t mpo_vnode_label_associate_file;
    uint32_t mpo_vnode_label_associate_pipe;
    uint32_t mpo_vnode_label_associate_posixsem;
    uint32_t mpo_vnode_label_associate_posixshm;
    uint32_t mpo_vnode_label_associate_singlelabel;
    uint32_t mpo_vnode_label_associate_socket;
    uint32_t mpo_vnode_label_copy;
    uint32_t mpo_vnode_label_destroy;
    uint32_t mpo_vnode_label_externalize_audit;
    uint32_t mpo_vnode_label_externalize;
    uint32_t mpo_vnode_label_init;
    uint32_t mpo_vnode_label_internalize;
    uint32_t mpo_vnode_label_recycle;
    uint32_t mpo_vnode_label_store;
    uint32_t mpo_vnode_label_update_extattr;
    uint32_t mpo_vnode_label_update;
    uint32_t mpo_vnode_notify_create;
    uint32_t mpo_vnode_check_signature;
    uint32_t mpo_vnode_check_uipc_bind;
    uint32_t mpo_vnode_check_uipc_connect;
    uint32_t mpo_proc_check_run_cs_invalid;
    uint32_t mpo_proc_check_suspend_resume;
    uint32_t mpo_thread_userret;
    uint32_t mpo_iokit_check_set_properties;
    uint32_t mpo_reserved3;
    uint32_t mpo_vnode_check_searchfs;
    uint32_t mpo_priv_check;
    uint32_t mpo_priv_grant;
    uint32_t mpo_proc_check_map_anon;
    uint32_t mpo_vnode_check_fsgetpath;
    uint32_t mpo_iokit_check_open;
    uint32_t mpo_proc_check_ledger;
    uint32_t mpo_vnode_notify_rename;
    uint32_t mpo_vnode_check_setacl;
    uint32_t mpo_vnode_notify_deleteextattr;
    uint32_t mpo_system_check_kas_info;
    uint32_t mpo_vnode_check_lookup_preflight;
    uint32_t mpo_vnode_notify_open;
    uint32_t mpo_system_check_info;
    uint32_t mpo_pty_notify_grant;
    uint32_t mpo_pty_notify_close;
    uint32_t mpo_vnode_find_sigs;
    uint32_t mpo_kext_check_load;
    uint32_t mpo_kext_check_unload;
    uint32_t mpo_proc_check_proc_info;
    uint32_t mpo_vnode_notify_link;
    uint32_t mpo_iokit_check_filter_properties;
    uint32_t mpo_iokit_check_get_property;
};

#pragma mark kernelpatchfinder32_base
kernelpatchfinder32_base::kernelpatchfinder32_base(const char *filename)
: kernelpatchfinder32(filename)
{
    //
}

kernelpatchfinder32_base::kernelpatchfinder32_base(const void *buffer, size_t bufSize, bool takeOwnership)
: kernelpatchfinder32(buffer, bufSize, takeOwnership)
{
    //
}

kernelpatchfinder32_base::kernelpatchfinder32_base(kernelpatchfinder32 &&mv)
: kernelpatchfinder32(std::move(mv))
{
    //
}

kernelpatchfinder32_base::~kernelpatchfinder32_base(){
    //
}

#pragma mark Location finders
kernelpatchfinder::loc64_t kernelpatchfinder32_base::find_syscall0(){
    constexpr char sig_syscall_3[] = "\x06\x00\x00\x00\x03\x00\x0c\x00";
    loc_t sys3 = memmem(sig_syscall_3, sizeof(sig_syscall_3)-1);
    uint8_t syscall_entry_size = 0xc;
    loc_t syscall0 = 0;
    
verify:
    syscall0 = sys3 - (3 * syscall_entry_size) + 0x8;
    try {
        loc_t func0 = deref(syscall0) & ~1;
        vmem_thumb iter = _vmemThumb->getIter(func0);
        assure(iter() == arm32::push);
        _syscall_entry_size = syscall_entry_size;
        debug("Syscall entry size is 0x%x",_syscall_entry_size);
        return syscall0;
    } catch (...) {
        warning("Syscall entry size is not 0x%x",syscall_entry_size);
        if (syscall_entry_size == 0xc){
            syscall_entry_size = 0x10;
            goto verify;
        } else if (syscall_entry_size == 0x10){
            syscall_entry_size = 0x14;
            //Is this iOS 7 ???
            goto verify;
        } else{
            throw;
        }
    }
    reterror("this should be never reached!");
}

kernelpatchfinder::loc64_t kernelpatchfinder32_base::find_table_entry_for_syscall(int syscall){
    loc_t syscallTable = (loc_t)find_syscall0();
    return (syscallTable + (syscall-1)*_syscall_entry_size);
}

kernelpatchfinder::loc64_t kernelpatchfinder32_base::find_function_for_syscall(int syscall){
    return deref((loc_t)find_table_entry_for_syscall(syscall));
}

kernelpatchfinder::loc64_t kernelpatchfinder32_base::find_sbops(){
    loc_t str = findstr("Seatbelt sandbox policy", false);
    debug("str=0x%08x",str);
    
    patchfinder32::loc_t ref = -1;
    do{
        ref = memmem(&str, sizeof(str), ref+1);
        //ref cannot be misaligned in this case
    }while (ref & 3);
    debug("ref=0x%08x",ref);

    return (loc_t)deref(ref+0xc);
}

#pragma mark Patch finders
std::vector<patch> kernelpatchfinder32_base::get_MarijuanARM_patch(){
    std::vector<patch> patches;
    constexpr char release_arm[] = "RELEASE_ARM";
    constexpr char marijuanarm[] = "MarijuanARM";

    patchfinder32::loc_t strloc = -1;
    try {
        while ((strloc = memmem(release_arm, sizeof(release_arm)-1, strloc+1))) {
            patches.push_back({strloc,marijuanarm,sizeof(marijuanarm)-1});
        }
    } catch (...) {
        //
    }

    //everything is fine as long as we found at least one instance
    retassure(patches.size(), "Not a single instance of %s was found",release_arm);
    
    return patches;
}

std::vector<patch> kernelpatchfinder32_base::get_trustcache_true_patch(){
    std::vector<patch> patches;
    
    /*
        Maybe a little less cursed than 64bit variant.
     */

    vmem_thumb iter = _vmemThumb->getIter();

    try {
        for (int z=0;;z++) {
inloop:
            while (++iter != arm32::mla);
            vmem_thumb iter2 = iter;
            while ((++iter2).supertype() != sut_branch_imm)
                ;

            for (int i=0; i<14; i++) {
                if (++iter2 != arm32::ldrb) goto inloop;
                if (++iter2 != arm32::ldrb) goto inloop;
                if (++iter2 != arm32::cmp) goto inloop;
                if ((++iter2).supertype() != arm32::sut_branch_imm) goto inloop;
            }
            try {
                while (++iter2 != arm32::sub) {
                    assure(iter2() == arm32::ldrb);
                    assure(++iter2 == arm32::ldrb);
                    assure(++iter2 == arm32::cmp);
                    assure((++iter2).supertype() == arm32::sut_branch_imm);
                }
                retassure(++iter2 == arm32::cmp && iter2().imm() == 0, "should be cmp rx, 0 here");
            } catch (...) {
                goto inloop;
            }

            loc_t loc = iter;
            debug("loc=0x%08x",loc);
            loc_t loc2 = iter2;
            debug("loc2=0x%08x",loc2);
            loc_t found_bof = find_bof_thumb(iter);
            debug("found_bof=0x%08x",found_bof);
            
            retassure(loc-found_bof <= 0x100, "bof is too far away");
            
            /*
                mov r0, 1
                bx lr
             */
            pushINSN(thumb::new_T1_immediate_movs(found_bof, 1, 0));
            pushINSN(thumb::new_T1_general_bx(found_bof+2, 14));
            }
    } catch (...) {
        //
    }

    assure(patches.size()); //need at least one
    
    return patches;
}

std::vector<patch> kernelpatchfinder32_base::get_cs_enforcement_disable_amfi_patch(){
    std::vector<patch> patches;
    loc_t str = findstr("csflags",true);
    debug("str=0x%08x",str);
    bool isArmCode = false;
    
    loc_t ref = find_literal_ref_thumb(str);
    if (!ref){
        ref = find_literal_ref_arm(str);
        isArmCode = true;
    }
    debug("ref=0x%08x",ref);
    assure(ref);

    if (isArmCode) {
        vmem_arm iter = _vmemArm->getIter(ref);

        while (--iter != arm32::push);
        pushINSN(arm::new_A1_immediate_mov(iter, 0, 0));
        pushINSN(arm::new_A1_general_bx(iter.pc()+4, 14));
    }else{
        vmem_thumb iter = _vmemThumb->getIter(ref);

        while (--iter != arm32::push);
        pushINSN(thumb::new_T1_immediate_movs(iter, 0, 0));
        pushINSN(thumb::new_T1_general_bx(iter.pc()+2, 14));
    }

    return patches;
}

std::vector<patch> kernelpatchfinder32_base::get_amfi_validateCodeDirectoryHashInDaemon_patch(){
    UNCACHEPATCHES;
    loc_t memcmp = 0;
    if (haveSymbols()) {
        memcmp = find_sym("_memcmp");
    }else{
        reterror("unimplemented");
    }
    debug("memcmp=0x%08x",memcmp);
    
    /* find*/
    //movs r0, #0x0
    //bx lr
    vmem_thumb ret0 = _vmemThumb->getIter(memcmp);
    while (1) {
        while (++ret0 != arm32::mov || ret0().subtype() != st_immediate || ret0().rd() != 0 || ret0().imm() != 0)
            ;
        if (++ret0 == arm32::bx && ret0().rm() == 14 ){
            --ret0;
            break;
        }
    }
    loc_t ret0_gadget = ret0;
    ret0_gadget |= 1;
    debug("ret0_gadget=0x%08x",ret0_gadget);

    {
        loc_t str = findstr("int _validateCodeDirectoryHashInDaemon",false);
        debug("str=0x%08x",str);
        
        loc_t ref = find_literal_ref_thumb(str);
        if (!ref) ref = find_literal_ref_arm(str);
        debug("ref=0x%08x",ref);
        retassure(ref, "failed to find ref");
        
        {
            loc_t kext_start = ref &~3;
            while (static_cast<uint32_t>(deref(kext_start)) != 0xfeedface)
                kext_start-=4;
            debug("kext_start=0x%08x",kext_start);

            loc_t kext_end = kext_start+4;
            while (static_cast<uint32_t>(deref(kext_end)) != 0xfeedface)
                kext_end+=4;
            debug("kext_end=0x%08x",kext_end);
            
            for (;kext_start < kext_end; kext_start += 4){
                if ((deref(kext_start) & ~1) == (memcmp & ~1)){
                    patches.push_back({kext_start,&ret0_gadget,sizeof(ret0_gadget),slide_ptr});
                }
            }
        }
    }
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder32_base::get_mount_patch(){
    std::vector<patch> patches;
    
    loc_t mount = (loc_t)find_function_for_syscall(167);
    mount &= ~1;
    debug("mount=0x%08x",mount);

    vmem_thumb iter = _vmemThumb->getIter(mount);

    while (++iter != arm32::bl);

    loc_t mount_internal = iter().imm();
    debug("mount_internal=0x%08x",mount_internal);

    iter = mount_internal;

    while (++iter != arm32::orr || iter().subtype() != st_immediate || iter().imm() != 0x10000);

    loc_t pos = iter;
    debug("orr pos=0x%08x",pos);

    retassure(--iter == arm32::it, "expected it");
    for (int i=0;(++iter).supertype() != sut_branch_imm && i < 8; i++ )
        ;
    retassure(iter().supertype() == sut_branch_imm, "Failed to find branch imm");
    
    loc_t pos2 = iter;
    debug("pos2=0x%08x",pos2);
    
    //check for 'tst.w r5, #1'
    {
        arm32::thumb insn = iter - 1;
        if (insn != arm32::tst) insn = iter - 2;
        retassure(insn == arm32::tst && insn.imm() == 1 && (insn.rn() == 5 || insn.rn() == 0 /* compiler changes?? */), "expected tst.w r5, #1");
    }    
    //patch MNT_RDONLY check
    debug("patching MNT_RDONLY check ...");
    if (iter().insnsize() == 2) {
        pushINSN(arm32::thumb::new_T2_immediate_b(iter, iter().imm()));
    }else{
        if (iter().condition() == EQ) {
            pushINSN(arm32::thumb::new_T1_general_nop(iter.pc()));
            pushINSN(arm32::thumb::new_T1_general_nop(iter.pc() + 2));
        }else{
            reterror("unimplemented");
        }
    }
    
    return patches;
}

std::vector<patch> kernelpatchfinder32_base::get_sandbox_patch(){
    std::vector<patch> patches;
    loc_t sbops = (loc_t)find_sbops();
    debug("sbobs=0x%08x",sbops);
    

    /* find*/
    //movs r0, #0x0
    //bx lr
    vmem_thumb ret0 = _vmemThumb->getIter();
    while (1) {
        while (++ret0 != arm32::mov || ret0().subtype() != st_immediate || ret0().rd() != 0 || ret0().imm() != 0)
            ;
        if (++ret0 == arm32::bx && ret0().rm() == 14 ){
            --ret0;
            break;
        }
    }
    loc_t ret0_gadget = ret0;
    ret0_gadget |= 1;
    debug("ret0_gadget=0x%08x",ret0_gadget);
    
#define PATCH_OP(loc) \
    if (loc_t origval = deref(loc)) { \
        loc_t tmp = ret0_gadget; \
        patches.push_back({loc,&tmp,sizeof(tmp),slide_ptr}); \
    }
    
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_mount_check_mount));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_mount_check_remount));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_mount_check_umount));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_write));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_rename));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_fsgetpath));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_getattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_proc_check_get_cs_info));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_proc_check_set_cs_info));
    
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_file_check_mmap));

    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_access));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_chdir));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_chroot));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_create));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_deleteextattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_exchangedata));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_exec));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_getattrlist));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_getextattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_ioctl));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_kqfilter));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_label_update));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_link));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_listextattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_lookup));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_open));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_read));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_readdir));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_readlink));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_rename_from));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_rename_to));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_revoke));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_select));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setattrlist));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setextattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setflags));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setmode));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setowner));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setutimes));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_stat));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_truncate));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_unlink));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_write));

    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_mount_check_stat));

    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_create));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_open));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_post));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_unlink));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_wait));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_label_associate));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_label_destroy));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_label_init));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_create));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_mmap));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_open));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_stat));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_truncate));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_unlink));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_label_associate));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_label_destroy));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_label_init));

    //watchOS??
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_notify_create));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_proc_check_fork));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_iokit_check_get_property));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_accept));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_accepted));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_bind));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_connect));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_create));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_label_update));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_listen));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_receive));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_received));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_select));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_send));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_stat));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_setsockopt));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_socket_check_getsockopt));
    
    return patches;
#undef PATCH_OP
}

std::vector<patch> kernelpatchfinder32_base::get_allow_UID_key_patch(){
    UNCACHEPATCHES;

    loc_t aes_cbc_str = findstr("AES-CBC", true);
    debug("aes_cbc_str=0x%08x",aes_cbc_str);
    
    loc_t aes_cbc_ref = find_literal_ref(aes_cbc_str);
    debug("aes_cbc_ref=0x%08x",aes_cbc_ref);

    aes_cbc_ref+=1;
    loc_t vtable_ref = memmem(&aes_cbc_ref, sizeof(uint32_t),aes_cbc_ref);
    debug("vtable_ref=0x%08x",vtable_ref);
    
    vtable_ref += 4;
    
    loc_t cryptofunc = deref(vtable_ref) & ~1;
    debug("cryptofunc=0x%08x",cryptofunc);
    
    auto iter = _vmemThumb->getIter(cryptofunc);
    
    while ((++iter).supertype() != sut_branch_imm)
        ;
    retassure(iter() != arm32::bl, "shouldn't be bl");
    
    loc_t badLoc = iter().imm();
    debug("badLoc=0x%08x",badLoc);
    
    do{
        if (iter().supertype() == sut_branch_imm && iter().imm() == badLoc){
            pushINSN(arm32::thumb::new_T2_register_mov(iter(), 0, 0));
            if (iter().insnsize() != 2){
                pushINSN(arm32::thumb::new_T2_register_mov(++iter, 0, 0));
            }
        }
    }while (++iter != arm32::pop);
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder32_base::get_force_NAND_writeable_patch(){
    std::vector<patch> patches;
    
    loc_t str = findstr(" NAND is not writable", false);
    retassure(str, "Failed to find str");
    {
        const char *strbuf = (const char *)memoryForLoc(str);
        int offset = 0;
        while (strbuf[offset]) offset--;
        str += offset + 1;
    }
    debug("str=0x%08x",str);

    loc_t ref = find_literal_ref_thumb(str);
    debug("ref=0x%08x",ref);

    vmem_thumb iter = _vmemThumb->getIter(ref);

    while (--iter != arm32::bl)
        ;
    while (--iter != arm32::bl) {
        auto insn = iter();
        if (insn == arm32::cbz && insn.rn() == 0) {
            pushINSN(thumb::new_T1_general_nop(insn.pc()));
            if (insn.insnsize() == 4) {
                pushINSN(thumb::new_T1_general_nop(insn.pc() + 2));
            }
        }
    }

end:
    retassure(patches.size(), "Failed to find at least one patch");
    return patches;
}

std::vector<patch> kernelpatchfinder32_base::get_i_can_has_debugger_patch(){
    std::vector<patch> patches;

    loc_t func_i_can_has_debugger = find_sym("_PE_i_can_has_debugger");
    debug("func_i_can_has_debugger=0x%08x",func_i_can_has_debugger);
    pushINSN(thumb::new_T1_immediate_movs(func_i_can_has_debugger, 1, 0));
    pushINSN(thumb::new_T1_general_bx(func_i_can_has_debugger+2, 14));

    return patches;
}


std::vector<patch> kernelpatchfinder32_base::get_AppleImage3NORAccess_hide_failure_patch(){
    std::vector<patch> patches;
    
    loc_t pos = find_literal_ref_thumb(0x80000061);
    debug("pos=0x%08x",pos);

    
    reterror("todo");
    return patches;
}

std::vector<patch> kernelpatchfinder32_base::get_read_bpr_patch(){
    loc_t ml_io_map = find_sym("_ml_io_map") | 1;
    debug("ml_io_map=0x%08x",ml_io_map);
    
    loc_t kernel_store = find_sym("__giDebugReserved2");
    debug("kernel_store=0x%08x",kernel_store);

    loc_t kmem_free = find_sym("_kmem_free") | 1;
    debug("kmem_free=0x%08x",kmem_free);
    
    loc_t release_uname_str = findstr("RELEASE_ARM_", false);
    debug("release_uname_str=0x%08x",release_uname_str);
    const char *release_uname_str_ptr = (const char*)memoryForLoc(release_uname_str);
    release_uname_str_ptr+=sizeof("RELEASE_ARM_")-1;
    while (*release_uname_str_ptr && isalpha(*release_uname_str_ptr)) release_uname_str_ptr++;
    
    loc_t bpr_addr = 0;
    int cpid = atoi(release_uname_str_ptr);
    debug("cpid=0x%d",cpid);
    switch (cpid) {
        case 8004:
        case 8002: //I'm not sure why, but leave this here :o
            bpr_addr = 0x481d0030/*t8004*/;
            break;
            
        default:
            reterror("unimplemented CPID=%d",cpid);
    }

    debug("bpr_addr=0x%08x",bpr_addr);
    return get_read_bpr_patch_with_params(213, bpr_addr, ml_io_map, kernel_store, kmem_free);
}

std::vector<patch> kernelpatchfinder32_base::get_noemf_patch(){
    UNCACHEPATCHES;
    loc_t func = find_sym("_bufattr_cpx");
    debug("func=0x%08x",func);
    assure(func);
    pushINSN(thumb::new_T1_immediate_movs(func, 0, 0));
    pushINSN(thumb::new_T1_general_bx(func+2, 14));
    RETCACHEPATCHES;
}

#pragma mark Util
kernelpatchfinder::loc64_t kernelpatchfinder32_base::find_rootvnode() {
    return find_sym("_rootvnode");
}


#pragma mark combo utils
std::vector<patch> kernelpatchfinder32_base::get_codesignature_patches(){
    std::vector<patch> patches;
    addPatches(get_amfi_validateCodeDirectoryHashInDaemon_patch());
    addPatches(get_cs_enforcement_disable_amfi_patch());
    return patches;;
}

#pragma mark non-override
std::vector<patch> kernelpatchfinder32_base::get_read_bpr_patch_with_params(int syscall, loc_t bpr_reg_addr, loc_t ml_io_map, loc_t kernel_store, loc_t kmem_free){
    std::vector<patch> patches;

    const char readbpr[] =
    "\xF0\xB5\x13\x48\x20\xF0\xFF\x00\x20\xF4\x70\x60\x41\xF2\x00\x01\x10\x4A\x7C\x46\x16\x3C\x22\x44\x0F\x4F\x27\x44\x00\xBF\x3B\x68\x00\x2B\x01\xD1\x90\x47\x03\x46\x3B\x60\x09\x49\x40\xF6\xFF\x70\x01\x40\x5B\x18\x1D\x68\x00\xBF\x4F\xF6\xFF\x70\x05\x40\x4F\xF0\x82\x40\x40\xF4\x82\x00\x40\xEA\x05\x00\xBD\xE8\xF0\x80\x00\xBF";
    
    loc_t table = (loc_t)find_table_entry_for_syscall(syscall);
    debug("table=0x%08x",table);
    loc_t nops = findnops((sizeof(readbpr)-1+4+4*3)/4);
    nops += 4;
    nops &= ~3;
    debug("nops=0x%08x",nops);

    patches.push_back({nops,readbpr,sizeof(readbpr)-1});

    patches.push_back({nops+sizeof(readbpr)-1+4*0,&bpr_reg_addr, sizeof(bpr_reg_addr)});

    ml_io_map -= nops;
    patches.push_back({nops+sizeof(readbpr)-1+4*1,&ml_io_map, sizeof(ml_io_map)});

    kernel_store -= nops;
    patches.push_back({nops+sizeof(readbpr)-1+4*2,&kernel_store, sizeof(kernel_store)});
    
    nops |= 1;
    patches.push_back({table,&nops,sizeof(nops)});

    return patches;
}

#pragma mark utils
void kernelpatchfinder32_base::slide_ptr(class patch *p, uint64_t slide){
    slide += *(uint32_t*)p->_patch;
    memcpy((void*)p->_patch, &slide, 4);
}
