//
//  kernelpatchfinder64_iOS12.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 22.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//
#include <libgeneral/macros.h>

#include "kernelpatchfinder64_iOS12.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "kernelpatchfinder64_iOS13.hpp"
#include "../all64.h"
#include "sbops64.h"

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

std::vector<patch> kernelpatchfinder64_iOS12::get_codesignature_patches(){
    UNCACHEPATCHES;
    try {
        return get_trustcache_true_patch();
    } catch (tihmstar::exception &e) {
        error("Failed to get_trustcache_true_patch with error=%d (%s)",e.code(),e.what());
        e.dump();
        warning("Fallback to old-style amfi patches");
        
        addPatches(get_amfi_validateCodeDirectoryHashInDaemon_patch());
        addPatches(get_cs_enforcement_disable_amfi_patch());
        RETCACHEPATCHES;
    }
}

std::vector<patch> kernelpatchfinder64_iOS12::get_mount_patch(){
    UNCACHEPATCHES;
    
    loc_t mount = find_function_for_syscall(167);
    vmem iter = _vmem->getIter();
    
    try {
        iter = mount | 0xffffffUL << (6*8);;
    } catch (...) {
        warning("Failed to deref mount ptr, retrying with iOS 16 chains");
        iter = (mount & 0xFFFFFFFF) + _base;
    }
    
    debug("mount=0x%016llx\n",iter.pc());

    while (++iter != insn::bl);
    
    loc_t mount_internal = iter().imm();
    debug("mount_internal=0x%016llx\n",mount_internal);

    
    iter = mount_internal;
    
    while (++iter != insn::orr || iter().imm() != 0x10000);
    
    loc_t pos = iter;
    debug("pos=0x%016llx\n",pos);


    loc_t ref = 0;
    try {
        ref = find_branch_ref(pos, -0x100);
    } catch (...) {
        retassure(--iter == insn::tbz, "Failed to find ref");
        ref = iter;
    }
    
    debug("ref=0x%016llx\n",ref);

    iter = ref;
    
    while (--iter != insn::ldrb)
        ;
    {
        loc_t p1 = iter;
        if (++iter == insn::tbz) {
            loc_t p1dst = iter().imm();
            auto iter2 = _vmem->getIter(p1dst);
            /*
                We really should include the MNT_UPDATE automatically here
             */
            if (--iter2 == insn::orr && iter2().imm() == 0x10000){
                p1 = iter;
                debug("p1=0x%016llx\n",p1);
                pushINSN(insn::new_immediate_b(iter, iter2));
                p1 = 0;
            }
        }
        if (p1){
            debug("p1=0x%016llx\n",p1);
            iter = p1;
            pushINSN(insn::new_immediate_movz(iter, 0, iter().rn(), 0));
        }
    }
    
    while ((--iter != insn::tbz || iter().special() != 5) && (iter() != insn::tbnz || iter().special() != 5));

    loc_t p2 = iter;
    debug("p2=0x%016llx\n",p2);

    loc_t p2dst = iter().imm();
    debug("p2dst=0x%016llx\n",p2dst);
    
    if (iter() == insn::tbnz) {
        pushINSN(insn::new_general_nop(p2));
    }else{
        pushINSN(insn::new_immediate_b(p2, p2dst));
    }
    
    /* ---- allow mounting / as root ---- */

    loc_t str = findstr("%s:%d: not allowed to mount as root\n", true);
    debug("str=0x%016llx\n",str);

    ref = find_literal_ref(str);
    debug("ref=0x%016llx\n",ref);

    iter = ref;
    
    while (--iter != insn::cmp)
        ;
    
    debug("p2=0x%016llx\n",(loc_t)iter);

    patches.push_back({iter, "\x1F\x00\x00\xEB" /* cmp x0, x0 */, 4});
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS12::get_sandbox_patch(){
    UNCACHEPATCHES;
    
    patchfinder64::loc_t sbops = find_sbops();
    //pointer now contain linker information :o
    sbops |= 0xffff000000000000;
    
    debug("sbobs=0x%016llx",sbops);
    
    vmem iter = _vmem->getIter();
        
    do{
        ++iter;
        while (++iter != insn::ret || iter().pactype() != insn::pac_none);
    }while (--iter != insn::movz || iter().rd() != 0 || iter().imm() != 0);
        
    patchfinder64::loc_t ret0gadget = iter;
    debug("ret0gadget=0x%016llx",ret0gadget);
        
#define PATCH_OP(loc) \
    if (uint64_t origval = deref(loc)) { \
        patchfinder64::loc_t tmp = 0; \
        if (((origval>>36) != 0xfffffff) && (origval & (1LLU<<63))) \
            tmp = ((ret0gadget-_base) & 0xFFFFFFFF) | (origval & 0xFFFFFFFF00000000); /* PACed pointers (iPhone11,2) */ \
        else \
            tmp = (ret0gadget & 0x0000ffffffffffff) | (origval & 0xffff000000000000); \
        patches.push_back({loc,&tmp,sizeof(tmp)}); \
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

#undef PATCH_OP

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS12::get_no_nonce_entanglement_patch(){
    UNCACHEPATCHES;
    loc_t str = findstr("entangle-nonce",true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    auto iter = _vmem->getIter(ref);
    
    while ((++iter).supertype() != libinsn::arm64::insn::sut_branch_imm)
        ;
    
    loc_t tgt = iter;
    debug("tgt=0x%016llx",tgt);
    
    if (iter() == insn::cbz && iter().rt() == 0) {
        pushINSN(insn::new_immediate_b(iter, iter().imm()));
    }else if (iter() == insn::cbnz && iter().rt() == 0){
        pushINSN(insn::new_general_nop(iter));
    }else{
        reterror("Unexpected insn");
    }

    RETCACHEPATCHES;
}
