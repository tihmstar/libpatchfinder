//
//  kernelpatchfinder64_iOS16.cpp
//  libpatchfinder
//
//  Created by tihmstar on 08.06.22.
//

#include "kernelpatchfinder64_iOS16.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"
#include "sbops64.h"
#include <string.h>

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_boot_args_commandline_offset(){
    UNCACHELOC;
    
    std::string s = "-x";
    s.insert(s.begin(), 0);
    loc_t str = findstr(s, true);
    debug("str=0x%016llx",str);
    assure(str);
    
    loc_t ref = find_literal_ref(str+1);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    while (++iter != insn::bl)
        ;
    
    loc_t PE_parse_boot_argn = iter().imm();
    debug("PE_parse_boot_argn=0x%016llx",PE_parse_boot_argn);
    
    while (--iter != insn::add || iter().rd() != 0)
        ;
    offset_t bootargOffset = iter().imm();
    RETCACHELOC(bootargOffset);
}

std::vector<patch> kernelpatchfinder64_iOS16::get_trustcache_true_patch(){
    UNCACHEPATCHES;

    vmem iter = _vmem->getIter();
    loc_t orr1pos = 0;
    while (!orr1pos) {
    retry_loop:
        while (++iter != insn::adrp && (iter() != insn::adr))
               ;
        vmem iter2 = iter;
        int foundBlrs = 0;
        for (int i=0; i<20; i++) {
            auto curinsn = ++iter2;
            if (curinsn == insn::blr || curinsn == insn::blraa) foundBlrs++;
            else if (curinsn == insn::orr){
                if (foundBlrs == 2 && curinsn.rd() == 0 && curinsn.imm() == 1) {
                    orr1pos = iter2;
                    for (int j=0; j<15; j++) {
                        if (++iter2 == insn::ret) goto found_func;
                    }
                    orr1pos = 0;
                    goto retry_loop;
                found_func:;
                    break;
                }
            }
        }
    }
    debug("orr1pos=0x%016llx",orr1pos);
    ++iter;
    loc_t bof = find_bof(orr1pos);
    debug("bof=0x%016llx",bof);

    pushINSN(insn::new_immediate_movz(bof, 1, 0, 0));
    pushINSN(insn::new_general_ret(bof+4));

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_codesignature_patches(){
    UNCACHEPATCHES;

    //add disabling launch constraints
    loc_t str = findstr("amfi_enforce_launch_constraints", true);
    debug("str=0x%16llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%16llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl)
        ;
    ++iter;
    retassure(iter() == insn::mov && iter().rm() == 0, "unexpected insn");
    uint8_t rd = iter().rd();
    
    while (++iter != insn::cbz || iter().rt() != rd) {
        retassure(iter() != insn::ret, "unexpected end of function");
    }
    loc_t badloc = iter().imm();
    debug("badloc=0x%16llx",badloc);

    loc_t goodloc = badloc-4;
    iter = goodloc;
    retassure(iter() == insn::str, "unexpected insn, expected str");
    
    uint8_t srcreg = iter().rn();
    
    loc_t is_launch_constraints_enforced = find_register_value(goodloc, srcreg, goodloc-0x10);
    is_launch_constraints_enforced += iter().imm();
    debug("is_launch_constraints_enforced=0x%16llx",is_launch_constraints_enforced);
    {
        uint32_t zero = 0;
        patches.push_back({is_launch_constraints_enforced,&zero,sizeof(zero)});
    }
    
    {
        //Hello iOS 16.4!
        loc_t query_trust_cache = find_sym("_query_trust_cache");
        if (!query_trust_cache) {
            warning("Failed to get query_trust_cache symbol, ignoring...");
        }else{
            debug("query_trust_cache=0x%016llx",query_trust_cache);
            loc_t stub_ptr = _vmem->memmem(&query_trust_cache, sizeof(query_trust_cache));
            debug("stub_ptr=0x%016llx",stub_ptr);
            
            loc_t stub_query_trust_cache = find_literal_ref(stub_ptr);
            assure(stub_query_trust_cache);
            stub_query_trust_cache -=4;
            debug("stub_query_trust_cache=0x%016llx",stub_query_trust_cache);
            
            try {
                loc_t trustcache_check_call = find_call_ref(stub_query_trust_cache,1);
                debug("trustcache_check_call=0x%016llx",trustcache_check_call);
                
                loc_t trustcache_check = find_bof(trustcache_check_call);
                debug("trustcache_check=0x%016llx",trustcache_check);
                pushINSN(insn::new_immediate_movz(trustcache_check+4*0, 1, 0, 0));
                pushINSN(insn::new_immediate_cbz(trustcache_check+4*1, trustcache_check+4*3, 2));
                pushINSN(insn::new_immediate_str_unsigned(trustcache_check+4*2, 0, 2, 0));
                pushINSN(insn::new_general_ret(trustcache_check+4*3));
            } catch (...) {
                warning("Failed to get iOS 16.4 trustcache_check patch, ignoring...");
            }
        }
    }
    
    //add usual patches
    addPatches(get_trustcache_true_patch());
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_force_boot_ramdisk_patch(){
    UNCACHEPATCHES;

    {
        //no rootfs auth patch
        loc_t str = findstr("rootvp not authenticated after mounting", false);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);

        vmem iter = _vmem->getIter(ref);
        
        while (--iter != insn::cbnz)
            ;
        
        loc_t btgt = iter+1;
        debug("btgt=0x%16llx",btgt);
        
        for (int i=0; i<10; i++) {
            while (--iter != insn::bl)
                ;
            loc_t x1val = find_register_value(iter, 1,iter.pc()-0x20);
            if (!x1val) continue;
            try {
                if (strcmp((const char*)_vmem->memoryForLoc(x1val), "rd") == 0) goto found_patch;
            } catch (...) {
                //
            }
        }
        reterror("Failed to find function");
    found_patch:
        pushINSN(insn::new_immediate_b(iter, btgt));
    }
    
    {
        //IOFindBSDRoot patch
        loc_t str = findstr("!BSD\n", true);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);
        
        vmem iter = _vmem->getIter(ref);


        while (true) {
            while (++iter != insn::bl)
                ;
            loc_t x1val = find_register_value(iter, 1,iter.pc()-0x20);
            if (!x1val) continue;
            try {
                if (strcmp((const char*)_vmem->memoryForLoc(x1val), "rd") != 0) continue;
            } catch (...) {
                continue;
            }
            
            ++iter;
            retassure(iter() == insn::cbnz, "unexpected insn");
            loc_t bdst = iter().imm();
            loc_t shellcodeEnd = iter;
            debug("shellcodeEnd=0x%16llx",shellcodeEnd);
            while (--iter != insn::mov || iter().rd() != 2)
                ;
            ++iter;
            loc_t shellcodeBegin = iter;
            debug("shellcodeBegin=0x%16llx",shellcodeBegin);
            retassure((shellcodeEnd-shellcodeBegin)/4 >= 3, "not enough room for shellcode");
            pushINSN(insn::new_immediate_movz(shellcodeBegin+0x00, 0x646d, 0, 0));
            pushINSN(insn::new_immediate_movk(shellcodeBegin+0x04, 0x30, 0, 16));
            pushINSN(insn::new_immediate_str_unsigned(shellcodeBegin+0x08, 0, 2, 0));
            pushINSN(insn::new_immediate_b(shellcodeBegin+0x0c, bdst));
            break;
        }
    }
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_read_bpr_patch_with_params(int syscall, loc_t bpr_reg_addr, loc_t ml_io_map, loc_t kernel_map, loc_t kmem_free){
    UNCACHEPATCHES;

    loc_t bss_space = find_bss_space(16,false);
    if (bss_space & 7) {
        bss_space +=8;
        bss_space &= ~7;
    }
    debug("bss_space=0x%016llx",bss_space);

    loc_t table = find_table_entry_for_syscall(syscall);
    debug("table=0x%016llx",table);

    uint32_t shellcode_insn_cnt = 25; //commitment
    loc_t shellcode = 0;
    try {
        shellcode = findnops(shellcode_insn_cnt);
    } catch (...) {
        shellcode = findnops(shellcode_insn_cnt, true, 0x00000000);
    }
    debug("shellcode=0x%016llx",shellcode);
    
    uint32_t afterMapInsn = 12; //commitment
    uint32_t addrpos = 23; //commitment
    uint32_t ml_map_io_stubInsn = 22; //commitment

#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    
    pushINSN(insn::new_immediate_sub(cPC, 0x10, 31, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x00, 29, 30, 31));
    try {
        pushINSN(insn::new_general_adr(cPC, bss_space, 0));
        pushINSN(insn::new_register_mov(cPC, 0, 29, 0));
    } catch (...) {
        --insnNum;//was incremented before without using the instruction space by adr
        pushINSN(insn::new_general_adrp(cPC, (bss_space & ~0xfff), 0));
        pushINSN(insn::new_immediate_add(cPC, bss_space & 0xfff, 0, 29));
    }
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0, 29, 0));
    pushINSN(insn::new_immediate_cmp(cPC, 0, 0));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+afterMapInsn*4, insn::cond::NE));
    
    pushINSN(insn::new_literal_ldr(cPC, shellcode+addrpos*4, 0));
    pushINSN(insn::new_immediate_movz(cPC, 0x4000, 1, 0));
    {
        uint32_t opcode = 0x9272C400; //and x0, x0, #0xffffffffffffc000
        patches.push_back({cPC, &opcode,sizeof(opcode)});
    }
    pushINSN(insn::new_immediate_bl(cPC, shellcode+ml_map_io_stubInsn*4));
    pushINSN(insn::new_immediate_str_unsigned(cPC, 0, 29, 0));
    assure(insnNum == afterMapInsn);
    pushINSN(insn::new_literal_ldr(cPC, shellcode+addrpos*4, 1));
    {
        uint32_t opcode = 0x92403421; //x1, x1, #0x3fff
        patches.push_back({cPC, &opcode,sizeof(opcode)});
    }
    pushINSN(insn::new_register_add(cPC, 0, 1, 0, 1));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0, 1, 29, true));
    pushINSN(insn::new_immediate_movz(cPC, 0x4141, 0, 16));
    {
        uint32_t opcode = 0x92403FBD; //and fp, fp, #0xffff
        patches.push_back({cPC, &opcode,sizeof(opcode)});
    }
    pushINSN(insn::new_register_add(cPC, 0, 0, 29, 0));
    pushINSN(insn::new_general_ldp_offset(cPC, 0, 29, 30, 31));
    pushINSN(insn::new_immediate_add(cPC, 0x10, 31, 31));
    pushINSN(insn::new_general_ret(cPC));
    assure(insnNum == ml_map_io_stubInsn);
    pushINSN(insn::new_immediate_b(cPC, ml_io_map));
    assure(insnNum == addrpos);
    patches.push_back({cPC,&bpr_reg_addr,sizeof(bpr_reg_addr)}); cPC;
    assure(insnNum == shellcode_insn_cnt);
#undef cPC
    
    //hello linkerinfo in pointers
    uint64_t funcptr = _vmem->deref(table) & 0xffffffff00000000;
    funcptr |= (shellcode & 0xffffffff);
    patches.push_back({table,&funcptr,sizeof(funcptr)});
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_mount_patch(){
    UNCACHEPATCHES;
    addPatches(kernelpatchfinder64_iOS15::get_mount_patch());
    
    loc_t str = findstr("Updating mount to read/write mode is not allowed", false);
    if (str) {
        debug("Found 'Updating mount to read/write mode is not allowed' str, adding additional apfs update rw patch");
        while (_vmem->deref(str) & 0xff) str--;
        str++;
        debug("str=0x%016llx",str);
        
        loc_t ref = find_literal_ref(str);
        debug("ref=0x%016llx",ref);

        vmem iter = _vmem->getIter(ref);
        
        while (--iter != insn::ldr){
            auto isn = iter();
            if (isn.supertype() == insn::sut_branch_imm && isn != insn::bl){
                /*
                 If we reached a non-conditional jump (which isn't bl),
                 then the code below can only be reached by jumping there
                 */
                ++iter;
                break;
            }
        }
        
        loc_t jmpsrc = find_branch_ref(iter, -0x500);
        debug("jmpsrc=0x%016llx",jmpsrc);

        pushINSN(insn::new_general_nop(jmpsrc));
    }
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_apfs_skip_authenticate_root_hash_patch(){
    UNCACHEPATCHES;
    
    loc_t str = findstr("\"could not authenticate personalized root hash!", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);
    
    pushINSN(insn::new_immediate_movz(bof, 0, 0, 0));
    pushINSN(insn::new_general_ret(bof+4));

    RETCACHEPATCHES;
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_sbops(){
    UNCACHELOC;
    try {
        RETCACHELOC(kernelpatchfinder64_iOS15::find_sbops());
    } catch (...) {
        //
    }
    patchfinder64::loc_t str = findstr("Seatbelt sandbox policy", false);
    retassure(str, "Failed to find str");
    debug("str=0x%16llx",str);
    str -= _base;
    patchfinder64::loc_t ref = 0;
    retassure(ref = _vmem->memmem(&str, 4), "Failed to find ref");
    debug("ref=0x%16llx",ref);

    loc_t retval = (patchfinder64::loc_t)_vmem->deref(ref+0x18);
    RETCACHELOC(retval);
}

std::vector<patch> kernelpatchfinder64_iOS16::get_sandbox_patch(){
    UNCACHEPATCHES;
    try {
        return kernelpatchfinder64_iOS15::get_sandbox_patch();
    } catch (...) {
        //
    }

    patchfinder64::loc_t sbops = find_sbops();
    //pointer now contain linker information :o
    sbops = (sbops & 0xFFFFFFFF) + _base;
    
    debug("sbobs=0x%016llx",sbops);
    
    vmem iter = _vmem->getIter();
        
    do{
        ++iter;
        while (++iter != insn::ret);
    }while (--iter != insn::movz || iter().rd() != 0 || iter().imm() != 0);
        
    patchfinder64::loc_t ret0gadget = iter;
    debug("ret0gadget=0x%016llx",ret0gadget);
        
#define PATCH_OP(loc) \
    if (uint64_t origval = _vmem->deref(loc)) { \
        patchfinder64::loc_t tmp = ((ret0gadget-_base) & 0xFFFFFFFF) | (origval & 0xFFFFFFFF00000000); \
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
#undef PATCH_OP

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_task_conversion_eval_patch(){
    UNCACHEPATCHES;
    
    loc_t str = findstr("Just like pineapple on pizza, this task/thread port doesn't belong here.", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t task_conversion_eval_internal = find_bof(ref);
    debug("task_conversion_eval_internal=0x%016llx",task_conversion_eval_internal);

    loc_t ktask = find_kerneltask();
    debug("ktask=0x%016llx",ktask);
    
    loc_t tref = find_literal_ref(ktask,0,task_conversion_eval_internal);
    debug("tref=0x%016llx",tref);

    vmem iter = _vmem->getIter(tref);
    
    uint8_t ktask_reg = iter().rt();
    
    for (int i=0; i<10; i++) {
        auto isn = ++iter;
        
        if (isn == insn::cmp) {
            uint8_t reg1 = isn.rm();
            uint8_t reg2 = isn.rn();
            
            uint8_t greg = reg1 + reg2;
            
            if (greg == ktask_reg || greg == 1){
                /*
                    check if we are comparing "ktask_reg with X0" or "X1 with X0"
                    check if next branch goes to epilogue
                    then replace with "cmp x0, x0"
                 */
                vmem iter2(iter);
                if (++iter2 != insn::bcond) continue;
                iter2 = iter2().imm();
                if (iter2() != insn::mov || iter2().rd() != 0) continue;
                
                pushINSN(insn::new_register_cmp(iter, 0, 0, 0, -1));
                goto gotpatches;
            }
        }
    }
    reterror("failed to find patch");
gotpatches:;
    retassure(patches.size(), "Failed to find a patch");
    RETCACHEPATCHES;
}
