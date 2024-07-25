//
//  kernelpatchfinder64_base.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 20.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include "kernelpatchfinder64_base.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"
#include "sbops64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

#pragma mark kernelpatchfinder64_base
kernelpatchfinder64_base::kernelpatchfinder64_base(const char *filename)
: kernelpatchfinder64(filename)
{
    //
}

kernelpatchfinder64_base::kernelpatchfinder64_base(const void *buffer, size_t bufSize, bool takeOwnership)
: kernelpatchfinder64(buffer, bufSize, takeOwnership)
{
    //
}

kernelpatchfinder64_base::kernelpatchfinder64_base(kernelpatchfinder64 &&mv)
: kernelpatchfinder64(std::move(mv))
{
    //
}

kernelpatchfinder64_base::~kernelpatchfinder64_base(){
    //
}

#pragma mark utils
static void slide_ptr(class patch *p, uint64_t slide){
    slide += *(uint64_t*)p->getPatch();
    memcpy((void*)p->getPatch(), &slide, 8);
}

#pragma mark Location finders
patchfinder64::loc_t kernelpatchfinder64_base::find_syscall0(){
    UNCACHELOC;
    constexpr char sig_syscall_3[] = "\x06\x00\x00\x00\x03\x00\x0c\x00";
    patchfinder64::loc_t sys3 = memmem(sig_syscall_3, sizeof(sig_syscall_3)-1);
    loc_t retval = sys3 - (3 * 0x20) + 0x8;
    RETCACHELOC(retval);
}

patchfinder64::loc_t kernelpatchfinder64_base::find_machtrap_table(){
    UNCACHELOC;
    patchfinder64::loc_t table = 0;
    
    vmem iter(_vmem, 0, kVMPROTALL);
    
    for (;;iter.nextSeg()) {
        auto curSegSize = iter.curSegSize();
        auto curSegBase = iter.pc();
        if (curSegSize < 10)
            continue;
        
        uint8_t *beginptr = (uint8_t *)iter.memoryForLoc(curSegBase);
        uint8_t *endptr = (uint8_t *)beginptr + iter.curSegSize();
        for (uint8_t *p = beginptr; p < endptr; p+=8) {
            int onefailed = 0;
            uint64_t *pp = (uint64_t*)p;
            
            if (!pp[0] || pp[1] || pp[2] || pp[3])
                continue;
            
            for (int z=0; z<4; z++) {
                if (memcmp(p, &p[z*4*8], 4*8)) {
                    onefailed = 1;
                    break;
                }
            }
            if (onefailed)
                continue;
            table = p-beginptr + curSegBase;
            goto foundpos;
        }
    }
foundpos:
    RETCACHELOC(table);
}


patchfinder64::loc_t kernelpatchfinder64_base::find_table_entry_for_syscall(int syscall){
    patchfinder64::loc_t syscallTable = find_syscall0();
    return (syscallTable + 4*(syscall-1)*sizeof(uint64_t));
}

patchfinder64::loc_t kernelpatchfinder64_base::find_function_for_syscall(int syscall){
    return deref(find_table_entry_for_syscall(syscall));
}

patchfinder64::loc_t kernelpatchfinder64_base::find_function_for_machtrap(int trapcall){
    patchfinder64::loc_t machtrapTable = find_machtrap_table();
    patchfinder64::loc_t tableEntry =machtrapTable + 4*8*trapcall;
    return deref(tableEntry);
}

patchfinder64::loc_t kernelpatchfinder64_base::find_kerneltask(){
    UNCACHELOC;
    patchfinder64::loc_t strloc = findstr("current_task() == kernel_task", true);
    debug("strloc=0x%016llx\n",strloc);
    
    patchfinder64::loc_t strref = find_literal_ref(strloc);
    debug("strref=0x%016llx\n",strref);

    patchfinder64::loc_t bof = find_bof(strref);
    debug("bof=0x%016llx\n",bof);
    
    vmem iter = _vmem->getIter(bof);

    patchfinder64::loc_t kernel_task = 0;
    
    do{
        if (++iter == insn::mrs) {
            if (iter().special() == insn::systemreg::tpidr_el1) {
                uint8_t xreg = iter().rt();
                uint8_t kernelreg = (uint8_t)-1;
                
                vmem iter2(iter,(patchfinder64::loc_t)iter);
                
                for (int i=0; i<5; i++) {
                    switch ((++iter2).type()) {
                        case insn::adrp:
                            kernel_task = iter2().imm();
                            kernelreg = iter2().rd();
                            break;
                        case insn::ldr:
                            if (kernelreg == iter2().rt()) {
                                kernel_task += iter2().imm();
                            }
                            break;
                        case insn::cmp:
                            if ((kernelreg == iter2().rm() && xreg == iter2().rn())
                                || (xreg == iter2().rm() && kernelreg == iter2().rn())) {
                                RETCACHELOC(kernel_task);
                            }
                            break;
                        default:
                            break;
                    }
                }
                kernel_task = 0;
            }
        }
    }while (iter < strref);
    reterror("failed to find kernel_task");
}

#pragma mark Patch finders
std::vector<patch> kernelpatchfinder64_base::get_MarijuanARM_patch(){
    UNCACHEPATCHES;
    constexpr char release_arm[] = "RELEASE_ARM";
    constexpr char marijuanarm[] = "MarijuanARM";

    patchfinder64::loc_t strloc = -1;
    try {
        while ((strloc = memmem(release_arm, sizeof(release_arm)-1, strloc+1))) {
            patches.push_back({strloc,marijuanarm,sizeof(marijuanarm)-1});
        }
    } catch (...) {
        //
    }

    //everything is fine as long as we found at least one instance
    retassure(patches.size(), "Not a single instance of %s was found",release_arm);
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_task_conversion_eval_patch(){
    UNCACHEPATCHES;
    
    /*
     if (caller == kernel_task) {
         return KERN_SUCCESS;
     }

     if (caller == victim) {
         return KERN_SUCCESS;
     }
     */
    
    /* -> This inlines to -> */
    
    /*
     mrs        x8, tpidr_el1
     ldr        x8, [x8, #0x368]
     ldr        x21, [x21, #0x68]
     adrp       x9, #0xfffffff008895000 ; 0xfffffff008895200@PAGE
     ldr        x9, [x9, #0x200] ; 0xfffffff008895200@PAGEOFF, kernel_task
     cmp        x8, x21
     ccmp       x9, x8, #0x4
     b.ne       loc_fffffff0075f1c54
     */
    
    /*
     patch:
     ccmp       x9, x8, #0x4
     to:
     ccmp       x8, x8, #0x4
     */
    
    patchfinder64::loc_t kernel_task = find_kerneltask();
    debug("kernel_task=0x%016llx\n",kernel_task);

    vmem iter = _vmem->getIter();
    
    while (true) {
        try {
            ++iter;
        } catch (out_of_range &e) {
            break;
        }
        
        if (iter() == insn::mrs && iter().special() == insn::systemreg::tpidr_el1) {
            vmem iter2(iter,(patchfinder64::loc_t)iter);
            int8_t regtpidr = iter().rt();
            int8_t regThisTask = -1;
                          
            int cntCmp = 0;
            
            for (int i=0; i<100; i++) {
                switch ((++iter2).type()) {
                    case insn::ldr:
                        if (iter2().rn() == regtpidr) {
                            regThisTask = iter2().rt();
                        }
                        break;
                    case insn::ccmp:
                        if (iter2().special() != 0x4) break;
                        //intentionally fall through
                    case insn::cmp:
                        if (cntCmp > 0) cntCmp++;
                        if (iter2().subtype() == insn::st_register) {
                            int8_t regKernelTask = -1;
                            if (iter2().rm() == regThisTask) {
                                regKernelTask = iter2().rn();
                            }else if (iter2().rn() == regThisTask){
                                regKernelTask = iter2().rm();
                            }else{
                                break; //false alarm
                            }
                            if (cntCmp == 0) cntCmp++;

                            patchfinder64::loc_t bof = find_bof(iter2);
                            if (bof > iter) { //sanity check
                                //we cross function boundaries, probaly this is not what we are looking for
                                break;
                            }
                            
                            uint64_t cmpVal = find_register_value(iter2, regKernelTask, iter);
                            if (cmpVal == kernel_task && cntCmp == 2 && iter2() == insn::ccmp) {
                                debug("%s: patchloc=0x%016llx\n",__FUNCTION__,(patchfinder64::loc_t)iter2);
                                insn pins = insn::new_register_ccmp(iter2, iter2().condition(), iter2().special(), iter2().rn(), iter2().rn());
                                uint32_t opcode = pins.opcode();
                                patches.push_back({(patchfinder64::loc_t)pins.pc(), &opcode, 4});
                                goto loop_continue;
                            }
                        }
                        break;
                    case insn::ret:
                        goto loop_continue;
                    default:
                        try {
                            if (iter2().rt() == regtpidr) regtpidr = -1;
                            if (iter2().rt() == regThisTask) regThisTask = -1;
                        } catch (...) {
                            //
                        }
                        break;
                }
            }
        }
    loop_continue:
        continue;
    }
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_vm_fault_internal_patch(){
    UNCACHEPATCHES;

    patchfinder64::loc_t str = 0;
    try {
        str = _vmem->memstr("\"Write fault on compressor map, va:");
    } catch (...) {
        str = _vmem->memstr("Write fault on compressor map, va:");
    }
    debug("str=0x%016llx\n",str);

    patchfinder64::loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx\n",ref);

    
    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::cmp || iter().imm() != 6 || iter-1 != insn::and_);
    ++iter;
    
    if (iter() == insn::ccmp) ++iter;
    
    assure(iter().supertype() == insn::sut_branch_imm);
    
    patchfinder64::loc_t pos = iter;
    debug("pos=0x%016llx\n",pos);

    {
        insn pins = insn::new_immediate_b(iter, iter().imm());
        uint32_t opcode = pins.opcode();
        patches.push_back({iter, &opcode, sizeof(opcode)});
    }

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_trustcache_true_patch(){
    UNCACHEPATCHES;
    
    /*
        Fair warning: This shit is cursed
     */

    vmem iter(_vmem);

    try {
        for (int z=0;;z++) {
inloop:
            while (++iter != insn::madd);
            vmem iter2 = iter;
            
            
            for (int i=0; i<14; i++) {
                if (++iter2 != insn::ldrb) goto inloop;
                if (++iter2 != insn::ldrb) goto inloop;
                if (++iter2 != insn::cmp) goto inloop;
                if ((++iter2).supertype() != insn::sut_branch_imm) goto inloop;
                if (++iter2 != insn::madd) goto inloop;
            }
            iter2 = iter;
            --iter2;
            if (--iter2 != insn::movz) goto inloop;

            iter2 = iter;
            patchfinder64::loc_t loc = iter;
            debug("loc=0x%016llx",loc);

            patchfinder64::loc_t found = find_bof(iter2);
            debug("found=0x%016llx",found);
                        
            if (((patchfinder64::loc_t)iter2 - found) >= 0x50) {
                //damn it you and your compiler optimizations
                debug("Trustcache patch found but, but it doesn't seem right, since it's very far away. Trying to fix...");
                while (iter2 > found) {
                    //there should be an adrp x8, <imm>
                    if (--iter2 == insn::adrp && iter2().rd() == 8) {
                        /*
                         looks like we are at the beginning of the function, be we are not sure about prologues
                         It's not the best idea to just return, because we might break stack
                         Let's look for a fail case, correct it and jump there instead
                         */
                    do_correct_tactic:
                        patchfinder64::loc_t maybebof = iter2;
                        debug("maybebof=0x%016llx",maybebof);
                        if (iter2() == insn::ret){
                            debug("maybebof is a ret, that is wrong! abandoning this...");
                            goto inloop;
                        }

                        /*
                            Just searching for movz x0, 0 doesn't work here, because there might be traps o.O
                            But first cbz should branch to good fail case
                         */
                        
                        while ((++iter2).supertype() != insn::sut_branch_imm);
                        
                        patchfinder64::loc_t good_failcase = iter2().imm();
                        debug("good_failcase=0x%016llx",good_failcase);
                        
                        //patch fail->success
                        pushINSN(insn::new_immediate_movz(good_failcase, 1, 0, 0));
                        
                        //jump to success
                        pushINSN(insn::new_immediate_b(maybebof, good_failcase));
                        
                        //we are done here
                        goto inloop;
                    }else if (iter2() == insn::bl || iter2() == insn::ret){
                        /*
                         There is one exception here.
                         ret
                         ldr    w9, [x0, #0x14]     <--- bof
                         cbz    w9, fail
                         If we are at a ret and find a cbz within the next 4 insn,
                         let's assume the function doesn't have a prologue and still go with with the correction strategy
                         */
                        if (iter2() == insn::ret) {
                            vmem iter3 = iter2;
                            for (int i=0; i<4; i++) {
                                if (++iter3 == insn::cbz){
                                    debug("Almost abandoned this, but we'll make an exception because this smells like a function without prologue");
                                    //iter2 points to ret of previous function, which is good enough to act as bof
                                    goto do_correct_tactic;
                                }
                            }
                        }
                        debug("we went too far. abandoning this place");
                        goto inloop;
                    }
                }
            }
            
            /*
                mov x0, 1
                ret
             */
            constexpr char patch[] = "\x20\x00\x80\xD2\xC0\x03\x5F\xD6";
            patches.push_back({found,patch,sizeof(patch)-1});
        }
    } catch (...) {
        //
    }

    assure(patches.size()); //need at least one
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_mount_patch(){
    UNCACHEPATCHES;
    
    patchfinder64::loc_t mount = find_function_for_syscall(167);
    mount |= 0xffffffUL << (6*8);
    debug("mount=0x%016llx\n",mount);
    
    vmem iter = _vmem->getIter(mount);
    
    while (++iter != insn::bl);
    loc_t mount_internal_bl = iter;
    debug("mount_internal_bl=0x%016llx\n",mount_internal_bl);

    patchfinder64::loc_t mount_internal = iter().imm();
    debug("mount_internal=0x%016llx\n",mount_internal);

    
    iter = mount_internal;
    
    while (++iter != insn::orr || iter().imm() != 0x10000);
    
    patchfinder64::loc_t pos = iter;
    debug("pos=0x%016llx\n",pos);
    
    while ((--iter != insn::tbz && iter() != insn::tbnz) || iter().special() != 0);

    if (iter() == insn::tbnz) {
        pushINSN(insn::new_general_nop(iter));
    }else{
        pushINSN(insn::new_immediate_b(iter, iter().imm()));
    }
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_tfp0_patch(){
    UNCACHEPATCHES;
    
    patchfinder64::loc_t get_task_for_pid = find_function_for_machtrap(45);
    get_task_for_pid |= 0xffffUL << (8*6);
    debug("get_task_for_pid=0x%016llx\n",get_task_for_pid);

    vmem iter = _vmem->getIter(get_task_for_pid);
    
    while (++iter != insn::cbz);
    
    patchfinder64::loc_t p1 = iter;
    debug("p1=0x%016llx\n",p1);

    patches.push_back({p1,"\x1F\x20\x03\xD5",4});
    
    RETCACHEPATCHES;
};

std::vector<patch> kernelpatchfinder64_base::get_cs_enforcement_disable_amfi_patch(){
    UNCACHEPATCHES;
    patchfinder64::loc_t str = findstr("csflags",true);
    debug("str=0x%016llx",str);

    patchfinder64::loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem cbz = _vmem->getIter(ref);
    while (--cbz != insn::cbz && cbz() != insn::cbnz){
        retassure(cbz() != insn::stp, "Failed to find cbz!");
    }
    
    if (cbz() == insn::cbz) {
        vmem movz(cbz);
        while (++movz != insn::movz);
        --movz;

        int anz = static_cast<int>((movz.pc()-cbz.pc())/4 +1);

        for (int i=0; i<anz; i++) {
            pushINSN(insn::new_general_nop(cbz.pc()+4*i));
        }
    }else if (cbz() == insn::cbnz){
        pushINSN(insn::new_immediate_b(cbz, cbz().imm()));
        loc_t nopos = cbz().imm();
        pushINSN(insn::new_general_nop(nopos+4*0));
        pushINSN(insn::new_general_nop(nopos+4*1));
        pushINSN(insn::new_general_nop(nopos+4*2));
    }else{
        reterror("This should not have happened!");
    }

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_amfi_validateCodeDirectoryHashInDaemon_patch(){
    UNCACHEPATCHES;
    patchfinder64::loc_t str = findstr("int _validateCodeDirectoryHashInDaemon",false);
    debug("str=0x%016llx",str);

    patchfinder64::loc_t ref = find_literal_ref(str);
    assure(ref);
    debug("ref=0x%016llx",ref);

    vmem bl_amfi_memcp = _vmem->getIter(ref);

    patchfinder64::loc_t memcmp = 0;

    patchfinder64::loc_t jscpl = 0;
    while (1) {
        while (++bl_amfi_memcp != insn::bl);

        try {
            jscpl = bl_jump_stub_ptr_loc(bl_amfi_memcp);
        } catch (tihmstar::bad_branch_destination &e) {
            continue;
        }
        if (haveSymbols()) {
            debug("bl_stub=0x%016llx (0x%16llx) -> 0x%016llx",(patchfinder64::loc_t)bl_amfi_memcp,jscpl,deref(jscpl));
            if (deref(jscpl) == (uint64_t)(memcmp = find_sym("_memcmp")))
                break;
        }else{
            //check for _memcmp function signature
            vmem checker = _vmem->getIter(memcmp = (patchfinder64::loc_t)deref(jscpl));
            if (checker == insn::cbz
                && (++checker == insn::ldrb && checker().rn() == 0)
                && (++checker == insn::ldrb && checker().rn() == 1)
//                ++checker == insn::sub //i'm too lazy to implement this now, first 3 instructions should be good enough though.
                ) {
                break;
            }
        }
    }
    patchfinder64::loc_t bl_amfi_memcp_loc = bl_amfi_memcp;
    debug("bl_amfi_memcp_loc=0x%016llx",bl_amfi_memcp_loc);

    /* find*/
    //movz w0, #0x0
    //ret
    vmem ret0 = _vmem->getIter(memcmp);
    while (ret0() != insn::movz || ret0().rd() != 0 || ret0().imm() != 0) {
        while (--ret0 != insn::ret)
            ;
        --ret0;
    }
    patchfinder64::loc_t ret0_gadget = ret0;
    debug("ret0_gadget=0x%016llx",ret0_gadget);

    patches.push_back({jscpl,&ret0_gadget,sizeof(ret0_gadget),slide_ptr});
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_get_task_allow_patch(){
    UNCACHEPATCHES;
    
    patchfinder64::loc_t amif_str = findstr("AMFI: ", false);
    debug("amfi_str=0x%016llx\n",amif_str);

    
    patchfinder64::loc_t get_task_allow_str = findstr("get-task-allow", true, amif_str);
    debug("get_task_allow_str=0x%016llx\n",get_task_allow_str);

    patchfinder64::loc_t get_task_allow_ref = 0;
    patchfinder64::loc_t find_func = 0;
    
    get_task_allow_ref = -4;
    while (true) {
        get_task_allow_ref = find_literal_ref(get_task_allow_str, 0, get_task_allow_ref+4);
        debug("get_task_allow_ref=0x%016llx\n",get_task_allow_ref);
        
        find_func = find_bof(get_task_allow_ref);
        vmem iter = _vmem->getIter(find_func);
        
        int adrpCnt = 0;
        
        while (++iter != insn::ret && adrpCnt < 2) {
            if (iter() == insn::adrp) adrpCnt++;
            if (iter() == insn::adr) adrpCnt++;
        }
        if (iter() == insn::ret) break;
    }
    debug("find_func=0x%016llx\n",find_func);

        
    patchfinder64::loc_t funcref = find_call_ref(find_func);
    debug("funcref=0x%016llx\n",funcref);
    
    vmem iter = _vmem->getIter(funcref);
    --iter;
    assure(iter().rd() == 0);

    patchfinder64::loc_t p1 = iter;
    debug("p1=0x%016llx\n",p1);
    
    /*
    movn       x0, #0xf000, lsl #48
    str        x0, [x1]
     */
    constexpr char patch[] = "\x00\x00\xFE\x92\x20\x00\x00\xF9";

    patches.push_back({p1,patch,sizeof(patch)-1});

    RETCACHEPATCHES;
};

std::vector<patch> kernelpatchfinder64_base::get_apfs_snapshot_patch(){
    UNCACHEPATCHES;
    
    patchfinder64::loc_t os_update_str = findstr("com.apple.os.update-",true);
    debug("os_update_str=0x%016llx\n",os_update_str);
    
    patches.push_back({os_update_str,"x",1});

    
//    //apfs_snap_vnop_rename patch
//
//    patchfinder64::loc_t apfs_snap_vnop_rename_str = findstr("apfs_snap_vnop_rename",true);
//    debug("apfs_snap_vnop_rename_str=0x%016llx\n",apfs_snap_vnop_rename_str);
//
//    patchfinder64::loc_t apfs_snap_vnop_rename_ref = find_literal_ref(apfs_snap_vnop_rename_str);
//    debug("apfs_snap_vnop_rename_ref=0x%016llx\n",apfs_snap_vnop_rename_ref);
//
//    vmem iter = _vmem->getIter(apfs_snap_vnop_rename_ref);
//
//    while (--iter != insn::tbnz || iter().imm() != 6);
//
//    constexpr char patch_nop[] = "\x1F\x20\x03\xD5";
//    patches.push_back({iter,patch_nop,sizeof(patch_nop)-1});
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_sandbox_patch(){
    UNCACHEPATCHES;
    patchfinder64::loc_t sbops = find_sbops();
    //pointer now contain linker information :o
    sbops |= 0xffff000000000000;
    
    debug("sbobs=0x%016llx",sbops);
    
    vmem iter = _vmem->getIter();
        
    do{
        ++iter;
        while (++iter != insn::ret);
    }while (--iter != insn::movz || iter().rd() != 0 || iter().imm() != 0);
        
    patchfinder64::loc_t ret0gadget = iter;
    debug("ret0gadget=0x%016llx",ret0gadget);
    
    /*
        re-insert linker info???
        - first mask off real 2 highest bytes
        - then mask in highest 2 bytes of orig ptr
     */
    
#define PATCH_OP(loc) \
    if (uint64_t origval = deref(loc)) { \
        patchfinder64::loc_t tmp = (ret0gadget & 0x0000ffffffffffff) | (origval & 0xffff000000000000); \
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

std::vector<patch> kernelpatchfinder64_base::get_nuke_sandbox_patch(){
    UNCACHEPATCHES;
    patchfinder64::loc_t sbops = find_sbops();
    //pointer now contain linker information :o
    sbops |= 0xffff000000000000;
    
    debug("sbobs=0x%016llx",sbops);
    
    vmem iter = _vmem->getIter();
    do{
        ++iter;
        while (++iter != insn::ret);
    }while (--iter != insn::movz || iter().rd() != 0 || iter().imm() != 0);
        
    patchfinder64::loc_t ret0gadget = iter;
    debug("ret0gadget=0x%016llx",ret0gadget);
    
    /*
        re-insert linker info???
        - first mask off real 2 highest bytes
        - then mask in highest 2 bytes of orig ptr
     */
    
#define PATCH_OP(loc) \
    if (uint64_t origval = deref(loc)) { \
        patchfinder64::loc_t tmp = (ret0gadget & 0x0000ffffffffffff) | (origval & 0xffff000000000000); \
        patches.push_back({loc,&tmp,sizeof(tmp)}); \
    }

    for (int i=0; i<sizeof(struct mac_policy_ops)-8; i+=8) {
        if (i == offsetof(struct mac_policy_ops,mpo_policy_init)) continue;
        if (i == offsetof(struct mac_policy_ops,mpo_policy_initbsd)) continue;
        PATCH_OP(sbops+i);
    }
    
#undef PATCH_OP
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_i_can_has_debugger_patch(){
    UNCACHEPATCHES;
    patchfinder64::loc_t str = findstr("Darwin Kernel",false);
    retassure(str, "Failed to find str");
    str -=4;

    patches.push_back({str,"\x01",1});
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_force_NAND_writeable_patch(){
    UNCACHEPATCHES;
    
    patchfinder64::loc_t str = findstr(" NAND is not writable", false);
    retassure(str, "Failed to find str");
    {
        const char *strbuf = (const char *)_vmem->memoryForLoc(str);
        int offset = 0;
        while (strbuf[offset]) offset--;
        str += offset + 1;
    }
    debug("str=0x%016llx\n",str);

    patchfinder64::loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx\n",ref);

    vmem iter = _vmem->getIter(ref);
    
    for (int i=0; i<2; i++) {
        while ((--iter).supertype() != insn::sut_branch_imm);
        //currently we only support tbz / tbnz
        if (iter() == insn::tbz || iter() == insn::tbnz) {
            if (iter().rt() == 0){ //the first is check if logging, the second is our target
                retassure(iter().special() == 0, "tb(n)z cheks an unexpected bit");
                goto found_tb_n_z;
            }
        }else if (iter() == insn::b){
            //backup plan iOS 10.0.2
            patchfinder64::loc_t bdst = iter+1;
            for (int ign = 0; ign<2; ign++) {
                patchfinder64::loc_t bsrc = 0;
                try {
                    bsrc = find_branch_ref(bdst, -0x200, ign);
                } catch (...) {
                    //we shouldn't get here, but maybe we're fine if we found at least one instance
                    warning("failed to find bsrc on iter=%d",ign);
                    break;
                }
                debug("bsrc=0x%016llx\n",bsrc);
                vmem iter2 = _vmem->getIter(bsrc);
                retassure(iter2() == insn::cbz || iter2() == insn::cbnz, "Unimplemented branch type. We only know cbz and cbnz");

                if (iter2() == insn::cbnz) {
                    pushINSN(insn::new_immediate_b(iter2, iter2().imm()));
                }else{
                    pushINSN(insn::new_general_nop(iter2));
                }
            }
            goto end;
        }
    }
    reterror("Failed to find tb(n)z");
found_tb_n_z:
    if (iter() == insn::tbz || iter() == insn::cbnz) {
        pushINSN(insn::new_immediate_b(iter, iter().imm()));
    }else{
        pushINSN(insn::new_general_nop(iter));
    }
    
end:
    retassure(patches.size(), "Failed to find at least one patch");
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_always_get_task_allow_patch(){
    UNCACHEPATCHES;
    
    patchfinder64::loc_t str = findstr("AMFI: hook..execve() killing pid %u: %s\n", true);
    debug("str=0x%016llx",str);
    
    patchfinder64::loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    patchfinder64::loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);
    
    vmem iter = _vmem->getIter(bof);
    while (true) {
        while (++iter != insn::orr || (iter+1) != insn::str)
            ;
        if (iter().rd() == (iter+1).rt()) break;
    }
    ++iter;
    
    patchfinder64::loc_t strpos = iter;
    debug("strpos=0x%016llx",strpos);
    uint8_t flags_get_reg = iter().rn();
    debug("flags_get_reg=%d",flags_get_reg);

    patchfinder64::loc_t get_task_allow_str = findstr("get-task-allow", true);
    debug("get_task_allow_str=0x%016llx",get_task_allow_str);
    patchfinder64::loc_t get_task_allow_str_ref = -1;

    while (true) {
        get_task_allow_str_ref = find_literal_ref(get_task_allow_str, 0, get_task_allow_str_ref + 1);
        debug("get_task_allow_str_ref=0x%016llx",get_task_allow_str_ref);
        patchfinder64::loc_t thisbof = find_bof(get_task_allow_str_ref);
        if (thisbof == bof) break;
    }
    iter = get_task_allow_str_ref;
    while (++iter != insn::bl)
        ;
    patchfinder64::loc_t badbl = iter;
    debug("badbl=0x%016llx",badbl);

    pushINSN(insn::new_immediate_ldr_unsigned(badbl-4*2, 0, flags_get_reg, 0));
    {
        //orr encoding is hard!
        //orr x0, x0, #0x4
        uint32_t opcode = 0xb27e0000;
        patches.push_back({badbl-4*1,&opcode, sizeof(opcode)});
    }
    pushINSN(insn::new_immediate_str_unsigned(badbl-4*0, 0, flags_get_reg, 0));

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_allow_UID_key_patch(){
    UNCACHEPATCHES;
    
    vmem iter = _vmem->getIter();

    
    while (true) {
        while (++iter != insn::cmp || iter().subtype() != insn::st_immediate)
            ;
        if (iter().imm() != 0x3e8 && iter().imm() != 0x7d0 && iter().imm() != 0x835) {
            continue;
        }
        uint8_t cmpreg = iter().rn();
        uint64_t val = iter().imm();
//        loc_t candidate = iter;
//        debug("candidate=0x%016llx val=0x%x",candidate,val);
        vmem iter2 = iter;

        for (int i=0; i<8; i++) {
            auto insn = ++iter2;
            if (insn == insn::cmp && insn.subtype() == insn::st_immediate && insn.rn() == cmpreg && (insn.imm() != val && (insn.imm() == 0x3e8 || insn.imm() == 0x7d0 || insn.imm() == 0x7d2 || insn.imm() == 0x835))){

                vmem iter3 = iter2;
                for (int j=0; j<8; j++) {
                    auto insn = ++iter3;
                    if (insn == insn::cmp && insn.subtype() == insn::st_immediate && insn.rn() == cmpreg && (insn.imm() == 0x3e8 || insn.imm() == 0x7d0 || insn.imm() == 0x7d2 || insn.imm() == 0x835)) {
                        loc_t cmp = iter;
                        loc_t cmp2 = iter2;
                        loc_t cmp3 = iter3;
                        debug("cmp1=0x%016llx",cmp);
                        debug("cmp2=0x%016llx",cmp2);
                        debug("cmp3=0x%016llx",cmp3);

                        pushINSN(insn::new_immediate_cmp(iter, 0xff, iter().rn()));
                        pushINSN(insn::new_immediate_cmp(iter2, 0xff, iter2().rn()));
                        pushINSN(insn::new_immediate_cmp(iter3, 0xff, iter3().rn()));
                        return patches;
                    }
                }
            }
        }
    }
    
    reterror("todo");
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_ramdisk_detection_patch(){
    UNCACHEPATCHES;
    
    std::set<loc_t> badbofs;

    vmem iter = _vmem->getIter();
    
    {
        loc_t bsd_str = findstr("BSD root: %s, major", false);
        loc_t bsd_str_ref = find_literal_ref(bsd_str);
        loc_t bsd_str_bof = find_bof(bsd_str_ref);
        badbofs.insert(bsd_str_bof);
    }

    {
        loc_t s = findstr("rootvp not authenticated", false);
        loc_t r = find_literal_ref(s);
        loc_t b = find_bof(r);
        badbofs.insert(b);
    }
    
    while (true) {
        try {
            while (++iter != insn::cmp || iter().imm() != 0x6d)
                ;
        } catch (...) {
            break;
        }
        vmem iter2 = iter;
        for (int i=0; i<4; i++) {
            if (++iter2 == insn::cmp && iter2().imm() == 0x64 /*&& iter2().rd() == iter().rd()*/) {
                loc_t ref = iter2;
                loc_t bof = find_bof(ref);
                if (badbofs.find(bof) != badbofs.end()) continue;
                debug("ref=0x%016llx",ref);
                pushINSN(insn::new_immediate_cmp(iter2.pc(), 0x41, iter2().rn()));
                break;
            }
        }
    }
    
    loc_t rd_str = memmem("\x00rd\x00", 4)+1;
    debug("rd_str=0x%016llx",rd_str);
    
    loc_t rd_ref = -4;
    
    while ((rd_ref = find_literal_ref(rd_str,0,rd_ref+4))) {
        debug("rd_ref=0x%016llx",rd_ref);
        loc_t bof = find_bof(rd_ref);
        if (badbofs.find(bof) != badbofs.end()) continue;

        vmem iter = _vmem->getIter(rd_ref);
        
        if (iter() == insn::add) {
            pushINSN(insn::new_immediate_add(iter, iter().imm()+1, iter().rn(), iter().rd()));
        }else{
            reterror("not implemented");
        }
    }
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_read_bpr_patch(){
    UNCACHEPATCHES;
    loc_t ml_io_map = find_ml_io_map();
    debug("ml_io_map=0x%016llx",ml_io_map);
    
    loc_t kernel_map = find_kernel_map();
    debug("kernel_map=0x%016llx",kernel_map);

    loc_t kmem_free = find_kmem_free();
    debug("kmem_free=0x%016llx",kmem_free);
    
    loc_t release_uname_str = findstr("RELEASE_ARM64_", false);
    debug("release_uname_str=0x%016llx",release_uname_str);
    const char *release_uname_str_ptr = (const char*)_vmem->memoryForLoc(release_uname_str);
    release_uname_str_ptr+=sizeof("RELEASE_ARM64_")-1;
    while (*release_uname_str_ptr && isalpha(*release_uname_str_ptr)) release_uname_str_ptr++;
    
    loc_t bpr_addr = 0;
    int cpid = atoi(release_uname_str_ptr);
    debug("cpid=0x%d",cpid);
    switch (cpid) {
        case 8010:
        case 8011:
            bpr_addr = 0x2102d0030;
            break;
        case 8015:
            bpr_addr = 0x2352d0030;
            break;
            
        default:
            reterror("unimplemented CPID=%d",cpid);
    }

    debug("bpr_addr=0x%016llx",bpr_addr);
    addPatches(get_read_bpr_patch_with_params(213, bpr_addr, ml_io_map, kernel_map, kmem_free));
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_kernelbase_syscall_patch(){
    UNCACHEPATCHES;
    loc_t table = find_table_entry_for_syscall(213);
    debug("table=0x%016llx",table);

    const char shellcode[] = "\x60\x6E\xFF\x90\x00\xFC\x4C\xD3\xC0\x03\x5F\xD6";

    loc_t nops = 0;
    try {
        nops = findnops((sizeof(shellcode)-1 + 8)/4);
    } catch (...) {
        nops = findnops((sizeof(shellcode)-1 + 8)/4, true, 0x00000000);
    }
    debug("nops=0x%016llx",nops);

    
    pushINSN(insn::new_general_adrp(nops, 0xfffffff007004000, 0));
    patches.push_back({nops+4,shellcode+4,sizeof(shellcode)-1-4});

    //hello linkerinfo in pointers
    uint64_t funcptr = deref(table) & 0xffffffff00000000;
    funcptr |= (nops & 0xffffffff);
    patches.push_back({table,&funcptr,sizeof(funcptr)});
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_base::get_harcode_bootargs_patch(std::string bootargs){
    std::vector<patch> patches;
    
    uint64_t argsSize = bootargs.size();
    argsSize += 4;
    argsSize &= ~3;
    
    while (bootargs.size() < argsSize)
        bootargs.push_back('\0');
    
    loc_t entrypoint = find_entry();
    debug("entry=0x%16llx",entrypoint);

    vmem iter = _vmem->getIter(entrypoint);
    
    uint32_t entryOpcode = iter().opcode();
    
    loc_t entrybdst = iter().imm();
    debug("entrybdst=0x%16llx",entrybdst);

    offset_t bootargOffset = find_boot_args_commandline_offset();
    debug("bootargOffset=0x%llx",bootargOffset);
    
    uint32_t shellcode_insn_cnt = 13; //commitment
    loc_t shellcode = findnops(shellcode_insn_cnt + argsSize/4);
    debug("shellcode=0x%016llx",shellcode);
    
#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    
    pushINSN(insn::new_immediate_add(cPC, bootargOffset, 0, 5));
    pushINSN(insn::new_general_adr(cPC, shellcode+shellcode_insn_cnt*4, 6));
    pushINSN(insn::new_immediate_movz(cPC, argsSize, 7, 0));
    pushINSN(insn::new_immediate_subs(cPC, 4, 7, 7));
    pushINSN(insn::new_register_ldr(cPC, 6, 7, 8, true));
    pushINSN(insn::new_register_str(cPC, 5, 7, 8, true));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+4*3, libinsn::arm64::insn::NE));
    pushINSN(insn::new_immediate_movz(cPC, entryOpcode & 0xffff, 5, 0));
    pushINSN(insn::new_immediate_movk(cPC, entryOpcode>>16, 5, 16));
    {
        int insnNumBackup = insnNum;
        try{
            pushINSN(insn::new_general_adr(cPC, entrypoint, 6));
            pushINSN(insn::new_general_nop(cPC));
        }catch (...){
            insnNum = insnNumBackup;
            pushINSN(insn::new_general_adrp(cPC, entrypoint & ~0x3fff, 6));
            pushINSN(insn::new_immediate_add(cPC, entrypoint & 0x3fff, 6, 6));
        }
    }
    pushINSN(insn::new_immediate_str_unsigned(cPC, 0, 6, 5));
    pushINSN(insn::new_immediate_b(cPC, entrybdst));
    assure(insnNum == shellcode_insn_cnt);
    patches.push_back({cPC,bootargs.data(),bootargs.size()});
    pushINSN(insn::new_immediate_b(entrypoint, shellcode));
#undef cPC
    return patches;
}

std::vector<patch> kernelpatchfinder64_base::get_harcode_boot_manifest_patch(const void *hash, size_t hashSize){
    UNCACHEPATCHES;
    size_t realhashSize = hashSize;
    while (realhashSize & 3) realhashSize++;
    
    loc_t entrypoint = find_entry();
    debug("entry=0x%16llx",entrypoint);
    
    vmem iter = _vmem->getIter(entrypoint);
    
    loc_t hookpos = iter().imm();
    debug("hookpos=0x%16llx",hookpos);
    
    
    offset_t cmdlineOffset = find_boot_args_commandline_offset();
    offset_t deviceTreePOffset = (cmdlineOffset - sizeof(uint32_t) - sizeof(uint64_t)) & ~3;
    offset_t virtBaseOffset = 0x08;
    offset_t physBaseOffset = 0x10;
    
    debug("deviceTreePOffset=0x%016llx",deviceTreePOffset);
    
    uint32_t shellcode_insn_cnt = 25; //commitment
    loc_t shellcode = findnops(shellcode_insn_cnt + realhashSize/4);
    debug("shellcode=0x%016llx",shellcode);
    uint32_t loopdst = 9;
    uint32_t loop2dst = 19;
#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, deviceTreePOffset, 0, 5));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, virtBaseOffset, 0, 6));
    pushINSN(insn::new_register_add(cPC, 0, 5, 6, 5, true));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, physBaseOffset, 0, 6));
    pushINSN(insn::new_register_add(cPC, 0, 5, 6, 5, false));
    //load "boot-man" 0x6e61 6d2d 746f 6f62
    pushINSN(insn::new_immediate_movz(cPC, 0x6f62, 6, 0));
    pushINSN(insn::new_immediate_movk(cPC, 0x746f, 6, 16));
    
    //    pushINSN(insn::new_immediate_movk(cPC, 0x6d2d, 6, 32));
    //    pushINSN(insn::new_immediate_movk(cPC, 0x6e61, 6, 48));
    pushINSN(insn::new_immediate_movz(cPC, 0x6d2d, 4, 0));
    pushINSN(insn::new_immediate_movk(cPC, 0x6e61, 4, 16));
    
    assure(loopdst == insnNum);
    
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0, 5, 7, true));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 4, 5, 8, true));
    pushINSN(insn::new_immediate_add(cPC, 4, 5, 5));
    pushINSN(insn::new_register_cmp(cPC, 0, 6, 7, -1));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+loopdst*4, insn::NE));
    pushINSN(insn::new_register_cmp(cPC, 0, 4, 8, -1));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+loopdst*4, insn::NE));
    pushINSN(insn::new_immediate_add(cPC, 32, 5, 5));
    
    pushINSN(insn::new_general_adr(cPC, shellcode+shellcode_insn_cnt*4, 6));
    pushINSN(insn::new_immediate_movz(cPC, 0x30, 7, 0));
    assure(loop2dst == insnNum);
    pushINSN(insn::new_immediate_subs(cPC, 4, 7, 7));
    pushINSN(insn::new_register_ldr(cPC, 6, 7, 8, true));
    pushINSN(insn::new_register_str(cPC, 5, 7, 8, true));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+loop2dst*4, libinsn::arm64::insn::NE));
    {
        uint32_t opcode = (uint32_t)deref(hookpos);
        patches.push_back({cPC,&opcode,sizeof(opcode)});
    }
    pushINSN(insn::new_immediate_b(cPC, hookpos+4));
    assure(insnNum == shellcode_insn_cnt);
    patches.push_back({cPC,hash,hashSize});
    pushINSN(insn::new_immediate_b(hookpos, shellcode));
#undef cPC
    
    RETCACHEPATCHES;
}

#pragma mark Util
patchfinder64::loc_t kernelpatchfinder64_base::find_rootvnode() {
    return find_sym("_rootvnode");
}

patchfinder64::loc_t kernelpatchfinder64_base::find_allproc(){
    UNCACHELOC;
    patchfinder64::loc_t str = findstr("\"pgrp_add : pgrp is dead adding process\"",true);
    retassure(str, "Failed to find str");
    
    patchfinder64::loc_t ref = find_literal_ref(str);
    retassure(ref, "ref to str");
    
    vmem ptr = _vmem->getIter(ref);
    
    while (++ptr != insn::and_ || ptr().rd() != 8 || ptr().rn() != 8 || ptr().imm() != 0xffffffffffffdfff);
    
    patchfinder64::loc_t retval = (patchfinder64::loc_t)find_register_value(ptr-2, 8);
    
    RETCACHELOC(retval);
}

patchfinder64::loc_t kernelpatchfinder64_base::find_sbops(){
    UNCACHELOC;
    patchfinder64::loc_t str = findstr("Seatbelt sandbox policy", false);
    retassure(str, "Failed to find str");
    debug("str=0x%16llx",str);

    patchfinder64::loc_t ref = 0;
    try {
        retassure(ref = memmem(&str, sizeof(str)), "Failed to find ref");
    } catch (...) {
        //pointer now contain linker information
        debug("Failed to find full ref, retrying with masking off upper 2 bytes...");
        retassure(ref = memmem(&str, sizeof(str)-2), "Failed to find ref");
    }

    loc_t retval = (patchfinder64::loc_t)deref(ref+0x18);
    RETCACHELOC(retval);
}

patchfinder64::loc_t kernelpatchfinder64_base::find_ml_io_map(){
    UNCACHELOC;
    try {
        loc_t sym = find_sym("_ml_io_map");
        return sym;
    } catch (...) {
        //
    }
    debug("Failed to find sym _ml_io_map, trying fallback method...");
    
    loc_t str = findstr("no-dockfifo-uart",true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    {
        for (int i=0; i<100; i++) {
            if (--iter == insn::bl) goto foundfunc;
        }
        reterror("Failed to find func in range");
    foundfunc:
        ;
    }
    loc_t func = iter().imm();
    debug("func=0x%016llx",func);

    loc_t ml_io_map = -4;
    
    while (true) {
        ml_io_map = find_branch_ref(func,0,0,ml_io_map+4);
        debug("ref candidate=0x%016llx",ml_io_map);
        iter = ml_io_map;
        if (iter() != insn::b) continue;
        bool hasW2 = false;
        bool hasW3 = false;
        for (int i=0; i<2; i++) {
            if (--iter != insn::movz && (iter() != insn::orr || iter().rn() != 0x1f /*wzr*/)) goto nextloop;
            hasW3 |= (iter().rd() == 3 && iter().imm() == 3);
            hasW2 |= (iter().rd() == 2 && iter().imm() == 7);
        }
        if (hasW2 && hasW3) {
            loc_t retval = iter;
            RETCACHELOC(retval);
        }
    nextloop:
        continue;
    }
    reterror("Failed to find _ml_io_map");
}

patchfinder64::loc_t kernelpatchfinder64_base::find_kernel_map(){
    UNCACHELOC;
    try {
        loc_t sym = find_sym("_kernel_map");
        return sym;
    } catch (...) {
        //
    }
    debug("Failed to find sym _kernel_map, trying fallback method...");
    
    loc_t str = findstr("mach_vm_region failed: %d",true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    while (--iter != insn::bl);
    
    retassure(find_register_value(iter, 3) == 9, "wrong func! x3 arg should be 9");
    
    loc_t kernel_map = find_register_value(iter, 0);
    
    RETCACHELOC(kernel_map);
}

patchfinder64::loc_t kernelpatchfinder64_base::find_kmem_free(){
    UNCACHELOC;
    try {
        loc_t sym = find_sym("_kmem_free");
        return sym;
    } catch (...) {
        //
    }
    debug("Failed to find sym _kmem_free, trying fallback method...");
    
    loc_t str = 0;
    try {
        str = findstr("\"kmem_free",false);
    } catch (...) {
        debug("Failed to find '\"kmem_free', retrying with 'kmem_free'");
    }
    if (!str) str = findstr("kmem_free",false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t kmem_free = find_bof(ref);
    
    RETCACHELOC(kmem_free);
}

patchfinder64::loc_t kernelpatchfinder64_base::find_bss_space(uint32_t bytecnt, bool useBytes){
    if (!_unusedBSS.size()) {
        debug("Searching for bss space...");
        {
            loc_t str = findstr("packet(SPI=%u ", true);
//            debug("str=0x%016llx",str);
            
            loc_t ref = find_literal_ref(str);
//            debug("ref=0x%016llx",ref);
            
            vmem iter = _vmem->getIter(ref);
            while (++iter != insn::bl)
                ;
            
            loc_t pe_parse_boot_arg = iter;
//            debug("pe_parse_boot_arg=0x%016llx",pe_parse_boot_arg);
            
            loc_t pos = find_register_value(pe_parse_boot_arg, 0, pe_parse_boot_arg-0x20);
//            debug("pos=0x%016llx",pos);
            _unusedBSS.push_back({pos,256});
        }
        
        debug("Done searching for bss space!");
        _unusedBSS.push_back({0,0}); //mark as already inited
    }
    retassure(_unusedBSS.size(), "Failed to find bss space");
    
    int besti = -1;
    size_t bestSize = 0;
    
    for (int i=0; i<_unusedBSS.size(); i++) {
        auto np = _unusedBSS.at(i);
        if (bytecnt <= np.second) {
            if (besti == -1 || np.second < bestSize) {
                besti = i;
                bestSize = np.second;
            }
        }
    }
    retassure(besti != -1, "Failed to find enough nopspace");
    auto foundpos = _unusedBSS.at(besti);
    if (useBytes) {
        _unusedBSS.erase(_unusedBSS.begin() + besti);
        if (bytecnt < bestSize) {
            size_t remainSpaceSize = foundpos.second - bytecnt;
            loc_t remainSpace = foundpos.first + bytecnt;
            _unusedBSS.push_back({remainSpace,remainSpaceSize});
        }
        debug("consuming bss {0x%016llx,0x%016llx}",foundpos.first,foundpos.first+foundpos.second);
    }

    return foundpos.first;
}

patchfinder64::loc_t kernelpatchfinder64_base::find_pac_tag_ref(uint16_t pactag, int skip, loc_t startpos, int limit){
    vmem iter = _vmem->getIter(startpos);
    bool hasLimit = limit;
    do{
        while (++iter != insn::movk || iter().imm() != ((uint64_t)pactag << 48)){
            if (hasLimit && !limit--) return 0;
        }
    }while(skip--);
    return iter;
}

patchfinder64::loc_t kernelpatchfinder64_base::find_boot_args_commandline_offset(){
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

    iter = PE_parse_boot_argn;
    
    while (++iter != insn::adr && iter() != insn::adrp)
        ;
    uint8_t reg = iter().rd();
    debug("reg=%d at=0x%016llx",reg,iter.pc());
    
    while (++iter != insn::ldr)
        ;

    debug("ldr at=0x%016llx",iter.pc());
    assure(iter().rn() == reg);
    uint8_t reg2 = iter().rt();

    while (++iter != insn::ldr && iter() != insn::ldrb)
        ;
    assure(iter().rn() == reg2);
    
    offset_t bootargOffset = iter().imm();
    RETCACHELOC(bootargOffset);
}


#pragma mark combo utils
std::vector<patch> kernelpatchfinder64_base::get_codesignature_patches(){
    UNCACHEPATCHES;
    addPatches(get_amfi_validateCodeDirectoryHashInDaemon_patch());
    addPatches(get_cs_enforcement_disable_amfi_patch());
    RETCACHEPATCHES;
}

#pragma mark non-override
std::vector<patch> kernelpatchfinder64_base::get_read_bpr_patch_with_params(int syscall, loc_t bpr_reg_addr, loc_t ml_io_map, loc_t kernel_map, loc_t kmem_free){
    UNCACHEPATCHES;
    
    const char readbpr[] =
    "\xFF\x43\x01\xD1\xFD\x7B\x04\xA9\x00\x03\x00\x58\x01\x00\x88\xD2\x00\xC4\x72\x92\x0F\x00\x00\x94\x81\x02\x00\x58\x21\x34\x40\x92\x01\x00\x01\x8B\x3D\x00\x40\xB9\xE1\x03\x00\xAA\x02\x00\x88\xD2\x09\x00\x00\x94\x20\x28\xA8\xD2\xBD\x3F\x40\x92\x1F\x20\x03\xD5\x00\x00\x1D\xAA\xFD\x7B\x44\xA9\xFF\x43\x01\x91\xC0\x03\x5F\xD6";
    
    loc_t table = find_table_entry_for_syscall(syscall);
    debug("table=0x%016llx",table);
    loc_t nops = 0;
    try {
        nops = findnops((sizeof(readbpr)-1 + 0x20)/4);
    } catch (...) {
        nops = findnops((sizeof(readbpr)-1 + 0x20)/4, true, 0x00000000);
    }
    debug("nops=0x%016llx",nops);
    
    patches.push_back({nops,readbpr,sizeof(readbpr)-1});
    
    pushINSN(insn::new_immediate_b(nops+sizeof(readbpr)-1+4*0, ml_io_map));
    try {
        pushINSN(insn::new_general_adr(nops+sizeof(readbpr)-1+4*1, kernel_map, 0));
        pushINSN(insn::new_general_nop(nops+sizeof(readbpr)-1+4*2));
    } catch (...) {
        pushINSN(insn::new_general_adrp(nops+sizeof(readbpr)-1+4*1, (kernel_map & ~0xfff), 0));
        pushINSN(insn::new_immediate_add(nops+sizeof(readbpr)-1+4*2, kernel_map & 0xfff, 0, 0));
    }
    pushINSN(insn::new_immediate_ldr_unsigned(nops+sizeof(readbpr)-1+4*3, 0, 0, 0));
    pushINSN(insn::new_immediate_b(nops+sizeof(readbpr)-1+4*4, kmem_free));

    patches.push_back({nops+sizeof(readbpr)-1+4*6,&bpr_reg_addr,sizeof(bpr_reg_addr)});
    
    //hello linkerinfo in pointers
    uint64_t funcptr = deref(table) & 0xffffffff00000000;
    funcptr |= (nops & 0xffffffff);
    patches.push_back({table,&funcptr,sizeof(funcptr)});

    RETCACHEPATCHES;
}
