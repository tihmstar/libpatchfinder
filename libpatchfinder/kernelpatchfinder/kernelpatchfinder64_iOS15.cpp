//
//  kernelpatchfinder64_iOS15.cpp
//  libpatchfinder
//
//  Created by tihmstar on 21.03.22.
//

#include "../../include/libpatchfinder/OFexception.hpp"
#include "kernelpatchfinder64_iOS15.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"
#include "sbops64.h"

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

#pragma mark Offset finders
kernelpatchfinder::offset_t kernelpatchfinder64_iOS15::find_struct_offset_for_PACed_member(const char *strDesc){
    loc_t ref = find_PACedPtrRefWithStrDesc(strDesc);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    uint8_t rd = iter().rd();
    
    while (++iter != insn::autda || iter().rn() != rd)
        retassure(iter() != insn::ret, "Failed to find auth");

    loc_t authloc = iter;
    debug("authloc=0x%016llx",authloc);
    
    uint8_t authreg = iter().rd();
    while (--iter != insn::ldr || iter().rt() != authreg)
        retassure(iter() != insn::pacibsp, "Failed to find ldr");

    return iter().imm();
}

#pragma mark Location finders
patchfinder64::loc_t kernelpatchfinder64_iOS15::find_kernel_map(){
    UNCACHELOC;
    try {
        loc_t sym = kernelpatchfinder64_base::find_kernel_map();
        return sym;
    } catch (...) {
        //
    }
    debug("Failed to find sym _kernel_map, trying iOS 15.4 method...");
    
    loc_t str = findstr("io_telemetry_limit",true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    while (++iter != insn::ret);

    loc_t funcend = iter;
    debug("funcend=0x%016llx",funcend);

    while (--iter != insn::bl);
    loc_t vm_map_deallocate = iter;
    debug("vm_map_deallocate=0x%016llx",vm_map_deallocate);

    loc_t kernel_map = 0;
    uint8_t reg = 0;
    
    switch ((++iter).type()) {
        case insn::adr:
            kernel_map = iter().imm();
            break;
        case insn::adrp:
            kernel_map = iter().imm();
            reg = iter().rd();
            while ((++iter).pc() < funcend) {
                if (iter() == insn::ldr && iter().rn() == reg) {
                    kernel_map += iter().imm();
                    goto end;
                }else{
                    //check if reg gets overwritten
                    try {if (iter().rd() == reg) break;} catch (...) {}
                    try {if (iter().rn() == reg) break;} catch (...) {}
                }
            }
            reterror("Failed to read loc");
            break;

        default:
            reterror("unexpected insn. we expect adrp or adr");
    }
end:
    RETCACHELOC(kernel_map);
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_kerneltask(){
    UNCACHELOC;
    patchfinder64::loc_t strloc = findstr("Attempting to set task policy on kernel_task", false);
    debug("strloc=0x%016llx\n",strloc);
    
    patchfinder64::loc_t strref = find_literal_ref(strloc);
    debug("strref=0x%016llx\n",strref);
    
    vmem iter = _vmem->getIter(strref);

    while (--iter != insn::adr && iter() != insn::adrp)
        ;
    while (--iter != insn::adr && iter() != insn::adrp)
        ;

    loc_t bdst = iter;
    debug("bdst=0x%016llx\n",bdst);

    loc_t bsrc = find_branch_ref(bdst, -0x400);
    debug("bsrc=0x%016llx\n",bsrc);

    iter = bsrc;
    
    while (--iter != insn::adr && iter() != insn::adrp)
        ;
    
    loc_t kerneltask = 0;
    uint8_t rd = -1;
    kerneltask = iter().imm();
    rd = iter().rd();

    for (int i=0; i<10; i++) {
        if (++iter == insn::ldr && iter().rn() == rd) {
            kerneltask += iter().imm();
            RETCACHELOC(kerneltask);
        }
    }
    reterror("Failed to find kerneltask");
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_allproc(){
    UNCACHELOC;
    loc_t str = findstr("shutdownwait", true);
    debug("str=0x%016llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl)
        ;
    
    switch ((++iter).type()) {
        case insn::cbz:
            ++iter;
            break;
                
        case insn::cbnz:
            iter = iter().imm();
            break;
            
        default:
            reterror("unimplemented");
            break;
    }
    
    loc_t allproc = 0;
    while (++iter != insn::adr && iter() != insn::adrp)
        ;
    allproc = iter().imm();
    
    while (++iter != insn::ldr)
        ;
    allproc += iter().imm();
    
    RETCACHELOC(allproc);
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_kerncontext(){
    UNCACHELOC;
    loc_t str = findstr("%s[%d] had to be forced closed with exit1()", false);
    debug("str=0x%016llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl)
        ;
    
    loc_t ret = find_register_value(iter, 0);
    RETCACHELOC(ret);
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_vnode_getattr(){
    UNCACHELOC;
    loc_t str = findstr("vnode_getattr() returned", false);
    while (deref(--str) & 0xff)
        ;
    ++str;
    debug("str=0x%016llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (--iter != insn::bl)
        ;
    
    RETCACHELOC(iter().imm());
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_proc_p_flag_offset(){
    UNCACHELOC;
    
    loc_t str = findstr("/Applications/Camera.app/", false);
    debug("str=0x%016llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (--iter != insn::blr)
        ;
    
    loc_t blr = iter;
    debug("blr=0x%016llx",blr);

    while ((--iter).supertype() != insn::sut_branch_imm)
        ;

    loc_t branch = iter;
    debug("branch=0x%016llx",branch);

    while (--iter != insn::ldr)
        ;

    RETCACHELOC(iter().imm());
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_kmem_free(){
    UNCACHELOC;
    try {
        loc_t kmem_free = kernelpatchfinder64_iOS13::find_kmem_free();
        RETCACHELOC(kmem_free);
    } catch (...) {
        //
    }
    debug("Failed to find_kmem_free using old method, trying fallback method...");
    
    loc_t str = 0;
    str = findstr("Bad compare and swap in diagnose",false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);

    vmem iter = _vmem->getIter(ref);
    
    loc_t kmem_free = 0;
    
    while (true) {
        while (--iter != insn::bl)
            ;
        retassure(iter > bof, "reached bof");
        kmem_free = iter().imm();
        vmem iter2 = _vmem->getIter(kmem_free-4);
        for (int i=0; i<10; i++) {
            auto insn = ++iter2;
            if (insn == insn::cbz || insn == insn::cbnz) {
                if (insn.rt() == 2) {
                    goto didfind;
                }
            }else if (insn != insn::stp && insn != insn::add){
                break;
            }
        }
        kmem_free = 0;
    }
didfind:
    assure(kmem_free);
    RETCACHELOC(kmem_free);
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_machtrap_table(){
    UNCACHELOC;
    loc_t str = findstr("kern_invalid mach trap", true);
    debug("str=0x%016llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    
    loc_t kern_invalid = find_bof(iter);
    debug("kern_invalid=0x%016llx",kern_invalid);
    
    loc_t table_entry = 0;
    try {
        table_entry = memmem(&kern_invalid, 8);
    } catch (...) {
        //pac devce??
        kern_invalid -= _base;
        table_entry = memmem(&kern_invalid, 4);
    }
    debug("table_entry=0x%016llx",table_entry);

    RETCACHELOC(table_entry);
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_function_for_machtrap(int trapcall){
    patchfinder64::loc_t machtrapTable = find_machtrap_table();
    patchfinder64::loc_t tableEntry =machtrapTable + 3*8*trapcall;
    loc_t e = deref(tableEntry);
    if ((e >> 36) != 0xfffffff) {
        //pac
        e = _base + (e & 0xffffffff);
    }
    return e;
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_IOGeneralMemoryDescriptor_ranges_offset(){
    UNCACHELOC;

    loc_t str = findstr("short external upl", false);
    debug("str=0x%016llx",str);
    assure(str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    assure(ref);
    
    loc_t func_IOGeneralMemoryDescriptor_initWithOptions_bof = find_bof(ref);
    debug("func_IOGeneralMemoryDescriptor_initWithOptions_bof=0x%016llx",func_IOGeneralMemoryDescriptor_initWithOptions_bof);

    loc_t kernel_task = find_kerneltask();
    debug("kernel_task=0x%016llx",kernel_task);

    loc_t ref_kt = find_literal_ref(kernel_task,0,func_IOGeneralMemoryDescriptor_initWithOptions_bof);
    debug("ref_kt=0x%016llx",ref_kt);
    retassure(ref_kt-func_IOGeneralMemoryDescriptor_initWithOptions_bof< 0x1000, "hit is unreasonably late");
    
    vmem iter = _vmem->getIter(ref_kt);
    uint8_t ktreg = iter().rt();
    
    {
        for (int i=0; i<10; i++) {
            if (++iter == insn::cmp) goto found_cmp;
        }
        reterror("Failed to find cmp");
    found_cmp:;
    }
    uint8_t taskkt = iter().rn();
    if (taskkt == ktreg) taskkt = iter().rm();
    
    loc_t task_off = find_register_value(iter, taskkt, iter.pc()-0x20);
    RETCACHELOC(task_off - 0x10);
}

patchfinder64::loc_t kernelpatchfinder64_iOS15::find_IOSurface_MemoryDescriptor_offset(){
    UNCACHELOC;
    vmem iter = _vmem->getIter();
    vmem iter2 = _vmem->getIter();
    loc_t ret = 0;
    while (true) {
        while (++iter != insn::bl)
            ;
        try {
            iter2 = iter().imm();
        } catch (...) {
            continue;
        }
        if (iter2() != insn::ldr || (iter2+1) != insn::ret) continue;
        ret = iter2().imm();
        iter2 = iter;
        if (++iter != insn::ldr || iter().rn() != 0) continue;
        if (++iter != insn::mov || iter().rm() != 0) continue;
        
        loc_t ref1 = iter;
        
        bool hasAutda = false;
        for (int i=0; i<5 && !(hasAutda); i++) {
            auto isn = ++iter;
            if (isn == insn::autda) hasAutda = true;
        }
        if (!hasAutda) continue;
        
        {
            for (int i=0; i<4; i++) {
                if (--iter2 == insn::bl) goto found;
            }
            continue;
        found:;
        }
        
        loc_t ref2 = find_pac_tag_ref(0xf5b3,0,ref1,0x20);
        if (!ref2) continue;
        debug("ref1=0x%016llx",ref1);
        RETCACHELOC(ret);
    }
}

std::vector<patch> kernelpatchfinder64_iOS15::get_always_get_task_allow_patch(){
    UNCACHEPATCHES;

    loc_t str = findstr("mac_vnode_check_signature: MAC hook", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);
    
    uint8_t savereg = -1;
    
    vmem iter = _vmem->getIter(bof);
    
    while (++iter != insn::mov || iter().rm() != 3)
        ;
    savereg = iter().rd();
    debug("savereg=%d",savereg);
    
    while (++iter != insn::ret)
        ;
    loc_t eof = iter;
    debug("eof=0x%016llx",eof);

    while (--iter != insn::mov || iter().rd() != 0)
        ;
    uint8_t retReg = iter().rm();
    loc_t scratchspace = ref - 4*4;
    
    pushINSN(insn::new_immediate_b(iter, scratchspace));
    
    pushINSN(insn::new_immediate_ldr_unsigned(scratchspace+4*0, 0, savereg, 0));
    {uint32_t opcode = 0xB2660000; patches.push_back({scratchspace+4*1,&opcode,4});} //orr x0, x0, #0x4000000
    {uint32_t opcode = 0xB27E0000; patches.push_back({scratchspace+4*2,&opcode,4});} //orr x0, x0, #0x4
    pushINSN(insn::new_immediate_str_unsigned(scratchspace+4*3, 0, savereg, 0));
    pushINSN(insn::new_register_mov(scratchspace+4*4, 0, 0, retReg));
    pushINSN(insn::new_immediate_b(scratchspace+4*5, iter.pc()+4));
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS15::get_tfp0_patch(){
    UNCACHEPATCHES;

    loc64_t tfp = find_function_for_machtrap(45);
    debug("tfp=0x%016llx",tfp);
    
    vmem iter = _vmem->getIter(tfp);
    while (++iter != insn::cbz)
        ;
    pushINSN(insn::new_general_nop(iter));
    
    
    loc_t control_str = findstr("userspace has control", false);
    debug("control_str=0x%016llx",control_str);

    loc_t access_str = findstr("userspace has access", false);
    debug("access_str=0x%016llx",access_str);

    loc_t control_str_ref = find_literal_ref(control_str);
    debug("control_str_ref=0x%016llx",control_str_ref);

    loc_t access_str_ref = find_literal_ref(access_str);
    debug("access_str_ref=0x%016llx",access_str_ref);
    
    iter = control_str_ref;
    
    while (--iter != insn::adrp)
        ;
    while (--iter != insn::adrp)
        ;

    loc_t p1 = 0;
    try {
        p1 = find_branch_ref(iter, -0x100);
    } catch (...) {
        --iter;
        try {
            p1 = find_branch_ref(iter, -0x100);
        } catch (...) {
            retassure(--iter == insn::bcond, "Unexpected branch layout");
            pushINSN(insn::new_immediate_b(iter, iter().imm()));
        }
    }
        
    if (p1){
        p1 = 0;
        while (true) {
            try {
                p1 = find_branch_ref(iter, -0x100, 0, p1);
                debug("p1=0x%016llx",p1);
                pushINSN(insn::new_general_nop(p1));
            } catch (...) {
                break;
            }
        }
        retassure(p1, "This should never happen!");
    }
    
    iter = access_str_ref;
    
    while (--iter != insn::adrp)
        ;
    while (--iter != insn::adrp)
        ;

    loc_t p2 = 0;
    try {
        p2 = find_branch_ref(iter, -0x100);
    } catch (...) {
        --iter;
        p2 = find_branch_ref(iter, -0x100);
    }
    {
        p2 = 0;
        while (true) {
            try {
                p2 = find_branch_ref(iter, -0x100, 0, p2);
                debug("p2=0x%016llx",p2);
                pushINSN(insn::new_general_nop(p2));
            } catch (...) {
                break;
            }
        }
        retassure(p2, "This should never happen!");
    }
    
    loc_t bof = find_bof(p2);
    debug("bof=0x%016llx",bof);
    iter = bof;

    int64_t x0 = -1;
    int64_t x1 = -1;
    while (++iter != insn::ret) {
        if (iter() == insn::movz) {
            if (iter().rd() == 0) {
                x0 = iter().imm();
            }else if (iter().rd() == 1) {
                x1 = iter().imm();
            }
        }
        if (iter() == insn::bl) {
            if (x0 >= 0 && x0 <=15 && x1 >= 0 && x1 <= 0x100) {
                pushINSN(insn::new_general_nop(iter));
                break;
            }
            x0 = -1;
            x1 = -1;
        }
    }
    
    addPatches(get_task_conversion_eval_patch());
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS15::get_task_conversion_eval_patch(){
    UNCACHEPATCHES;

    /*
     if (caller == kernel_task) {
         return KERN_SUCCESS;
     }

     if (caller == victim) {    <-- then find this
         return KERN_SUCCESS;
     }

     ...

     if ((victim->t_flags & TF_PLATFORM) && !(caller->t_flags & TF_PLATFORM))  <-- first find this
     */

    vmem iter = _vmem->getIter();
    
    
    while (true) {
    loopstart:
        try {
            ++iter;
        } catch (...) {
            break;
        }
        if (iter() == insn::ldr) {
            
            vmem iter2 = iter;
            uint8_t reg = iter().rt();
            uint8_t reg1 = iter().rn();
            if ((++iter2 != insn::tbz && iter2() != insn::tbnz) || iter2().special() != 0xa || iter2().rt() != reg) continue;
            if (++iter2 != insn::ldr) continue;
            reg = iter2().rt();
            uint8_t reg2 = iter2().rn();
            if ((++iter2 != insn::tbz && iter2() != insn::tbnz) || iter2().special() != 0xa || iter2().rt() != reg) continue;
            
            loc_t hit = iter;
            debug("hit=0x%016llx",hit);
                        
            loc_t bof = find_bof(hit);
            debug("bof=0x%016llx",bof);

            iter2 = iter;
            while (true) {
                while (--iter2 != insn::cmp || iter2().subtype() != insn::st_register){
                    if (iter2 < bof) {
                        vmem iter3 = iter2;
                        int8_t nx0 = -1;
                        int8_t nx1 = -1;
                        
                        while (++iter3 != insn::cmp) {
                            if (iter3() == insn::mov && iter3().rm() == 0){
                                nx0 = iter3().rd();
                            }else if (iter3() == insn::mov && iter3().rm() == 1){
                                nx1 = iter3().rd();
                            }
                        }
                        retassure(iter3().subtype() == insn::st_register, "reached bof without results");

                        iter2 = iter3;
                        if ((iter2().rn() == 0 || (nx0 != -1 && iter2().rn() == nx0)) && (iter2().rm() == 1 || (nx1 != -1 && iter2().rm() == nx1))) goto patch_cmp;
                        if ((iter2().rm() == 0 || (nx0 != -1 && iter2().rm() == nx0)) && (iter2().rn() == 1 || (nx1 != -1 && iter2().rn() == nx1))) goto patch_cmp;
                        debug("reached bof without results (fallback failed)");
                        goto loopstart;
                    }
                }
                if (iter2().rn() == reg1 && iter2().rm() == reg2) break;
                if (iter2().rn() == reg2 && iter2().rm() == reg1) break;
            }
        patch_cmp:
            pushINSN(insn::new_register_cmp(iter2.pc(), 0, -1, -1, -1));
            {
                loc_t ploc = iter2;
                debug("ploc=0x%016llx",ploc);
            }
        }
    }
    assure(patches.size()); //need at least one
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS15::get_trustcache_true_patch(){
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
            if (--iter2 != insn::movz && --iter2 != insn::mov) goto inloop;

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

std::vector<patch> kernelpatchfinder64_iOS15::get_insert_vfs_context_current_patch(patchfinder64::loc_t &tgtloc){
    try {
        auto patches = _savedPatches.at(__PRETTY_FUNCTION__);
        tgtloc = patches.front()._location;
        return patches;
    } catch (...) {
        //
    }
    std::vector<patch> patches;
    tgtloc = 0;
    loc_t kerncontext = find_kerncontext();
    debug("kerncontext=0x%016llx",kerncontext);

    loc_t f_open = find_function_for_syscall(5) | 0xffff000000000000;
    debug("f_open=0x%016llx",f_open);
    
    vmem iter = _vmem->getIter(f_open);
    
    while (++iter != insn::b && iter() != insn::bl)
        ;

    loc_t f_open_nocancel = iter().imm();
    debug("f_open_nocancel=0x%016llx",f_open_nocancel);

    iter = f_open_nocancel;
    while (++iter != insn::mrs)
        ;
    
    uint8_t reg = iter().rt();
    
    int insnNum = 0;

    int insnCnt = 9; //commitment
    int insnKernContext = 6; //commitment
    int insnRet = 8; //commitment
    loc_t shellcode = findnops(insnCnt);
#define cPC (shellcode+(insnNum++)*4)
    pushINSN(insn::new_register_msr(cPC, 0, libinsn::arm64::insn::tpidr_el1, true));
    assure(++iter == insn::ldr && iter().rn() == reg);
    reg = iter().rt();
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, iter().imm(), 0, 0));
    pushINSN(insn::new_immediate_cbz(cPC, shellcode+insnKernContext*4, 0));
    retassure(++iter == insn::cbz, "cbnz not implemented, otherwise unexpected insn");
    assure(++iter == insn::ldr && iter().rn() == reg);
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, iter().imm(), 0, 1));
    while (++iter != insn::add || iter().rd() != reg || iter().rn() != reg)
        retassure(iter() != insn::ret, "Failed to find add");
    pushINSN(insn::new_immediate_add(cPC, iter().imm(), 0, 0));
    pushINSN(insn::new_immediate_cbz(cPC, shellcode+insnRet*4, 1, true));
    assure(insnNum == insnKernContext);
    pushINSN(insn::new_general_adrp(cPC, kerncontext & ~0xfff, 0));
    pushINSN(insn::new_immediate_add(cPC, kerncontext & 0xfff, 0, 0));
    assure(insnNum == insnRet);
    pushINSN(insn::new_general_ret(cPC));
    assure(patches.size() == insnCnt);
    tgtloc = shellcode;
#undef cPC

    RETCACHEPATCHES;
}


std::vector<patch> kernelpatchfinder64_iOS15::get_insert_setuid_patch(){
    UNCACHEPATCHES;
    
    loc_t sbops = find_sbops() | 0xffff000000000000 ;
    debug("sbops=0x%016llx",sbops);

    loc_t hook_addr = sbops+offsetof(struct mac_policy_ops,mpo_cred_label_update_execve);
    debug("hook_addr=0x%016llx",hook_addr);

    loc_t orig_hook = deref(hook_addr);
    debug("orig_hook=0x%016llx",orig_hook | 0xffff000000000000);
    
    uint32_t shellcode_insn_cnt = 41; //commitment
    loc_t shellcode = findnops(shellcode_insn_cnt);
    debug("shellcode=0x%016llx",shellcode);

    loc_t vfs_context_current = 0;
    addPatches(get_insert_vfs_context_current_patch(vfs_context_current));
    debug("vfs_context_current=0x%016llx",vfs_context_current);

    loc_t vnode_getattr = find_vnode_getattr();
    debug("vnode_getattr=0x%016llx",vnode_getattr);

    loc_t proc_p_flag_offset = find_proc_p_flag_offset();
    debug("proc_p_flag_offset=0x%llx",proc_p_flag_offset);

    int commit_origInsnNum = 40; //commitment
    int commit_epilogue = 34; //commitment
    int commit_pre_execve_hook_orig_gid = 23; //commitment
    int commit_pre_execve_hook_orig_p_flags = 29; //commitment

#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    
    pushINSN(insn::new_immediate_cbz(cPC, shellcode+commit_origInsnNum*4, 3));
    pushINSN(insn::new_immediate_sub(cPC, 0x400, 31, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x00, 29, 30, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x10, 0, 1, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x20, 2, 3, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x30, 4, 5, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x40, 6, 7, 31));
    pushINSN(insn::new_immediate_bl(cPC, vfs_context_current));
    pushINSN(insn::new_register_mov(cPC, 0, 2, 0));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28, 31, 0));
    pushINSN(insn::new_immediate_add(cPC, 0x80, 31, 1));
    pushINSN(insn::new_immediate_movz(cPC, 0x380, 8, 0));
    pushINSN(insn::new_general_stp_offset(cPC, 0, -1, 8, 1));
    pushINSN(insn::new_general_stp_offset(cPC, 0x10, -1, -1, 1));
    pushINSN(insn::new_immediate_bl(cPC, vnode_getattr));
    pushINSN(insn::new_immediate_cbz(cPC, shellcode+commit_epilogue*4, 0,true));
    pushINSN(insn::new_immediate_movz(cPC, 0, 2, 0));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0xcc, 31, 8, true));
    pushINSN(insn::new_immediate_tbz(cPC, shellcode+commit_pre_execve_hook_orig_gid*4, 0, 11, 8));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0xc4, 31, 8, true));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x18, 31, 0));
    pushINSN(insn::new_immediate_str_unsigned(cPC, 0x18, 0, 8, true));
    pushINSN(insn::new_immediate_movz(cPC, 1, 2, 0));

    assure(commit_pre_execve_hook_orig_gid == insnNum);
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0xcc, 31, 8, true));
    pushINSN(insn::new_immediate_tbz(cPC, shellcode+commit_pre_execve_hook_orig_p_flags*4, 0, 10, 8));
    pushINSN(insn::new_immediate_movz(cPC, 1, 2, 0));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0xc8, 31, 8, true));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x18, 31, 0));
    pushINSN(insn::new_immediate_str_unsigned(cPC, 0x28, 0, 8, true));

    assure(commit_pre_execve_hook_orig_p_flags == insnNum);
    pushINSN(insn::new_immediate_cbz(cPC, shellcode+commit_epilogue*4, 2));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x20, 31, 0));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, proc_p_flag_offset, 0, 8, true));
    pushINSN(insn(0x32180108, cPC)); //orr w8, w8, #0x100
    pushINSN(insn::new_immediate_str_unsigned(cPC, proc_p_flag_offset, 0, 8, true));
    
    assure(commit_epilogue == insnNum);
    pushINSN(insn::new_general_ldp_offset(cPC, 0x10, 0, 1, 31));
    pushINSN(insn::new_general_ldp_offset(cPC, 0x20, 2, 3, 31));
    pushINSN(insn::new_general_ldp_offset(cPC, 0x30, 4, 5, 31));
    pushINSN(insn::new_general_ldp_offset(cPC, 0x40, 6, 7, 31));
    pushINSN(insn::new_general_ldp_offset(cPC, 0x00, 29, 30, 31));
    pushINSN(insn::new_immediate_add(cPC, 0x400, 31, 31));

    assure(commit_origInsnNum == insnNum);
    pushINSN(insn::new_immediate_b(cPC, orig_hook | 0xffffff0000000000));
    assert(shellcode_insn_cnt == insnNum);
#undef cPC
    
    {
        loc_t new_hook = (orig_hook & 0xffffff0000000000)
                       | (shellcode & 0x000000ffffffffff);
        patches.push_back({hook_addr,&new_hook,sizeof(new_hook)});
    }
    
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS15::get_apfs_root_from_sealed_livefs_patch(){
    UNCACHEPATCHES;
    
    loc_t str = findstr("Rooting from the live fs of a sealed volume is not allowed on a", false);
    assure(str);
    while (deref(str) & 0xff) str--;
    str++;
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    loc_t tgt = 0;

    while (true) {
        while (--iter != insn::ldr)
            ;
        if ((tgt = find_branch_ref(iter, -0x100))) break;
    }
    debug("tgt=0x%016llx",tgt);
    pushINSN(insn::new_general_nop(tgt));

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS15::get_tfp_anyone_allow_patch(){
    UNCACHEPATCHES;
    
    loc64_t tfp = find_function_for_machtrap(45);
    debug("tfp=0x%016llx",tfp);
    
    vmem iter = _vmem->getIter(tfp);
    for (int i=0; i<2; i++) {
        while (++iter != insn::bl)
            ;
    }
    loc_t proc_ident_call = iter;
    debug("proc_ident_call=0x%016llx",proc_ident_call);

    ++iter;
    retassure(iter()==insn::mov && iter().subtype() == insn::st_register, "unexpected insn");
    
    uint8_t bkreg = iter().rd();
    
    {
        int didskip = 0;
        for (int i=0; i<10; i++) {
            while (++iter != insn::bl)
                ;
            auto isn = iter-1;
            if (isn == insn::mov && isn.subtype() == insn::st_register
                && isn.rd() == 0 && isn.rm() == bkreg){
                if (didskip++ == 1) goto foundcall;
            }
        }
    foundcall:;
        //patch task_for_pid_posix_check
        pushINSN(insn::new_immediate_movz(iter, 1, 0, 0));
    }
    
    /* ---------- patch global macf checks --------------- */
    loc_t str = findstr("AMFI: unrestricted debugging is enabled.", false);
    debug("str=0x%llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%llx",bof);
    
    pushINSN(insn::new_immediate_movz(bof, 1, 0, 0));
    pushINSN(insn::new_general_ret(bof+4));
    
    /* ---------- patch local macf check --------------- */
    iter = tfp;
    while (true) {
        while (++iter != insn::bl)
            ;
        retassure(iter() != insn::ret, "unexpected EOF");
        auto isn = iter -1;
        if (isn != insn::mov && isn != insn::movz) continue;
        if (isn.subtype() != insn::st_immediate) continue;
        if (isn.rd() != 2 || isn.imm() != 0) continue;
        loc_t macCheckFunc = iter;
        debug("macCheckFunc=0x%016llx",macCheckFunc);
        pushINSN(insn::new_immediate_movz(macCheckFunc, 0, 0, 0));
        break;
    }

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS15::get_kernelbase_syscall_patch(){
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
    funcptr |= ((nops-_base) & 0xffffffff);
    patches.push_back({table,&funcptr,sizeof(funcptr)});
    
    RETCACHEPATCHES;
}


std::vector<patch> kernelpatchfinder64_iOS15::get_kcall_syscall_patch(){
    UNCACHEPATCHES;
    loc_t table = find_table_entry_for_syscall(214);
    debug("table=0x%016llx",table);

    const char shellcode[] = "\x00\x02\x1F\xD6";

    loc_t nops = 0;
    try {
        nops = findnops((sizeof(shellcode)-1 + 8)/4);
    } catch (...) {
        nops = findnops((sizeof(shellcode)-1 + 8)/4, true, 0x00000000);
    }
    debug("nops=0x%016llx",nops);
    
    patches.push_back({nops,shellcode,sizeof(shellcode)-1});

    //hello linkerinfo in pointers
    uint64_t funcptr = deref(table) & 0xffffffff00000000;
    funcptr |= ((nops-_base) & 0xffffffff);
    patches.push_back({table,&funcptr,sizeof(funcptr)});
    
    RETCACHEPATCHES;
}
