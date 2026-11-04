//
//  kernelpatchfinder64_iOS17.cpp
//  libpatchfinder
//
//  Created by erd on 20.06.23.
//
#include <libgeneral/macros.h>

#include "kernelpatchfinder64_iOS17.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all64.h"
#include "sbops64.h"
#include <string.h>

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

std::vector<patch> kernelpatchfinder64_iOS17::get_codesignature_patches(){
    UNCACHEPATCHES;

    {
        //add disabling launch constraints
        loc_t str = findstr("AMFI: Validation Category info: current", false);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);
        
        loc_t bof = find_bof(ref);
        debug("bof=0x%16llx",bof);

        pushINSN(insn::new_immediate_movz(bof, 0, 0, 0));
        pushINSN(insn::new_general_ret(bof+4));
    }

    {
        //Hello iOS 16.4!
        loc_t query_trust_cache = find_query_trustcache();
        debug("query_trust_cache=0x%016llx",query_trust_cache);
        loc_t stub_ptr = 0;
        loc_t stub_query_trust_cache = 0;
        try {
            stub_ptr = memmem(&query_trust_cache, sizeof(query_trust_cache));
        } catch (...) {
            //
        }
        
        if (stub_ptr){
            debug("stub_ptr=0x%016llx",stub_ptr);
            stub_query_trust_cache = find_literal_ref(stub_ptr);
        }
        if (!stub_query_trust_cache){
            /*
                On A12 it's not a stub
             */
            stub_query_trust_cache = query_trust_cache;
        }else{
            assure(stub_query_trust_cache);
            stub_query_trust_cache -=4;
            debug("stub_query_trust_cache=0x%016llx",stub_query_trust_cache);
        }

        bool didFindTargetFunc = 0;
        loc_t trustcache_check_call = -4;
        while (true) {
            try {
                trustcache_check_call = find_call_ref(stub_query_trust_cache,0,trustcache_check_call+4);
            } catch (...) {
                break;
            }
            debug("trustcache_check_call=0x%016llx",trustcache_check_call);
            loc_t trustcache_check = find_bof(trustcache_check_call);
            debug("trustcache_check=0x%016llx",trustcache_check);
            
            int cnt_bl = 0;
            auto iter = _vmem->getIter(trustcache_check);
            
            while (++iter != insn::ret){
                if (iter() == insn::bl) cnt_bl++;
            }
            if (cnt_bl != 2){
                debug("wrong target, ignoring...");
                continue;
            }
            
            retassure(!didFindTargetFunc, "Already found target, but it should be just on, right??");
            didFindTargetFunc = true;
            debug("Correct target!");
            pushINSN(insn::new_immediate_movz(trustcache_check+4*0, 1, 0, 0));
            pushINSN(insn::new_immediate_cbz(trustcache_check+4*1, trustcache_check+4*3, 2));
            pushINSN(insn::new_immediate_str_unsigned(trustcache_check+4*2, 0, 2, 0));
            pushINSN(insn::new_general_ret(trustcache_check+4*3));
        }
        retassure(didFindTargetFunc, "Failed to find a patch");
    }

    addPatches(get_trustcache_true_patch()); //needed for iPhone 11,2 iOS 17.0
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS17::get_no_nonce_entanglement_patch(){
    UNCACHEPATCHES;
    loc_t str = findstr("entangle-nonce",true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    auto iter = _vmem->getIter(ref);
    
    while ((++iter).supertype() != libinsn::arm64::insn::sut_branch_imm)
        ;
    
    loc_t tgt = 0;
    uint8_t rt = 0;
    
reevaluate:
    tgt = iter;
    debug("tgt=0x%016llx rt=%d",tgt,rt);
    if ((iter() == insn::cbz || iter() == insn::tbz) && iter().rt() == rt) {
        pushINSN(insn::new_immediate_b(iter, iter().imm()));
    }else if ((iter() == insn::cbnz || iter() == insn::tbnz) && iter().rt() == rt){
        pushINSN(insn::new_general_nop(iter));
    }else if (iter() == insn::bl){
        assure(++iter == insn::ldrb);
        rt = iter().rt();
        ++iter;
        goto reevaluate;
    }else if (iter() == insn::cmp && iter().rn() == rt){
        retassure(++iter == insn::bcond, "unexpected insn");

        if (iter().condition() == insn::cond::NE) {
            pushINSN(insn::new_general_nop(iter));
        } else if (iter().condition() == insn::cond::EQ){
            pushINSN(insn::new_immediate_b(iter, iter().imm()));
        } else {
            reterror("Unexpected insn^2");
        }
    }else{
        reterror("Unexpected insn");
    }

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS17::get_mount_patch(){
    UNCACHEPATCHES;

    loc_t mount = find_function_for_syscall(167);
    vmem iter = _vmem->getIter();

    try {
        iter = (mount | 0xffff000000000000);
    } catch (...) {
        warning("Failed to deref mount ptr, retrying with iOS 16 chains");
        iter = ((mount & 0xFFFFFFFFUL) + _base);
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
            if (++iter == insn::tbz) {
                if (++iter == insn::orr && iter().imm() == 0x10000) {
                    if (++iter == insn::tbnz) {
                        pushINSN(insn::new_immediate_b(iter, iter().imm()));
                    }else if (iter() == insn::tbz){
                        pushINSN(insn::new_general_nop(iter));
                    }else{
                        reterror("Unexpected insn");
                    }
                    p1 = 0;
                }
            }
            if (p1){
                iter = p1;
                pushINSN(insn::new_immediate_movz(iter, 0, iter().rn(), 0));
            }
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
    
    
    {
        /* ---- APFS update to rw ---- */
        loc_t str = findstr("Updating mount to read/write mode is not allowed", false);
        if (str) {
            debug("Found 'Updating mount to read/write mode is not allowed' str, adding additional apfs update rw patch");
            while (deref(str) & 0xff) str--;
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
                    if (++iter == insn::movk && iter().imm() == 0xc8a2000000000000){
                        /*
                            On PAC CPUs (iPhone12,3 iOS 26.2) we sometimes have panic traps like these
                             0xfffffff00a608198         tst        x16, #0xffc0000000000000
                             0xfffffff00a60819c         b.eq       loc_fffffff00a6081a4
                             0xfffffff00a6081a0         movk       x9, #0xc8a2, lsl #48     <----- triggers panic
                             0xfffffff00a6081a4         mov        w8, #0x895
                            Make sure our block detection handles these correctly.
                         */
                        --iter;
                        --iter;
                        continue;
                    }
                    break;
                }
            }
            
            loc_t jmpsrc = find_branch_ref(iter, -0x500);
            debug("jmpsrc=0x%016llx",jmpsrc);

            pushINSN(insn::new_general_nop(jmpsrc));
        }
    }
    RETCACHEPATCHES;
}
