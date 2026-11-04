//
//  ibootpatchfinder64_iOS10.cpp
//  libpatchfinder
//
//  Created by tihmstar on 26.02.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//
#include <libgeneral/macros.h>

#include "ibootpatchfinder64_iOS10.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS10::get_skip_set_bpr_patch(){
    std::vector<patch> patches;
    for (uint64_t bpr_reg : {0x2102d0030/*t8010*/, 0x2352d0030/*t8015*/, 0x23d2d0030/*t8030,t8020,t8006*/}) {
        loc_t bpr_reg_ref = -4;
        while ((bpr_reg_ref = find_literal_ref(bpr_reg,0,bpr_reg_ref+4))){
            if (bpr_reg_ref) {
                vmem iter = _vmem->getIter(bpr_reg_ref);
                uint8_t addr_reg = iter().rd();
                assure(++iter == insn::ldr && iter().rn() == addr_reg);
                uint8_t val_reg = iter().rt();
                
                for (int i=0; i<5; i++) {
                    if (++iter == insn::orr && iter().rn() == val_reg && iter().imm() == 1) {
                        debug("setBPR=0x%016llx",iter.pc());
                        pushINSN(insn::new_general_nop(iter));
                        goto nextloop;
                    }
                }
            }
        nextloop:
            continue;
        }
    }
    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS10::get_sigcheck_img4_patch(){
    std::vector<patch> patches;
    loc_t img4str = findstr("IMG4", true);
    debug("img4str=0x%016llx\n",img4str);

    loc_t img4strref = find_literal_ref(img4str);
    debug("img4strref=0x%016llx\n",img4strref);

    loc_t f1top = find_bof(img4strref);
    debug("f1top=0x%016llx\n",f1top);

    loc_t f1topref = 0;
    try {
        f1topref = find_call_ref(f1top,1);
    } catch (...) {
        f1topref = find_call_ref(f1top); //don't ignore i guess?
    }
    
    debug("f1topref=0x%016llx\n",f1topref);

    loc_t f2top = find_bof(f1topref);
    debug("f2top=0x%016llx\n",f2top);

    vmem iter = _vmem->getIter(f2top);

    loc_t adr_x3 = 0;
    loc_t adr_x2 = 0;

    while (true) {
        if (++iter == insn::adr && iter().rd() == 2){
            adr_x2 = iter;
        }else if (iter() == insn::adr && iter().rd() == 3){
            adr_x3 = iter;
        }else if (iter() == insn::bl){
            if (adr_x2 && adr_x3) {
                break;
            }else{
                adr_x2 = 0;
                adr_x3 = 0;
            }
        }
    }
    
    assure(adr_x2);
    iter = adr_x2;
    
    loc_t callback_ref = iter;
    debug("callback_ref=0x%016llx\n",callback_ref);

    loc_t callback = (loc_t)deref((loc_t)iter().imm());
    debug("callback=0x%016llx\n",callback);

    iter = callback;
    
    while (++iter != insn::ret);
    
    loc_t ret = iter;
    debug("ret=0x%016llx\n",ret);

    if (--iter == insn::add) {
        assure(iter().rd() == 31 && iter().rn() == 31); //add sp, sp, #something
    }else{
        assure(iter() == insn::ldp);
    }
    
    while (--iter == insn::ldp);
    
    if (iter() != insn::mov || iter().rd() != 0) {//are we writing to x0 from some register?
        if (iter() == insn::sub && iter().rd() == 31) {
            //wtf?? sub sp, x29, #0x40
            --iter;
        }
        
        //if no, then are we at a stack check at least?
        assure (iter().supertype() == insn::sut_branch_imm); //stack check branch
    }
    
    loc_t branch = iter;
    debug("branch=0x%016llx\n",branch);
    
    pushINSN(insn::new_immediate_movz(iter, 0, 0, 0));//movz x0, 0
    
    
    /*
        
        Extra patch: Allow booting components not explicitly covered by MANB
        This is needed for booting iOS 12 with iOS 9 APTicket, because that doesn't containt Trustcache
     */
    iter = callback_ref;
    while (++iter != insn::bl)
        ;
    loc_t verify_func_bl = iter;
    debug("verify_func_bl=0x%016llx\n",verify_func_bl);

    while ((++iter).supertype() != insn::sut_branch_imm)
        ;
    loc_t bimm = iter;
    debug("bimm=0x%016llx\n",bimm);

    if (iter() == insn::cbz) {
        pushINSN(insn::new_immediate_b(iter, iter().imm()));
    }else if (iter() == insn::cbnz){
        pushINSN(insn::new_general_nop(iter));
    }else{
        reterror("Unexpected insn found!");
    }
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS10::get_tz0_lock_patch(){
    UNCACHEPATCHES;
    
    vmem iter = _vmem->getIter();
    
    for (uint64_t lockval : {0x200000910 /*A7 lock*/, 0x200000490 /*A8 lock*/, 0x200000492 /*A8 lock (WTF iOS 10.0.1??)*/}) {
        if (loc_t lock_ref = find_literal_ref(lockval)){
            debug("lock_ref=0x%016llx",lock_ref);
            iter = lock_ref;
            uint8_t reg_ref = iter().rd();
            debug("reg_ref=%d",reg_ref);
            for (int i=0; i<2; i++) {
                /*
                 Skip locking both, tz0 and tz1
                 */
                while (++iter != insn::str || iter().rn() != reg_ref)
                    ;
                
                loc_t strtgt = iter;
                debug("strtgt=0x%016llx",strtgt);
                uint8_t reg_strval = iter().rt();
                debug("reg_strval=%d",reg_strval);
                pushINSN(insn::new_general_nop(iter));
                if (++iter == insn::bl)
                    ++iter;
                retassure(iter() == insn::ldr && iter().rn() == reg_ref, "unexpected insn");
                pushINSN(insn::new_register_mov(iter, 0, iter().rt(), reg_strval));
            }
        }
    }
    if (!patches.size()) {
        //fallback plan non-(A7 A8)
        
        /* Looking for:
         movz w8, #0x1
         str w8, [x24]
         bl call_dmb_sy
         ldr w8, [x24]
         tbz w8, 0x0, ....
         */
        try {
            while (true) {
                while (++iter != insn::str);
                uint8_t strrn = iter().rn();
                insn prevInsn = iter-1;
                if (prevInsn == insn::movz){
                    if (prevInsn.imm() != 1) continue;
                }else if (prevInsn == insn::orr){
                    if (prevInsn.imm() != 1 || prevInsn.rn() != 31 /*weird alias for wzr??*/) continue;
                }
                else continue;
                
                if (iter().rt() != prevInsn.rd()) continue; //this insn doesn't store result of prev insn
                
                if (++iter != insn::bl) continue; //here should be a call to call_dmb_sy
                
                if (++iter != insn::ldr || strrn != iter().rn()) continue; //check the store was successfull
                uint8_t ldrrt = iter().rt();
                ++iter;
                
                if (iter() == insn::cmp) {
                    if (iter().imm() != 1 && iter().imm() != 0) continue; //wtf?
                }else if (iter() == insn::tbz || iter() == insn::tbz){
                    if (iter().special() != 1 && iter().special() != 0) continue; //wtf?
                }
                
                loc_t check = iter;
                check -= 4;
                debug("check=0x%016llx",check);
                pushINSN(insn::new_immediate_movz(check, 1, ldrrt, 0));
                
                loc_t lock = check-2*4;
                debug("lock=0x%016llx",lock);
                pushINSN(insn::new_general_nop(lock));
            }
        } catch (...) {
            //will fail eventually. this is fine
        }
    }
    
    retassure(patches.size(), "Failed to find patches");
    RETCACHEPATCHES;
}
