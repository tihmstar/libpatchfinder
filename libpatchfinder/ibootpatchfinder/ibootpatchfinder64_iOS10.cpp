//
//  ibootpatchfinder64_iOS10.cpp
//  libpatchfinder
//
//  Created by tihmstar on 26.02.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include "ibootpatchfinder64_iOS10.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS10::get_skip_set_bpr_patch(){
    std::vector<patch> patches;
    for (uint64_t bpr_reg : {0x2102d0030/*t8010*/, 0x2352d0030/*t8015*/}) {
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
    
    return patches;
}
