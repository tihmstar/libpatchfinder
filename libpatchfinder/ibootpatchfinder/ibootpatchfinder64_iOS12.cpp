//
//  ibootpatchfinder64_iOS12.cpp
//  libpatchfinder
//
//  Created by tihmstar on 22.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include "ibootpatchfinder64_iOS12.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;


std::vector<patch> ibootpatchfinder64_iOS12::get_tz0_lock_patch(){
    std::vector<patch> patches;
    
    /* Looking for:
     movz w8, #0x1
     str w8, [x24]
     bl call_dmb_sy
     ldr w8, [x24]
     tbz w8, 0x0, ....
     */
    
    vmem iter = _vmem->getIter();

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
    
    retassure(patches.size(), "Failed to find patches");
    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS12::get_force_septype_local_patch(){
    std::vector<patch> patches;

    loc_t rsepref = find_literal_ref('rsep');
    debug("rsepref=0x%016llx",rsepref);
    
    loc_t bof = find_bof(rsepref);
    debug("bof=0x%016llx",bof);

    loc_t bref = -4;
    while (true) {
        try {
            bref = find_call_ref(bof,0,bref+4);
        } catch (...) {
            if (patches.size()) {
                //failed to find ref, but we already have at least one patch. Should be good
                break;
            }else{
                //failed to find bref, but we didn't find the correct patch yet
                throw;
            }
        }
        debug("bref=0x%016llx",bref);
        vmem iter = _vmem->getIter(bref);

        if (--iter != insn::movz || iter().rd() != 2){
            //setting third arg
            error("unexpected insn before call");
            continue;
        }
        
        if (iter().imm() == 0) {
            debug("arg already good");
            continue;
        }
        
        {
            insn pinsn = insn::new_immediate_movz(iter.pc(), 0, iter().rd(), 0);
            uint32_t opcode = pinsn.opcode();
            patches.push_back({pinsn.pc(),&opcode,sizeof(opcode)});
        }
    }
    
    return patches;
}
