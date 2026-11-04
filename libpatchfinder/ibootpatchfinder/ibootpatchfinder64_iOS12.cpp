//
//  ibootpatchfinder64_iOS12.cpp
//  libpatchfinder
//
//  Created by tihmstar on 22.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//
#include <libgeneral/macros.h>

#include "ibootpatchfinder64_iOS12.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS12::get_force_septype_local_patch(){
    std::vector<patch> patches;

    loc_t rsepref = find_literal_ref('rsep');
    assure(rsepref);
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
