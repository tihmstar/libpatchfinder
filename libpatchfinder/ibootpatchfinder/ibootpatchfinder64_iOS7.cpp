//
//  ibootpatchfinder64_iOS7.cpp
//  libpatchfinder
//
//  Created by tihmstar on 07.04.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include "ibootpatchfinder64_iOS7.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"


using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS7::get_sigcheck_img4_patch(){
    std::vector<patch> patches;
    try {
        addPatches(ibootpatchfinder64_base::get_sigcheck_img4_patch());
        return patches;
    } catch (tihmstar::exception &e) {
        warning("Failed to get iboot sigpatches using multi-strb strategy. Retrying with callback strategy");
    }

    loc_t img4str = findstr("IMG4", true);
    debug("img4str=0x%016llx\n",img4str);

    loc_t img4strref = find_literal_ref(img4str);
    debug("img4strref=0x%016llx\n",img4strref);

    loc_t f1top = find_bof(img4strref);
    debug("f1top=0x%016llx\n",f1top);

    loc_t f1topref = find_call_ref(f1top,1);
    debug("f1topref=0x%016llx\n",f1topref);

    loc_t f2top = find_bof(f1topref);
    debug("f2top=0x%016llx\n",f2top);

    vmem iter = _vmem->getIter(f2top);

    loc_t val_x2 = 0;
    loc_t val_x3 = 0;

    while (true) {
        if (++iter == insn::adr) {
            if (iter().rd() == 2) {
                val_x2 = iter().imm();
            }else if (iter().rd() == 3) {
                val_x3 = iter().imm();
            }
        } else if (iter() == insn::adrp){
            if (iter().rd() == 2) {
                val_x2 = iter().imm();
            }else if (iter().rd() == 3) {
                val_x3 = iter().imm();
            }
        } else if (iter() == insn::add){
            if (iter().rd() == 2) {
                val_x2 += iter().imm();
            }else if (iter().rd() == 3) {
                val_x3 += iter().imm();
            }
        } else if (iter() == insn::bl){
            if (val_x2 && val_x3) {
                /*
                    add x3, sp, #0xd8
                    is kinda cheating, but well, whatever
                 */
                break;
            }else{
                val_x2 = 0;
                val_x3 = 0;
            }
        }
    }
    
    loc_t callback = val_x2;
    debug("callback=0x%016llx\n",callback);

    iter = callback;
    
    while (++iter != insn::ret);
    
    loc_t ret = iter;
    debug("ret=0x%016llx\n",ret);
    
    //tested with iBoot-1940.1.75 and iBoot-2696
    while (--iter == insn::ldp); // a few ldp
    assure(iter() == insn::sub); //one sub
    assure((--iter).supertype() == insn::sut_branch_imm); //one cbnz or bne
    loc_t branch = iter;
    debug("branch=0x%016llx\n",branch);

    pushINSN(insn::new_immediate_movz(branch, 0, 0, 0));
    
    return patches;
}
