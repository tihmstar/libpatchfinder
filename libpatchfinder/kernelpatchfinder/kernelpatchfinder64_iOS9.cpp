//
//  kernelpatchfinder64_iOS9.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 25.02.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include "kernelpatchfinder64_iOS9.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"


using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;


std::vector<patch> kernelpatchfinder64_iOS9::get_mount_patch(){
    UNCACHEPATCHES;
    
    loc_t mount = find_function_for_syscall(167);
    mount |= 0xffffffUL << (6*8);
    debug("mount=0x%016llx\n",mount);
    
    vmem iter = _vmem->getIter(mount);
    
    while (++iter != insn::bl);
    
    loc_t mount_internal = iter().imm();
    debug("mount_internal=0x%016llx\n",mount_internal);

    
    iter = mount_internal;
    
    while (++iter != insn::orr || iter().imm() != 0x10000);
    
    loc_t pos = iter;
    debug("pos=0x%016llx\n",pos);
    
    try {
        loc_t ref = find_branch_ref(pos, -0x100);
        debug("ref=0x%016llx\n",ref);
        iter = ref-4;
    } catch (...) {
        debug("Failed to find ref, assuming old style layout");
        iter = pos;
    }
    
    //patch MNT_RDONLY check
    while (++iter != insn::tbz && iter() != insn::tbnz);
    assure(iter().special() == 0);
    uint8_t flagsreg = iter().rt();
    if (iter() == insn::tbz) {
        pushINSN(insn::new_general_nop(iter));
    }else{
        pushINSN(insn::new_immediate_b(iter, iter().imm()));
    }
    
    //patch MNT_UNION check
    iter = pos;
    while (iter.pc() > mount_internal) {
        while (--iter != insn::tbz && iter() != insn::tbnz);
        if (iter().special() == 0x5 && iter().rt() == flagsreg) {
            debug("detected MNT_UNION check! patching...");
            if (iter() == insn::tbz) {
                pushINSN(insn::new_immediate_b(iter, iter().imm()));
            }else{
                pushINSN(insn::new_general_nop(iter));
            }
            break;
        }
    }
    
    RETCACHEPATCHES;
}
