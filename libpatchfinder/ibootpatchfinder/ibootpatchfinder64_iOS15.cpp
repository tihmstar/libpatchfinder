//
//  ibootpatchfinder64_iOS15.cpp
//  libpatchfinder
//
//  Created by tihmstar on 01.10.21.
//

#include "ibootpatchfinder64_iOS15.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS15::get_sigcheck_img4_patch(){
    UNCACHEPATCHES;
    loc_t findpos = 0;
    vmem iter = _vmem->getIter();
    
    /* We are looking for this:
     0x00000001800312e4         ldr        x8, [x19, #0x10]
     0x00000001800312e8         cmp        x8, #0x4
     0x00000001800312ec         b.eq       loc_180031388

     0x00000001800312f0         cmp        x8, #0x2
     0x00000001800312f4         b.eq       loc_180031344

     0x00000001800312f8         cmp        x8, #0x1
     0x00000001800312fc         b.ne       loc_180031a88
     */
    
    while (!findpos) {
        if (++iter != insn::ldr || iter().imm() != 0x10) continue;

        if (++iter != insn::cmp || iter().imm() != 4) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        if (++iter != insn::cmp || iter().imm() != 2) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        if (++iter != insn::cmp || iter().imm() != 1) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        
        findpos = iter;
    }
    debug("findpos=0x%016llx",findpos);

    while (true) {
        while (++iter != insn::ldp);
        if (++iter != insn::ldp) continue;
        if (++iter != insn::ldp) continue;
        if (++iter != insn::ldp) continue;
        ++iter;
        break;
    }
    
    loc_t funcend = iter;
    debug("funcend=0x%016llx",funcend);
    
    while ((--iter != insn::mov || iter().rd() != 0))
        ;
    loc_t overwrite = iter;
    debug("overwrite=0x%016llx",overwrite);
    /*
        looking for:
     000000087000f7e4 mov x0, x20
     */

    pushINSN(insn::new_immediate_movz(overwrite, 0, 0, 0));
    RETCACHEPATCHES;
}
