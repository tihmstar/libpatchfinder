//
//  ibootpatchfinder32_iOS11.cpp
//  libpatchfinder
//
//  Created by tihmstar on 11.12.21.
//

#include "ibootpatchfinder32_iOS11.hpp"
#include <libgeneral/macros.h>

#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

std::vector<patch> ibootpatchfinder32_iOS11::get_skip_set_bpr_patch(){
    std::vector<patch> patches;
    for (uint32_t bpr_reg : {0x481d0030/*0x8004*/}) {
        loc_t bpr_reg_ref = -2;
        size_t insn_size = 2;
        while ((bpr_reg_ref = find_literal_ref_thumb(bpr_reg,0,(loc_t)(bpr_reg_ref+insn_size)))){
            if (bpr_reg_ref) {
                vmem_thumb iter = _vmem->getIter(bpr_reg_ref);
                insn_size = iter().insnsize();
                uint8_t addr_reg = iter().rt();
                assure(++iter == ldr && iter().rn() == addr_reg);
                uint8_t val_reg = iter().rt();
                
                for (int i=0; i<5; i++) {
                    if (++iter == orr && iter().rn() == val_reg && iter().imm() == 1) {
                        debug("setBPR=0x%08x",iter.pc());
                        pushINSN(thumb::new_T1_general_nop(iter));
                        if (iter().insnsize() == 4) pushINSN(thumb::new_T1_general_nop(iter.pc()+2));
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
