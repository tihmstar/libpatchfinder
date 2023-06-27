//
//  ibootpatchfinder64_iOS16.cpp
//  libpatchfinder
//
//  Created by tihmstar on 08.06.22.
//

#include "ibootpatchfinder64_iOS16.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS16::get_skip_set_bpr_patch(){
    UNCACHEPATCHES;
    
    /*
     In 16.1 20B5027f we're back to this again -_-"
0x00000001800cf2e8         mov        x8, #0x30
0x00000001800cf2ec         movk       x8, #0x102d, lsl #16
0x00000001800cf2f0         movk       x8, #0x2, lsl #32
0x00000001800cf2f4         ldr        w9, [x8]
0x00000001800cf2f8         ret
     
0x00000001800cf120         mov        x0, lr
0x00000001800cf124         bl         0x00000001800cf2e8
0x00000001800cf128         mov        lr, x0
0x00000001800cf12c         orr        w9, w9, #0x1
0x00000001800cf130         b          call_to_store
     */
    
    std::set<uint64_t> bpr_regs = {0x2102d0030/*t8010*/, 0x2352d0030/*t8015*/, 0x23d2dc030/*t8110*/};
    
    vmem iter = _vmem->getIter();
    try {
        while (true) {
        loop_start:
            while (++iter != insn::movz || iter().subtype() != insn::st_immediate)
                ;
            vmem iter2 = iter;
            uint8_t rd = iter().rd();
            loc_t tgtval = iter2().imm();
            
            loc_t didBranchTo = 0;
            
            for (int i=0; i<4; i++) {
                if (++iter2 != insn::movk || iter2().rd() != rd){
                    if (iter2() == insn::bl) {
                        iter2 = didBranchTo = iter2().imm();
                        continue;
                    }
                    break;
                }
                tgtval += iter2().imm();
            }
            
            if (bpr_regs.find(tgtval) == bpr_regs.end()) continue;

            if (iter2() != insn::ldr || iter2().rn() != rd) continue; //this should be fatal!
            uint8_t rt = iter2().rt();
            
            try{
                loc_t callref = -4;
                while ((callref = find_call_ref(iter,false,callref+4))) {
                    debug("callref=0x%llx",callref);
                    
                    iter2 = callref;
                    for (int i=0; i<4; i++) {
                        if (++iter2 == insn::orr && iter2().rn() == rt && iter2().imm() == 1) {
                            pushINSN(insn::new_register_mov(iter2, 0, iter2().rd(), iter2().rn()));
                            goto loop_start;
                        }
                    }
                }
            }catch(...){
                //
            }
        }
    } catch (...) {
        //
    }
    retassure(patches.size(), "Failed to find a single patch");
    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder64_iOS16::get_no_force_dfu_patch(){
    try {
        return ibootpatchfinder64_iOS15::get_no_force_dfu_patch();
    } catch (...) {
        //
    }
    UNCACHEPATCHES;

    loc_t tref = -4;
    while ((tref = find_literal_ref(100*1000,0,tref+4))) {
        vmem iter = _vmem->getIter(tref);
        debug("hit=0x%016llx",tref);
        if (++iter == insn::b) continue;
        debug("tref=0x%016llx",tref);
            
        {
            for (int i = 0; i< 10; i++){
                if (--iter == insn::bl) goto have_bl;
            }
            continue;
        have_bl:;
        }
        
        auto insn = ++iter;
        if (insn == insn::cbnz){
            pushINSN(insn::new_immediate_b(insn, insn.imm()));
            break;
        }else if (insn == insn::cbz){
            pushINSN(insn::new_general_nop(insn));
            break;
        }else{
            reterror("unexpected insn");
        }
    }

    retassure(patches.size(), "Failed to find patches");
    RETCACHEPATCHES;
}
