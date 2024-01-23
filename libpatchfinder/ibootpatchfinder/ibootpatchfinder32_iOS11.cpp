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
                vmem_thumb iter = _vmemThumb->getIter(bpr_reg_ref);
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


std::vector<patch> ibootpatchfinder32_iOS11::get_sigcheck_img4_patch(){
    std::vector<patch> patches;
    loc_t img4str = findstr("IMG4", true);
    debug("img4str=0x%08x",img4str);
    loc_t img4strref = -2;
    loc_t f1top = 0;
    loc_t f1topref = 0;
    
retry_find_ref:
    img4strref = find_literal_ref_thumb(img4str, 0, img4strref+2);
    debug("img4strref=0x%08x",img4strref);
    try{

        f1top = find_bof_thumb(img4strref);
        debug("f1top=0x%08x",f1top);

        f1topref = find_call_ref_thumb(f1top,1);
        debug("f1topref=0x%08x",f1topref);
    } catch (...){
        try {
            loc_t val = deref(img4strref);
            deref(val);
            warning("Failed to find f1topref, but 'img4strref' can be derefed. Is this a bad find? retrying...");
            goto retry_find_ref;
        } catch (...) {
            //
        }
        throw;
    }

    loc_t f2top = find_bof_thumb(f1topref);
    debug("f2top=0x%08x",f2top);

    
    vmem_thumb iter = _vmemThumb->getIter(f2top);

    loc_t val_r2 = 0;
    loc_t val_r3 = 0;
    
    while (true) {
        auto insn = ++iter;
        if (insn == arm32::ldr && insn.subtype() == st_literal) {
            if (insn.rt() == 2) {
                val_r2 = insn.imm();
            }else if (insn.rt() == 3) {
                val_r3 = insn.imm();
            }
        } else if (insn == arm32::bl){
            if (val_r2 && val_r3) {
                break;
            }
        }
    }

    loc_t callback_ptr = deref(val_r2);
    debug("callback_ptr=0x%08x",callback_ptr);

    loc_t callback = deref(callback_ptr) & ~1;
    debug("callback=0x%08x",callback);
    
    iter = callback;
    
    retassure(iter() == arm32::push, "unexpected instruction. Expecting push");

    while (++iter != arm32::pop || !iter().reglist().pc);

    loc_t pop_pc = iter;
    debug("pop_pc=0x%08x",pop_pc);

    while (--iter != arm32::mov) retassure(iter() != arm32::it, "found 'it' too early")
        ;
    
    loc_t movpos = iter;
    uint8_t movfromreg = iter().rm();
    debug("movpos=0x%08x",movpos);
    debug("movfromreg=%d",movfromreg);

    while (--iter != arm32::it)
        ;
    
    loc_t itpos = iter;
    debug("itpos=0x%08x",itpos);

    pushINSN(thumb::new_T1_immediate_movs(itpos, 0, movfromreg));

    return patches;
}
