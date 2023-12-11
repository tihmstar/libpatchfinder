//
//  ibootpatchfinder32_iOS12.cpp
//  libpatchfinder
//
//  Created by tihmstar on 21.12.21.
//

#include "ibootpatchfinder32_iOS12.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

std::vector<patch> ibootpatchfinder32_iOS12::get_force_septype_local_patch(){
    std::vector<patch> patches;

    loc_t rsepref = find_literal_ref_thumb('rsep');
    debug("rsepref=0x%08x",rsepref);
    loc_t bof = find_bof_thumb(rsepref);
    debug("bof=0x%08x",bof);

    loc_t bref = -2;
    while (true) {
        try {
            bref = find_call_ref_thumb(bof,0,bref+2);
        } catch (...) {
            if (patches.size()) {
                //failed to find ref, but we already have at least one patch. Should be good
                break;
            }else{
                //failed to find bref, but we didn't find the correct patch yet
                throw;
            }
        }
        debug("bref=0x%08x",bref);
        vmem_thumb iter = _vmemThumb->getIter(bref);

        if (--iter != mov || (iter().rd() != 2 && (--iter != mov || iter().rd() != 2))){
            //setting third arg
            error("unexpected insn before call");
            continue;
        }
        
        if (iter().imm() == 0) {
            debug("arg already good");
            continue;
        }
        
        pushINSN(thumb::new_T1_immediate_movs(iter.pc(), 0, iter().rd()));
        if (iter().insnsize() == 4) pushINSN(thumb::new_T1_general_nop(iter.pc()+2));
    }
     
    return patches;
}
