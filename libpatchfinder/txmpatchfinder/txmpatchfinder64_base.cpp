//
//  txmpatchfinder64_base.cpp
//  libpatchfinder
//
//  Created by erd on 13.10.26.
//

#include "txmpatchfinder64_base.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

#pragma mark txmpatchfinder64_base
txmpatchfinder64_base::txmpatchfinder64_base(const char *filename)
: txmpatchfinder64(filename)
{
    //
}

txmpatchfinder64_base::txmpatchfinder64_base(const void *buffer, size_t bufSize, bool takeOwnership)
: txmpatchfinder64(buffer, bufSize, takeOwnership)
{
    //
}

txmpatchfinder64_base::txmpatchfinder64_base(txmpatchfinder64 &&mv)
: txmpatchfinder64(std::move(mv))
{
    //
}

txmpatchfinder64_base::~txmpatchfinder64_base(){
    //
}

#pragma mark Patch finders

std::vector<patch> txmpatchfinder64_base::get_codesignature_patches(){
    UNCACHEPATCHES;
    /*
        iOS 27.0 iPhone12,1
     */
    auto iter = _vmem->getIter();

    /*
        Query module
     */
    while (true) {
        try {
            if (++iter != insn::mov || iter().rd() != 0) continue;
            if (++iter != insn::mov || iter().rd() != 1) continue;
            if (++iter != insn::movz || iter().rd() != 2 || iter().imm() != 0x14) continue;
            if (++iter != insn::bl) continue;
        } catch (tihmstar::out_of_range &e) {
            break;
        }
        loc_t hit = iter;
        debug("hit=0x%016llx",hit);
        pushINSN(insn::new_immediate_movz(iter, 0, 0, 0));
    }
    retassure(patches.size(), "Failed to find single patch");

    /*
        sig constraints
     */
    loc_t ref = find_literal_ref(0x22da1);
    debug("ref=0x%016llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);
    
    iter = bof;
    
    while (++iter != insn::bcond && iter() != insn::cbz && iter() != insn::cbnz)
        ;
    
    loc_t failloc = iter().imm();
    debug("failloc=0x%016llx",failloc);
    
    pushINSN(insn::new_general_nop(iter));
    while (++iter != insn::ret) {
        if ((iter() == insn::bcond || iter() == insn::cbz || iter() == insn::cbnz) && iter().imm() == failloc) {
            pushINSN(insn::new_general_nop(iter));
        }
    }

    RETCACHEPATCHES;
}
