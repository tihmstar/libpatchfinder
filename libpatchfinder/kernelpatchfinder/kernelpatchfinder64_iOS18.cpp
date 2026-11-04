//
//  kernelpatchfinder64_iOS18.cpp
//  libpatchfinder
//
//  Created by erd on 15.07.26.
//

#include "kernelpatchfinder64_iOS18.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all64.h"
#include "sbops64.h"
#include <string.h>

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

patchfinder64::loc_t kernelpatchfinder64_iOS18::find_query_trustcache(){
    UNCACHELOC;
    try {
        return find_sym("_query_trust_cache");
    } catch (...) {
        //
    }
    /*
        A12 PPL stuff
     */
    auto iter = _vmem->getIter();
    loc_t target = 0;
    while (!target) {
        while (++iter != insn::movz || iter().subtype() != insn::st_immediate || iter().rd() != 15 || iter().imm() != 0x63)
            ;
        target = iter;
        if (++iter != insn::b)
            target = 0;
    }
    debug("target=0x%016llx",target);

    loc_t bref = find_branch_ref(target, 0);
    debug("bref=0x%016llx",bref);
    
    iter = bref;

    for (int i=0; i<10; i++) {
        if (--iter == insn::bti) goto found_bof;
    }
    /*
        iPhone11,2 iOS 18.0 the bti instruction disappeared
     */
    iter = bref;
    for (int i=0; i<10; i++) {
        if (--iter == insn::cbz) goto found_bof;
    }
    reterror("Failed to find query_trustcache");

found_bof:;
    RETCACHELOC(iter);
}
