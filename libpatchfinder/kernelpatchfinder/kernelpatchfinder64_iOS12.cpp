//
//  kernelpatchfinder64_iOS12.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 22.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include "kernelpatchfinder64_iOS12.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "kernelpatchfinder64_iOS13.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"


using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

std::vector<patch> kernelpatchfinder64_iOS12::get_codesignature_patches(){
    UNCACHEPATCHES;
    try {
        return get_trustcache_true_patch();
    } catch (tihmstar::exception &e) {
        error("Failed to get_trustcache_true_patch with error=%d (%s)",e.code(),e.what());
        e.dump();
        warning("Fallback to old-style amfi patches");
        
        addPatches(get_amfi_validateCodeDirectoryHashInDaemon_patch());
        addPatches(get_cs_enforcement_disable_amfi_patch());
        RETCACHEPATCHES;
    }
}

std::vector<patch> kernelpatchfinder64_iOS12::get_mount_patch(){
    UNCACHEPATCHES;
    
    loc_t mount = find_function_for_syscall(167);
    vmem iter = _vmem->getIter();
    
    try {
        iter = mount | 0xffffffUL << (6*8);;
    } catch (...) {
        warning("Failed to deref mount ptr, retrying with iOS 16 chains");
        iter = (mount & 0xFFFFFFFF) + _base;
    }
    
    debug("mount=0x%016llx\n",iter.pc());

    while (++iter != insn::bl);
    
    loc_t mount_internal = iter().imm();
    debug("mount_internal=0x%016llx\n",mount_internal);

    
    iter = mount_internal;
    
    while (++iter != insn::orr || iter().imm() != 0x10000);
    
    loc_t pos = iter;
    debug("pos=0x%016llx\n",pos);


    loc_t ref = find_branch_ref(pos, -0x100);
    debug("ref=0x%016llx\n",ref);

    iter = ref;
    
    while (--iter != insn::ldrb)
        ;
    
    {
        debug("p1=0x%016llx\n",(loc_t)iter);
        insn pins = insn::new_immediate_movz(iter, 0, iter().rn(), 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    
    while ((--iter != insn::tbz || iter().special() != 5) && (iter() != insn::tbnz || iter().special() != 5));

    loc_t p2 = iter;
    debug("p2=0x%016llx\n",p2);

    if (iter() == insn::tbnz) {
        patches.push_back({iter, "\x1F\x20\x03\xD5", 4});
    }else{
        insn pins = insn::new_immediate_b(iter, iter().imm());
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    
    /* ---- allow mounting / as root ---- */

    loc_t str = findstr("%s:%d: not allowed to mount as root\n", true);
    debug("str=0x%016llx\n",str);

    ref = find_literal_ref(str);
    debug("ref=0x%016llx\n",ref);

    iter = ref;
    
    while (--iter != insn::cmp)
        ;
    
    debug("p2=0x%016llx\n",(loc_t)iter);

    patches.push_back({iter, "\x1F\x00\x00\xEB" /* cmp x0, x0 */, 4});
    
    RETCACHEPATCHES;
}
