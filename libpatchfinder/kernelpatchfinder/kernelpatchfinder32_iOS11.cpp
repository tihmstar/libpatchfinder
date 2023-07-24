//
//  kernelpatchfinder32_iOS11.cpp
//  libpatchfinder
//
//  Created by tihmstar on 21.07.21.
//

#include "kernelpatchfinder32_iOS11.hpp"
#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;


std::vector<patch> kernelpatchfinder32_iOS11::get_codesignature_patches(){
    try {
        return get_trustcache_true_patch();
    } catch (tihmstar::exception &e) {
        error("Failed to get_trustcache_true_patch with error=%d (%s)",e.code(),e.what());
        e.dump();
        warning("Fallback to old-style amfi patches");
        
        std::vector<patch> patches;
        addPatches(get_amfi_validateCodeDirectoryHashInDaemon_patch());
        addPatches(get_cs_enforcement_disable_amfi_patch());
        return patches;
    }
}

std::vector<patch> kernelpatchfinder32_iOS11::get_mount_patch(){
    std::vector<patch> patches;

    loc_t mount = (loc_t)find_function_for_syscall(167);
    mount &= ~1;
    debug("mount=0x%08x",mount);

    vmem_thumb iter = _vmemThumb->getIter(mount);

    while (++iter != arm32::bl);

    loc_t mount_internal = iter().imm();
    debug("mount_internal=0x%08x",mount_internal);


    iter = mount_internal;
    uint8_t flagsreg = 0;

    while (++iter != arm32::orr || iter().subtype() != st_immediate || iter().imm() != 0x10000);
    flagsreg = iter().rd();
    
    loc_t pos = iter;
    debug("pos=0x%08x",pos);


    try {
        loc_t ref = find_branch_ref_thumb(pos, -0x100, 0);
        debug("ref=0x%08x",ref);
        iter = ref;
    } catch (...) {
        debug("Failed to find ref, assuming old style layout");
        iter = pos;
    }
    
    //patch MNT_RDONLY check
    debug("patching MNT_RDONLY check ...");
    if (iter().insnsize() == 2) {
        pushINSN(arm32::thumb::new_T2_immediate_b(iter, pos));
    }else{
        reterror("unimplemented");
    }

    {
        bool isLSL = false;
        bool isTST = false;
        
        for (int i=0; i<2; i++){
            auto insn = --iter;
            isTST |= (insn == tst);
            isLSL |= (insn == arm32::lsl && insn.subtype() == st_immediate && insn.rm() == flagsreg && insn.imm() == 0x1f);
        }
        retassure(isLSL || isTST, "expected tst or lsls");
    }

    try {
        while (iter.pc() > mount_internal) {
            while (true) {
                auto insn = --iter;
                if (insn == arm32::tst && insn.subtype() == st_immediate && insn.rn() == flagsreg && insn.imm() == 0x20) break;
                if (insn == arm32::lsl && insn.subtype() == st_immediate && insn.rm() == flagsreg && insn.imm() == 0x1a) break;
            }
            debug("detected MNT_UNION check! patching...");

            retassure((++iter).supertype() == sut_branch_imm, "expected bcond");
            if (iter().insnsize() == 2) {
                pushINSN(thumb::new_T1_general_nop(iter));
            }else{
                pushINSN(thumb::new_T1_general_nop(((loc_t)iter)));
                pushINSN(thumb::new_T1_general_nop(((loc_t)iter)+2));
            }
            break;
        }
    } catch (...) {
        //
    }
    
    /* ---- allow mounting / as root ---- */

    loc_t str = findstr("%s:%d: not allowed to mount as root\n", true);
    debug("str=0x%08x",str);

    loc_t ref = find_literal_ref_thumb(str);
    debug("ref=0x%08x",ref);
    
    iter = ref;
    
    {
        int i=0;
        while (i<0x24) {
            while (--iter != arm32::cmp) i+=2;
            if ((iter + 1).supertype() == sut_branch_imm) break;
            warning("unexpected instruction! expected bcond, but got something else. Ignoring this, since we're still in range and this might be misaligned parsing issue...");
        }
        retassure(i < 0x24, "Search for bcond went too far, aborting!");
    }
    
    retassure((++iter).supertype() == sut_branch_imm, "expected bcond");

    loc_t p2 = iter;
    debug("p2=0x%08x",p2);
    
    pushINSN(thumb::new_T2_immediate_b(p2, iter().imm()));

    return patches;
}
