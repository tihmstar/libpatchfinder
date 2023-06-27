//
//  kernelpatchfinder32_iOS9.cpp
//  libpatchfinder
//
//  Created by tihmstar on 26.07.21.
//

#include "kernelpatchfinder32_iOS9.hpp"
#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;

std::vector<patch> kernelpatchfinder32_iOS9::get_mount_patch(){
    std::vector<patch> patches;

    loc_t mount = (loc_t)find_function_for_syscall(167);
    mount &= ~1;
    debug("mount=0x%08x",mount);

    vmem_thumb iter = _vmem->getIter(mount);

    while (++iter != arm32::bl);

    loc_t mount_internal = iter().imm();
    debug("mount_internal=0x%08x",mount_internal);


    iter = mount_internal;

    while (++iter != arm32::orr || iter().subtype() != st_immediate || iter().imm() != 0x10000);

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
        //this is yet another case??
        for (int i=0; i<8; i++) {
            if (--iter == arm32::tst) break;
        }
        retassure(iter() == arm32::tst, "unexpected insn");
        --iter;
        loc_t ref = 0;
        loc_t pos = iter.pc();
        try {
            ref = find_branch_ref_thumb(pos, -0x100, 0);
        } catch (...) {
            pos -= 2;
            ref = find_branch_ref_thumb(pos, -0x100, 0);
        }
        debug("pos=0x%08x",pos);
        debug("ref=0x%08x",ref);

        iter = ref;
        if (iter().imm() == pos) {
            pushINSN(arm32::thumb::new_T1_general_nop(ref));
            if (iter().insnsize() == 4) {
                pushINSN(arm32::thumb::new_T1_general_nop(ref+2));
            }
        }else{
            pushINSN(arm32::thumb::new_T2_immediate_b(ref, pos));
        }
    }

    retassure(--iter == tst || --iter == tst, "expected tst");
    uint8_t flagsreg = iter().rn();
    
    try {
        while (iter.pc() > mount_internal) {
            while (--iter != arm32::tst || iter().subtype() != st_immediate || iter().rn() != flagsreg || iter().imm() != 0x20)
                ;
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
    
    return patches;
}
