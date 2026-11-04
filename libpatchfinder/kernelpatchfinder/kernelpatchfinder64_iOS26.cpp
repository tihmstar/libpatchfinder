//
//  kernelpatchfinder64_iOS26.cpp
//  libpatchfinder
//
//  Created by erd on 11.11.25.
//
#include <libgeneral/macros.h>

#include "kernelpatchfinder64_iOS26.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all64.h"
#include "sbops64.h"
#include <string.h>

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

std::vector<patch> kernelpatchfinder64_iOS26::get_force_boot_ramdisk_patch(){
    UNCACHEPATCHES;

    {
        //no rootfs auth patch
        loc_t str = findstr("rootvp not authenticated after mounting", false);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);

        vmem iter = _vmem->getIter(ref);
        
        while ((--iter).supertype() != insn::sut_branch_imm)
            ;
        ++iter;
        loc_t bref = find_branch_ref(iter, -0x200);
        debug("bref=0x%16llx",bref);
        pushINSN(insn::new_general_nop(bref));
    }
    
    {
        //IOFindBSDRoot patch
        loc_t str = findstr("!BSD\n", true);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);
        
        vmem iter = _vmem->getIter(ref);


        while (true) {
            while (++iter != insn::bl)
                ;
            loc_t x1val = find_register_value(iter, 1,iter.pc()-0x20);
            if (!x1val) continue;
            try {
                if (strcmp((const char*)_vmem->memoryForLoc(x1val), "rd") != 0) continue;
            } catch (...) {
                continue;
            }
            
            ++iter;
            retassure(iter() == insn::cbnz, "unexpected insn");
            loc_t bdst = iter().imm();
            loc_t shellcodeEnd = iter;
            debug("shellcodeEnd=0x%16llx",shellcodeEnd);
            while (--iter != insn::mov || iter().rd() != 2)
                ;
            ++iter;
            loc_t shellcodeBegin = iter;
            debug("shellcodeBegin=0x%16llx",shellcodeBegin);
            retassure((shellcodeEnd-shellcodeBegin)/4 >= 3, "not enough room for shellcode");
            pushINSN(insn::new_immediate_movz(shellcodeBegin+0x00, 0x646d, 0, 0));
            pushINSN(insn::new_immediate_movk(shellcodeBegin+0x04, 0x30, 0, 16));
            pushINSN(insn::new_immediate_str_unsigned(shellcodeBegin+0x08, 0, 2, 0));
            pushINSN(insn::new_immediate_b(shellcodeBegin+0x0c, bdst));
            break;
        }
    }
    RETCACHEPATCHES;
}
