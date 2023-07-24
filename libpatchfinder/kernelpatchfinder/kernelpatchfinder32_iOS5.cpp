//
//  kernelpatchfinder32_iOS5.cpp
//  libpatchfinder
//
//  Created by erd on 06.07.23.
//

#include "kernelpatchfinder32_iOS5.hpp"
#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;

std::vector<patch> kernelpatchfinder32_iOS5::get_allow_UID_key_patch(){
    std::vector<patch> patches;
    vmem_thumb iter = _vmemThumb->getIter();
    
    while (true) {
        while (++iter != arm32::cmp || iter().subtype() != st_immediate)
            ;
        if (iter().imm() != 0x3e8 && iter().imm() != 0x7d0) {
            continue;
        }
        uint8_t cmpreg = iter().rn();
        uint32_t val = iter().imm();
        
        vmem_thumb iter2 = iter;
        
        for (int i=0; i<4; i++) {
            auto insn = ++iter2;
            if (insn == arm32::cmp && insn.subtype() == st_immediate && insn.rn() == cmpreg && (insn.imm() == (val == 0x3e8 ? 0x7d0 : 0x3e8))){
                
                vmem_thumb iter3 = iter2;
                for (int j=0; j<4; j++) {
                    if (++iter3 == arm32::mov && iter3().imm() == 0x835){
                        loc_t cmp = iter;
                        loc_t cmp2 = iter2;
                        debug("cmp1=0x%08x",cmp);
                        debug("cmp2=0x%08x",cmp2);

                        pushINSN(arm32::thumb::new_T2_immediate_cmp(cmp, 0xff, cmpreg));
                        pushINSN(arm32::thumb::new_T2_immediate_cmp(cmp2, 0xff, cmpreg));
                        return patches;
                    }
                }
            }
        }
    }
    reterror("failed to find patch");
}

std::vector<patch> kernelpatchfinder32_iOS5::get_cs_enforcement_disable_amfi_patch(){
    std::vector<patch> patches;
    loc_t str = findstr("csflags",true);
    debug("str=0x%08x",str);

    loc_t ref = find_literal_ref_thumb(str);
    debug("ref=0x%08x",ref);
    assure(ref);

    vmem_thumb iter = _vmemThumb->getIter(ref);

    while (--iter != arm32::push);
    pushINSN(thumb::new_T1_immediate_movs(iter, 0, 0));
    pushINSN(thumb::new_T1_general_bx(iter.pc()+2, 14));

    return patches;
}
