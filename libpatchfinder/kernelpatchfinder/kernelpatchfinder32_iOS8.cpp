//
//  kernelpatchfinder32_iOS8.cpp
//  libpatchfinder
//
//  Created by tihmstar on 13.08.21.
//

#include "kernelpatchfinder32_iOS8.hpp"
#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;


std::vector<patch> kernelpatchfinder32_iOS8::get_cs_enforcement_disable_amfi_patch(){
    std::vector<patch> patches;
    loc_t str = findstr("csflags",true);
    debug("str=0x%08x",str);

    loc_t ref = find_literal_ref_thumb(str);
    debug("ref=0x%08x",ref);

    vmem_thumb cbz = _vmem->getIter(ref);
    while (--cbz != arm32::cbz);

    vmem_thumb mov(cbz);
    while (++mov != arm32::mov);
    --mov;

    int anz = static_cast<int>((mov.pc()-cbz.pc())/2 +1);

    for (int i=0; i<anz; i++) {
        pushINSN(thumb::new_T1_general_nop((cbz.pc()+2*i)));
    }

    return patches;
}
