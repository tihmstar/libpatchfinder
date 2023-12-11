//
//  kernelpatchfinder32_iOS6.cpp
//  libpatchfinder
//
//  Created by Elcomsoft R&D on 15.03.23.
//

#include "kernelpatchfinder32_iOS6.hpp"
#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;

std::vector<patch> kernelpatchfinder32_iOS6::get_amfi_validateCodeDirectoryHashInDaemon_patch(){
    std::vector<patch> patches;
    loc_t str = findstr("int _validateCodeDirectoryHashInDaemon",false);
    debug("str=0x%08x",str);

    loc_t ref = find_literal_ref_thumb(str);
    debug("ref=0x%08x",ref);
    
    loc_t memcmp = 0;

    if (haveSymbols()) {
        memcmp = find_sym("_memcmp");
    }else{
        reterror("unimplemented");
    }
    debug("memcmp=0x%08x",memcmp);
    
    loc_t bl_amfi_memcp_loc = 0;
    vmem_thumb bl_amfi_memcp_f = _vmemThumb->getIter(ref);
    vmem_thumb bl_amfi_memcp_b = _vmemThumb->getIter(ref);
    loc_t jscpl = 0;
    for (int i=0; i < 50; i++) {
        while (++bl_amfi_memcp_f != arm32::bl)
            ;
        while (--bl_amfi_memcp_b != arm32::bl)
            ;

        loc_t jscpl_f = 0;
        loc_t jscpl_b = 0;

        try {
            jscpl_f = bl_jump_stub_ptr_loc(bl_amfi_memcp_f);
        } catch (tihmstar::exception &e) {
            //
        }
        try {
            jscpl_b = bl_jump_stub_ptr_loc(bl_amfi_memcp_b);
        } catch (tihmstar::exception &e) {
            //
        }
        
        if (jscpl_f) {
            debug("bl_stub=0x%08x (0x%08x) -> 0x%08x",(loc_t)bl_amfi_memcp_f,jscpl_f,_vmemThumb->deref(jscpl_f));
            if ((_vmemThumb->deref(jscpl_f)>>1) == (memcmp>>1)){
                bl_amfi_memcp_loc = bl_amfi_memcp_f;
                jscpl = jscpl_f;
                break;
            }
        }
        if (jscpl_b) {
            debug("bl_stub=0x%08x (0x%08x) -> 0x%08x",(loc_t)bl_amfi_memcp_b,jscpl_b,_vmemThumb->deref(jscpl_b));
            if ((_vmemThumb->deref(jscpl_b)>>1) == (memcmp>>1)){
                bl_amfi_memcp_loc = bl_amfi_memcp_b;
                jscpl = jscpl_b;
                break;
            }
        }
    }
    retassure(bl_amfi_memcp_loc && jscpl, "Failed to find bl_amfi_memcp_loc or jscpl");
    debug("bl_amfi_memcp_loc=0x%08x",bl_amfi_memcp_loc);

    /* find*/
    //movs r0, #0x0
    //bx lr
    vmem_thumb ret0 = _vmemThumb->getIter(memcmp);
    while (1) {
        while (++ret0 != arm32::mov || ret0().subtype() != st_immediate || ret0().rd() != 0 || ret0().imm() != 0)
            ;
        if (++ret0 == arm32::bx && ret0().rm() == 14 ){
            --ret0;
            break;
        }
    }
    loc_t ret0_gadget = ret0;
    ret0_gadget |= 1;
    debug("ret0_gadget=0x%08x",ret0_gadget);

    patches.push_back({jscpl,&ret0_gadget,sizeof(ret0_gadget),slide_ptr});
    
    retassure(patches.size(), "Failed to find a single patch");
    return patches;
}
