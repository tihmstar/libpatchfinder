//
//  kernelpatchfinder32_iOS10.cpp
//  libpatchfinder
//
//  Created by tihmstar on 18.11.26.
//

#include "kernelpatchfinder32_iOS10.hpp"

#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;


std::vector<patch> kernelpatchfinder32_iOS10::get_generic_kernelpatches(){
    UNCACHEPATCHES;
    /*
        iPhone5,2 iOS 10.3.4
        This is literally h3lix
     */
    addPatches(get_lwvm_rw_patch());
    addPatches(get_mount_patch());
    addPatches(get_insert_setuid_patch());
    addPatches(get_proc_enforce_disable_patch());
    addPatches(get_codesignature_patches());
    addPatches(get_always_get_task_allow_patch());
    addPatches(get_sandbox_label_update_execve_patch());
    addPatches(get_MarijuanARM_patch());
    addPatches(get_sandbox_patch());
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder32_iOS10::get_lwvm_rw_patch(){
    UNCACHEPATCHES;
    /*
        iPhone5,2 iOS 10.3.4
     */
    loc_t PE_i_can_has_kernel_configuration = find_sym("_PE_i_can_has_kernel_configuration");
    debug("PE_i_can_has_kernel_configuration=0x%08x",PE_i_can_has_kernel_configuration);

    loc_t str = findstr("_mapForIO", true);
    debug("str=0x%08x",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%08x",ref);

    loc_t bof = find_bof(ref);
    debug("bof=0x%08x",bof);

    auto iter = _vmemThumb->getIter(bof);
        
    while (true){
        while (++iter != arm32::bl)
            ;
        retassure(iter() != arm32::pop, "EOF");
        try {
            loc_t dst = bl_jump_stub_ptr_loc(iter);
            if ((_vmemThumb->deref(dst)>>1) == (PE_i_can_has_kernel_configuration>>1)) break;
        } catch (...) {
            //
        }
    }

    loc_t call_stub_stub_PE_i_can_has_kernel_configuration = iter;
    debug("call_stub_stub_PE_i_can_has_kernel_configuration=0x%08x",call_stub_stub_PE_i_can_has_kernel_configuration);

    while (++iter != arm32::b && iter() != arm32::bcond)
        ;

    loc_t baddst = iter().imm();
    debug("baddst=0x%08x",baddst);
    if (iter().insnsize() == 2) {
        pushINSN(thumb::new_T1_general_nop(iter));
    }else{
        pushINSN(thumb::new_T1_general_nop(iter.pc()));
        pushINSN(thumb::new_T1_general_nop(iter.pc()+2));
    }
    
    iter = baddst;
    --iter;
    pushINSN(thumb::new_T2_immediate_b(iter, iter().imm()));
    RETCACHEPATCHES;
}
