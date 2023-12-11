//
//  kernelpatchfinder_iOS13.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 27.06.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//


#include "../../include/libpatchfinder/OFexception.hpp"
#include "kernelpatchfinder64_iOS13.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

std::vector<patch> kernelpatchfinder64_iOS13::get_generic_kernelpatches(){
    UNCACHEPATCHES;
    
    addPatches(get_MarijuanARM_patch());
    
    //codesignature
    addPatches(get_codesignature_patches());

//    addPatches(get_mount_patch());
//
//    addPatches(get_task_conversion_eval_patch());
//    addPatches(get_vm_fault_internal_patch());
//
//    addPatches(get_apfs_snapshot_patch());
    error("TODO: patchset is incomplete!");
    RETCACHEPATCHES;
}
#undef addPatches


patchfinder64::loc_t kernelpatchfinder64_iOS13::find_cs_blob_generation_count(){
    UNCACHELOC;
    loc_t strloc = findstr("\"success, but no blob!\"", true);
    debug("strloc=0x%016llx\n",strloc);

    loc_t strref = find_literal_ref(strloc);
    debug("strref=0x%016llx\n",strref);

    vmem iter = _vmem->getIter(strref);

    if (iter() == insn::add) --iter;
    
    loc_t bref = find_branch_ref((loc_t)iter,-0x1000);
    debug("bref=0x%016llx\n",bref);
    
    loc_t bof = find_bof(0xfffffff007d61bbc);
    debug("bof=0x%016llx\n",bof);

    loc_t mmm = find_literal_ref(0xfffffff0078e9680);
    debug("mmm=0x%016llx\n",mmm);

    reterror("todo");
}
