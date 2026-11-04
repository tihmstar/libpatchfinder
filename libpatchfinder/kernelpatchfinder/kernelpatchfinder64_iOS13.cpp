//
//  kernelpatchfinder_iOS13.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 27.06.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//
#include <libgeneral/macros.h>

#include "../../include/libpatchfinder/OFexception.hpp"
#include "kernelpatchfinder64_iOS13.hpp"
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

std::vector<patch> kernelpatchfinder64_iOS13::get_allow_sep_boot_skip_stage1(){
    UNCACHEPATCHES;

    loc_t str1 = findstr("\"SEP Boot Failure: unexpected status 1:", false);
    debug("str1=0x%llx",str1);
    retassure(str1, "Failed to find str1");

    loc_t str2 = findstr("\"SEP Boot Failure: unexpected status 2:", false);
    debug("str2=0x%llx",str2);
    retassure(str2, "Failed to find str2");
    
    loc_t ref1 = find_literal_ref(str1);
    debug("ref1=0x%llx",ref1);
    retassure(ref1, "ref1 to str1");

    loc_t ref2 = find_literal_ref(str2);
    debug("ref2=0x%llx",ref2);
    retassure(ref2, "ref2 to str2");

    auto iter = _vmem->getIter(ref1);
    loc_t refBBStart1 = 0;
    {
        loc_t bref = 0;
        loc_t cref = 0;
        for (int i=0; i<15; i++) {
            try {
                bref = find_branch_ref(iter, -0x600);
                goto didfindbref;
            } catch (...) {
                if (!cref) {
                    try {
                        cref = find_call_ref(iter);
                        debug("cref=0x%llx",cref);
                        iter = cref;
                        i = -1;
                        continue;
                    } catch (...) {
                        //
                    }
                }
                --iter;
            }
        }
        reterror("Failed to find bref!");
    didfindbref:;
        debug("bref=0x%llx",bref);
        iter = bref;
        refBBStart1 = iter().imm();
        retassure(--iter == insn::cmp, "unexpected insn");
    }
    debug("refBBStart1=0x%llx",refBBStart1);
    
    iter = _vmem->getIter(ref2);
    loc_t ref2Block = 0;
    {
        loc_t bref = 0;
        loc_t cref = 0;
        for (int i=0; i<15; i++) {
            try {
                bref = find_branch_ref(iter, -0x600);
                goto didfindbref2;
            } catch (...) {
                if (!cref) {
                    try {
                        cref = find_call_ref(iter);
                        debug("cref=0x%llx",cref);
                        iter = cref;
                        i = -1;
                        continue;
                    } catch (...) {
                        //
                    }
                }
                --iter;
            }
        }
        reterror("Failed to find bref!");
    didfindbref2:;
        debug("bref=0x%llx",bref);
        ref2Block = bref;
        iter = bref;
        retassure(--iter == insn::cmp, "unexpected insn");
    }
    debug("ref2Block=0x%llx",ref2Block);

    loc_t target = 0;
    iter = ref2Block;

    while ((--iter).supertype() != insn::sut_branch_imm)
        ;
    ++iter;
    target = iter;
    debug("target=0x%llx",target);

    
    pushINSN(insn::new_immediate_b(refBBStart1, target));
    
    RETCACHEPATCHES;
}
