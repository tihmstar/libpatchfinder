//
//  ibootpatchfinder32_iOS13.cpp
//  libpatchfinder
//
//  Created by tihmstar on 20.07.21.
//

#include "ibootpatchfinder32_iOS13.hpp"
#include <libgeneral/macros.h>

#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

#define DEFAULT_BOOTARGS_STR "rd=md0"
#define CERT_STR "Apple Inc.1"

std::vector<patch> ibootpatchfinder32_iOS13::get_boot_arg_patch(const char *bootargs){
    std::vector<patch> patches;

    loc_t default_boot_args_str_loc = findstr(DEFAULT_BOOTARGS_STR, false);
    debug("default_boot_args_str_loc=0x%08x",default_boot_args_str_loc);
    
    loc_t default_boot_args_data_xref = memmem(&default_boot_args_str_loc, sizeof(default_boot_args_str_loc));
    debug("default_boot_args_data_xref=0x%08x",default_boot_args_data_xref);

    loc_t default_boot_args_xref = find_literal_ref_thumb(default_boot_args_str_loc);
    debug("default_boot_args_xref=0x%08x",default_boot_args_xref);

    
    if (strlen(bootargs) > strlen(DEFAULT_BOOTARGS_STR)) {
        loc_t cert_str_loc = 0;
        debug("Relocating boot-args string...");

        /* Find the "Reliance on this cert..." string. */
        retassure(cert_str_loc = findstr(CERT_STR,false), "Unable to find \"%s\" string!", CERT_STR);

        debug("\"%s\" string found at 0x%08x", CERT_STR, cert_str_loc);

        /* Point the boot-args xref to the "Reliance on this cert..." string. */
        debug("Pointing default boot-args xref to 0x%08x...", cert_str_loc);

        default_boot_args_str_loc = cert_str_loc;
        
        patches.push_back({default_boot_args_data_xref, &default_boot_args_str_loc, sizeof(default_boot_args_str_loc)});
    }
    
    debug("Applying custom boot-args \"%s\"\n", bootargs);
    patches.push_back({default_boot_args_str_loc, bootargs, strlen(bootargs)+1});

    vmem_thumb iter = _vmemThumb->getIter(default_boot_args_xref);
        
    if ((--iter).supertype() != sut_branch_imm) {
        for (int i=0; i<2; i++,--iter) {
            if ((iter() == arm32::bl || --iter == arm32::bl) && (--iter).supertype() == sut_branch_imm) {
                goto validated_insn;
            }
        }
        reterror("unexpected insn");
    }else{
        //all good, this was expected!
    }
validated_insn:

    //make this beq unconditional
    pushINSN(thumb::new_T2_immediate_b(iter, iter().imm()));
    
    //follow branch
    iter = iter().imm();
    loc_t bdst = iter;
    debug("bdst=0x%08x",bdst);
    
    if (iter() == arm32::ldr && iter().subtype() == st_literal) {
        //replace that reg with out bootarg
        loc_t literalloc = iter().imm();
        debug("literalloc=0x%08x",literalloc);
        patches.push_back({literalloc, &default_boot_args_str_loc, sizeof(default_boot_args_str_loc)});
    }else{
        reterror("unimplemented case");
    }
    return patches;
}


std::vector<patch> ibootpatchfinder32_iOS13::get_force_septype_local_patch(){
    std::vector<patch> patches;

    loc_t rsepref = -2;
    while (true) {
        try {
            assure(rsepref = find_literal_ref_thumb('rsep',0,rsepref+2));
        } catch (...) {
            if (patches.size()) {
                //failed to find ref, but we already have at least one patch. Should be good
                break;
            }else{
                //failed to find bref, but we didn't find the correct patch yet
                throw;
            }
        }
        try {
            loc_t sepiref = 0;
            assure(sepiref = find_literal_ref_thumb('sepi',0,rsepref-0x20));
            if (abs((int64_t)(sepiref-rsepref)) < 0x10) {
                debug("skipping rsepref=0x%08x",rsepref);
                continue;
            }
        } catch (...) {
            //
        }
        debug("rsepref=0x%08x",rsepref);
        vmem_thumb iter = _vmemThumb->getIter(rsepref);
        if (iter() != ldr || iter().rt() != 1){
            debug("skipping reference by unexpected instruction!");
            continue;
        }
        uint32_t imm = iter().imm();
        uint32_t val = 'sepi';
        patches.push_back({imm, &val, sizeof(val)});
    }
    
    retassure(patches.size(), "Failed to find even a single patch");
    return patches;
}
