//
//  ibootpatchfinder32_iOS8.cpp
//  libpatchfinder
//
//  Created by erd on 16.10.23.
//
#include <libgeneral/macros.h>

#include "ibootpatchfinder32_iOS8.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

#define DEFAULT_BOOTARGS_STR "rd=md0 nand-enable-reformat=1 -progress"

std::vector<patch> ibootpatchfinder32_iOS8::get_honor_nvram_boot_arg_patch(){
    UNCACHEPATCHES;
    /*
     iPhone5,2 iOS 10.3.4
     */
    loc_t default_boot_args_str_loc = findstr(DEFAULT_BOOTARGS_STR, false);
    debug("default_boot_args_str_loc=0x%08x",default_boot_args_str_loc);
    
    loc_t default_boot_args_data_xref = memmem(&default_boot_args_str_loc, sizeof(default_boot_args_str_loc));
    debug("default_boot_args_data_xref=0x%08x",default_boot_args_data_xref);
    
    loc_t default_boot_args_xref = find_literal_ref_thumb(default_boot_args_str_loc);
    debug("default_boot_args_xref=0x%08x",default_boot_args_xref);
    
    loc_t env_get = find_env_get();
    debug("env_get=0x%08x",env_get);
    
    vmem_thumb iter = _vmemThumb->getIter(default_boot_args_xref);
    while ((--iter).supertype() != arm32::sut_branch_imm || iter() == arm32::bl)
        ;
    loc_t bstart = iter;
    debug("bstart=0x%08x",bstart);

    iter = default_boot_args_xref;
    while ((++iter).supertype() != arm32::sut_branch_imm || iter() == arm32::bl)
        ;
    
    loc_t bend = iter().imm();
    debug("bend=0x%08x",bend);

    iter = bstart;
    iter = iter().imm();
    uint8_t tgtreg = iter().rt();
    debug("tgtreg=%d",tgtreg);
    
    loc_t cur = bstart;
    pushINSN(thumb::new_T1_literal_ldr(cur, default_boot_args_data_xref, 0)); cur +=2;
    pushINSN(thumb::new_T1_immediate_bl(cur, env_get)); cur +=4;
    pushINSN(thumb::new_T2_register_mov(cur, tgtreg, 0)); cur +=2;
    while (cur < bend) {
        pushINSN(thumb::new_T1_general_nop(cur)); cur+=2;
    }

    {
        //old bootargs are not the "boot-args" string arg for getenv
        char argstr[] = "boot-args";
        patches.push_back({default_boot_args_str_loc, argstr, sizeof(argstr)});
    }

    RETCACHEPATCHES;
}
