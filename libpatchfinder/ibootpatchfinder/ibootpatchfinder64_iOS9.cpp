//
//  ibootpatchfinder64_iOS9.cpp
//  libpatchfinder
//
//  Created by tihmstar on 15.02.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//
#include <libgeneral/macros.h>

#include "ibootpatchfinder64_iOS9.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace arm64;

ibootpatchfinder64_base::loc_t ibootpatchfinder64_iOS9::find_malloc(){
    UNCACHELOC;
    
    try {
        loc_t res = ibootpatchfinder64_iOS7::find_malloc();
        RETCACHELOC(res);
    } catch (...) {
        //
    }
    
    loc_t handler_str_loc = findstr("setenv", true);
    debug("handler_str_loc=0x%016llx\n",handler_str_loc);

    loc_t tableref = memmem(&handler_str_loc, sizeof(handler_str_loc));
    debug("tableref=0x%016llx\n",tableref);
    
    loc_t cmd_setenv = _vmem->deref(tableref+8);
    debug("cmd_setenv=0x%016llx\n",cmd_setenv);
    
    auto iter = _vmem->getIter(cmd_setenv);
    
    loc_t do_setenv = cmd_setenv;

    if (iter() != insn::stp){
        while (++iter != insn::b)
            ;
        do_setenv = iter().imm();
    }
    
    debug("do_setenv=0x%016llx\n",do_setenv);
    loc_t funcend2 = 0;
    while (++iter != insn::ret)
        ;
    while (++iter != insn::ret)
        ;
    funcend2 = iter;

    iter = do_setenv;
    
    while (iter < funcend2) {
        while (++iter != insn::bl)
            ;
        loc_t ref_malloc = iter();
        uint64_t x0 = find_register_value(iter, 0);
        if (x0 == 0x200){
            debug("ref_malloc=0x%016llx",ref_malloc);
            RETCACHELOC(iter().imm());
        }
    }
    
    reterror("Failed to find malloc function");
}

std::vector<patch> ibootpatchfinder64_iOS9::get_sigcheck_img4_patch(){
    std::vector<patch> patches;

    loc_t img4str = findstr("IMG4", true);
    debug("img4str=0x%016llx\n",img4str);

    loc_t img4strref = find_literal_ref(img4str);
    debug("img4strref=0x%016llx\n",img4strref);

    loc_t f1top = find_bof(img4strref);
    debug("f1top=0x%016llx\n",f1top);

    loc_t f1topref = find_call_ref(f1top,1);
    debug("f1topref=0x%016llx\n",f1topref);

    loc_t f2top = find_bof(f1topref);
    debug("f2top=0x%016llx\n",f2top);

    vmem iter = _vmem->getIter(f2top);

    loc_t val_x2 = 0;
    loc_t val_x3 = 0;

    while (true) {
        if (++iter == insn::adr) {
            if (iter().rd() == 2) {
                val_x2 = iter().imm();
            }else if (iter().rd() == 3) {
                val_x3 = iter().imm();
            }
        } else if (iter() == insn::adrp){
            if (iter().rd() == 2) {
                val_x2 = iter().imm();
            }else if (iter().rd() == 3) {
                val_x3 = iter().imm();
            }
        } else if (iter() == insn::add){
            if (iter().rd() == 2) {
                val_x2 += iter().imm();
            }else if (iter().rd() == 3) {
                val_x3 += iter().imm();
            }
        } else if (iter() == insn::bl){
            if (val_x2 && val_x3) {
                /*
                    add x3, sp, #0xd8
                    is kinda cheating, but well, whatever
                 */
                break;
            }else{
                val_x2 = 0;
                val_x3 = 0;
            }
        }
    }
    
    loc_t callback = val_x2;
    debug("callback=0x%016llx\n",callback);

    iter = callback;
    
    while (++iter != insn::ret);
    
    loc_t ret = iter;
    debug("ret=0x%016llx\n",ret);
    
    //tested with iBoot-1940.1.75 and iBoot-2696
    while (--iter == insn::ldp); // a few ldp
    assure(iter() == insn::sub); //one sub
    assure((--iter).supertype() == insn::sut_branch_imm); //one cbnz or bne
    loc_t branch = iter;
    debug("branch=0x%016llx\n",branch);

    pushINSN(insn::new_immediate_movz(branch, 0, 0, 0));
    
    return patches;
}

patchfinder64::loc_t ibootpatchfinder64_iOS9::find_iBoot_logstr(uint64_t loghex, int skip, uint64_t shortdec){
    vmem iter = _vmem->getIter();
    uint64_t longval = 0;
    uint64_t shortval = 0;
    uint8_t rd = 9; //usually 9
    
    while (true) {
        while (++iter != insn::movz);
        longval = iter().imm();
        rd = iter().rd();

        vmem iter2 = _vmem->getIter(iter);

        {
            vmem prevIter{iter,iter.pc()-4};
            if (prevIter() == insn::movz && prevIter().rd() == 8) {
                shortval = prevIter().imm();
            }
        }
        while (++iter2 == insn::movk && iter2().rd() == rd){

            uint64_t curval =  iter2().imm();
            
            longval += curval;
        }
        if (longval == loghex && (shortdec == shortval || shortdec == 0)){
            if (skip-- == 0) return iter2;
        }
    }
    
    return 0;
}

std::vector<patch> ibootpatchfinder64_iOS9::get_ra1nra1n_patch(){
    UNCACHEPATCHES;

    addPatches(ibootpatchfinder64_iOS7::get_ra1nra1n_patch());
    
    /*
        disable dc zva in trampoline (i.e. don't clear iBoot)
     */
    loc_t findloc = memmem("\x12\x00\x80\xd2", 4);
    debug("findloc=0x%016llx",findloc);

    auto iter = _vmem->getIter(findloc);
    int dcinsns = 0;
    while (--iter != insn::nop) {
        uint32_t opcpde = iter().opcode();
        if (opcpde == 0xD50B7420 /*dc zva x0*/) {
            pushINSN(insn::new_general_nop(iter));
            dcinsns++;
        }
    }
    retassure(dcinsns, "Failed to find DC instructions");
    
    RETCACHEPATCHES;
}
