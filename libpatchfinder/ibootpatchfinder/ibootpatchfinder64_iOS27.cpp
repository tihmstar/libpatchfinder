//
//  ibootpatchfinder64_iOS27.cpp
//  libpatchfinder
//
//  Created by erd on 16.09.26.
//
#include <libgeneral/macros.h>

#include "ibootpatchfinder64_iOS27.hpp"
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

#define mBOOT_BASE_OFFSET 0x380


ibootpatchfinder64_iOS27::ibootpatchfinder64_iOS27(const char *filename)
    : ibootpatchfinder64_iOS26(filename)
{
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[mBOOT_BASE_OFFSET];
    safeDelete(_vmem);
    _vmem = new vmem({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    debug("mBoot base at=0x%016llx\n", _base);
}

ibootpatchfinder64_iOS27::ibootpatchfinder64_iOS27(const void *buffer, size_t bufSize, bool takeOwnership)
    : ibootpatchfinder64_iOS26(buffer,bufSize,takeOwnership)
{
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[mBOOT_BASE_OFFSET];
    safeDelete(_vmem);
    _vmem = new vmem({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    debug("mBoot base at=0x%016llx\n", _base);
}

std::vector<patch> ibootpatchfinder64_iOS27::get_force_septype_local_patch(){
    UNCACHEPATCHES;
    
    loc_t filesizestr = findstr("filesize", true);
    debug("filesizestr=0x%016llx",filesizestr);
    
    loc_t env_get_uint_x3_arg = 0;
    loc_t env_get_uint = 0;

    {
        /*
            AppleTV11,1 iOS 26.6
         */
        loc_t filesizeref = -1;
        while (!env_get_uint){
            filesizeref = find_literal_ref(filesizestr, 0, filesizeref+1);
            assure(filesizeref);
            debug("filesizeref=0x%016llx",filesizeref);
            auto iter = _vmem->getIter(filesizeref);
            while (++iter != insn::bl)
                ;
            bool is_finyfunc = false;
            auto iter2 = _vmem->getIter(iter().imm());
            for (int i=0; i<5; i++) {
                if (++iter2 ==insn::ret) {
                    is_finyfunc = true;
                    break;
                }
            }
            if (!is_finyfunc) {
                if (find_register_value(iter, 1) == 0) {
                    /*
                        HomePod mini has no firebloom
                     */
                    env_get_uint = iter().imm();
                    debug("env_get_uint=0x%016llx",env_get_uint);
                    break;
                }
                /*
                    AppleTV11,1 iOS 26.0. No outlining
                 */
                env_get_uint_x3_arg = find_register_value(iter, 3);
            }else{
                env_get_uint_x3_arg = find_register_value(iter2, 3, iter().imm());
            }
            if (!env_get_uint_x3_arg) continue;
            debug("env_get_uint_x3_arg=0x%016llx",env_get_uint_x3_arg);
            if (is_finyfunc) {
                while (++iter != insn::bl)
                    ;
            }
            if (find_register_value(iter, 4) == 0) {
                env_get_uint = iter().imm();
                debug("env_get_uint=0x%016llx",env_get_uint);
            }
        }
        
    }
    
    loc_t sepiref = -4;
    while ((sepiref = find_literal_ref('sepi',0,sepiref+4))) {
        debug("sepi=0x%016llx",sepiref);
        vmem iter = _vmem->getIter(sepiref);
        for (int i=0; i<4; i++) {
            if (++iter == insn::bl) goto pass_filter1;
        }
        continue;
    pass_filter1:
        uint64_t x1 = find_register_value(iter, 1, iter.pc()-0x20);
        if (x1 != 'sepi') {
            /*
                A12 firebloom ._.
             */
            uint64_t x4 = find_register_value(iter, 4, iter.pc()-0x20);
            if (x4 != 'sepi') {
                continue;
            }
        }
        
        loc_t bof = find_bof(iter);
        debug("bof=0x%016llx",bof);

        vmem iter2 = _vmem->getIter(bof);
    is_correct_func:
        bool fs_load_file_func_is_proxy = false;
        loc_t block_begin = 0;
        loc_t bref = 0;
        try {
            /*
                AppleTV11,1 iOS 26.6
             */
            //now find fs_load_file
            while (++iter2 != insn::movz || iter2().imm() != -1){
                assure(iter2() != insn::ret);
            }
            loc_t errloc = iter2;
            debug("errloc=0x%016llx",errloc);
            
            while ((--iter2).supertype() != insn::sut_branch_imm)
                ;
            ++iter2;
            loc_t errblock = iter2;
            debug("errblock=0x%016llx",errblock);
            
            bref = find_branch_ref(errblock, -0x30);
            debug("bref=0x%016llx",bref);
            block_begin = bref;
            iter2 = bref;
            retassure(--iter2 == insn::bl, "Failed to find fs_load_file");
            {
                //check for "big block"
                auto iter3 = _vmem->getIter(bref);
                while (true) {
                    if (--iter3 == insn::bl) continue;
                    if (iter3().supertype() != insn::sut_branch_imm) continue;
                    ++iter3;
                    block_begin = iter3;
                    break;
                }
            }

            if (bref-block_begin > 10*4){
                debug("fs_load_file is a big block, begin=0x%016llx",block_begin);
            }else{
                //check for proxy
                auto iter3 = _vmem->getIter(iter2().imm());
                for (int i=0; i<15; i++) {
                    if (++iter3 == insn::b) break;
                }
                if (iter3() == insn::b){
                    for (int i=0; i<15; i++) {
                        if (--iter3 == insn::add && (iter3().rd() == 2 || iter3().rd() == 5) && iter3().rn() == 31) {
                            debug("fs_load_file is a proxy!");
                            fs_load_file_func_is_proxy = true;
                            goto found_fs_load_file;
                        }
                        if (iter3().supertype() == insn::sut_branch_imm) break;
                    }
                }
            }
        } catch (...) {
            continue;
        }
    found_fs_load_file:
        
        {
            loc_t nbof = find_bof(iter2);
            retassure(nbof == bof, "Failed to find fs_load_file. Curloc is out of function");
        }
        
        loc_t fs_load_file = iter2;
        debug("fs_load_file=0x%016llx",fs_load_file);
        
        loc_t ploc = 0;
        if (fs_load_file_func_is_proxy) {
            debug("proxyfunc workaround");
            /*
                A12 firebloom!
                iPhone11,2 iOS 18.7.9
             */
            loc_t shellcode = findnops(10);
            pushINSN(insn::new_immediate_b(iter2, shellcode));
            ploc = shellcode;
            pushINSN(insn::new_general_adr(ploc+4*0, filesizestr, 1));
            pushINSN(insn::new_immediate_add(ploc+4*1, 9/*sizeof("filesize")*/, 1, 2));
            pushINSN(insn::new_literal_ldr(ploc+4*2, ploc+4*7, 3));
            ploc += 4*4;
            pushINSN(insn::new_immediate_b(ploc+4*4,(iter2+1)));
            patches.push_back({ploc+4*5,&env_get_uint_x3_arg,sizeof(env_get_uint_x3_arg)});
            iter2 = iter2().imm();
        } else if (bref-block_begin > 10*4){
            ploc = block_begin;
            {
                iter = block_begin;
                while (++iter != insn::ldp || iter().rt() != 0){
                    retassure(iter() != insn::pacibsp, "reached EOF");
                }
                loc_t ldrvalpos = iter;
                debug("ldrvalpos=0x%016llx",ldrvalpos);
            }
            pushINSN(insn::new_general_adr(ploc+4*0, filesizestr, 1));
            pushINSN(insn::new_immediate_add(ploc+4*1, 9/*sizeof("filesize")*/, 1, 2));
            pushINSN(insn::new_general_adrp(ploc+4*2, env_get_uint_x3_arg&~0xFFF, 3));
            pushINSN(insn::new_immediate_add(ploc+4*3, env_get_uint_x3_arg&0xFFF, 3, 3));
            pushINSN(insn::new_immediate_bl(ploc+4*4, env_get_uint));
            pushINSN(insn::new_immediate_str_unsigned(ploc+4*5, iter().imm(), iter().rn(), 0));
            iter = ploc+4*6;
            while (iter.pc() != bref) {
                pushINSN(insn::new_general_nop(iter)); ++iter;
            }
            break;
        } else {
            /*
                HomePod Mini iOS 27.0
             */
            for (int i=0; i<5; i++) {
                if (--iter2 == insn::add && iter2().rn() == 31) goto found;
            }
            reterror("failed to find stack str offset");
        found:
            ploc = iter2;
        }
        debug("ploc=0x%016llx",ploc);
        pushINSN(insn::new_general_adr(ploc+4*0, filesizestr, 0));
        pushINSN(insn::new_immediate_bl(ploc+4*1, env_get_uint));
        pushINSN(insn::new_immediate_str_unsigned(ploc+4*2, iter2().imm(), iter2().rn(), 0));
        pushINSN(insn::new_immediate_movz(ploc+4*3, 0, 0, 0));

        addPatches(get_cmd_handler_patch("rsepfirmware", bof));
        break;
    }

    retassure(patches.size(), "Failed to find patches");
    RETCACHEPATCHES;
}
