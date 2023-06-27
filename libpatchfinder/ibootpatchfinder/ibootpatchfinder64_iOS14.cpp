//
//  ibootpatchfinder64_iOS14.cpp
//  libpatchfinder
//
//  Created by tihmstar on 28.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>
#include "ibootpatchfinder64_iOS14.hpp"
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

#define iBOOT_BASE_OFFSET 0x300
#define DEFAULT_BOOTARGS_STR_14_5 "rd=md0"
#define CERT_STR "Apple Inc.1"

ibootpatchfinder64_iOS14::ibootpatchfinder64_iOS14(const char *filename)
    : ibootpatchfinder64_iOS13(filename)
{
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[iBOOT_BASE_OFFSET];
    _vmem = new vmem({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    debug("iBoot base at=0x%016llx\n", _base);
}

ibootpatchfinder64_iOS14::ibootpatchfinder64_iOS14(const void *buffer, size_t bufSize, bool takeOwnership)
    : ibootpatchfinder64_iOS13(buffer,bufSize,takeOwnership)
{
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[iBOOT_BASE_OFFSET];
    _vmem = new vmem({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    debug("iBoot base at=0x%016llx\n", _base);
}


std::vector<patch> ibootpatchfinder64_iOS14::get_sigcheck_img4_patch(){
    std::vector<patch> patches;
    loc_t findpos = 0;
    vmem iter = _vmem->getIter();
    
    /* We are looking for this:
     0x00000001800312dc         cmp        w8, #0x1
     0x00000001800312e0         b.ne       loc_1800313d8

     0x00000001800312e4         ldr        x8, [x19, #0x10]
     0x00000001800312e8         cmp        x8, #0x4
     0x00000001800312ec         b.eq       loc_180031388

     0x00000001800312f0         cmp        x8, #0x2
     0x00000001800312f4         b.eq       loc_180031344

     0x00000001800312f8         cmp        x8, #0x1
     0x00000001800312fc         b.ne       loc_180031a88
     */
    
    while (!findpos) {
        if (++iter != insn::cmp) continue;
        
        if (iter().imm() != 1) continue;
        
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        if (++iter != insn::ldr || iter().imm() != 0x10) continue;

        if (++iter != insn::cmp || iter().imm() != 4) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        if (++iter != insn::cmp || iter().imm() != 2) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        if (++iter != insn::cmp || iter().imm() != 1) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        
        findpos = iter;
    }
    debug("findpos=0x%016llx",findpos);

    
    while (++iter != insn::ret);
    
    loc_t funcend = iter;
    debug("funcend=0x%016llx",funcend);
    
    while ((--iter != insn::mov || iter().rd() != 0) && iter().supertype() != insn::sut_branch_imm)
        ;
    loc_t overwrite = iter;
    debug("overwrite=0x%016llx",overwrite);
    /*
        looking for either:
     000000087000f7e0 b.ne loc_87000f808
     000000087000f7e4 mov x0, x20
     whatever comes first (when going up from ret)
     */

    pushINSN(insn::new_immediate_movz(overwrite, 0, 0, 0));

    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS14::get_change_reboot_to_fsboot_patch(){
    std::vector<patch> patches;

    loc_t rebootstr = findstr("reboot", true);
    debug("rebootstr=0x%016llx",rebootstr);

    loc_t rebootrefstr = _vmem->memmem(&rebootstr,sizeof(loc_t));
    debug("rebootrefstr=0x%016llx",rebootrefstr);
    
    loc_t rebootrefptr = rebootrefstr+8;
    debug("rebootrefptr=0x%016llx",rebootrefptr);
    
    loc_t fsbootstr = findstr("fsboot", true);
    debug("fsbootstr=0x%016llx",fsbootstr);

    patches.push_back({rebootrefstr,&fsbootstr,sizeof(loc_t)}); //rewrite pointer to point to fsboot

    loc_t fsbootrefstr = _vmem->memmem(&fsbootstr,sizeof(loc_t));
    debug("fsbootrefstr=0x%016llx",fsbootrefstr);
    
    loc_t fsbootfunction = _vmem->deref(fsbootrefstr+8);
    debug("fsbootfunction=0x%016llx",fsbootfunction);
    patches.push_back({rebootrefstr+8,&fsbootfunction,sizeof(loc_t)}); //rewrite pointer to point to fsboot

    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS14::get_boot_arg_patch(const char *bootargs){
    try{
        return ibootpatchfinder64_base::get_boot_arg_patch(bootargs);
    }catch(...){
        debug("Failed to add old-style bootargs, trying with iOS 14.5 method\n");
    }
    std::vector<patch> patches;
    loc_t default_boot_args_str_loc = 0;
    loc_t default_boot_args_xref = 0;

    default_boot_args_str_loc = _vmem->memstr(DEFAULT_BOOTARGS_STR_14_5);
    debug("default_boot_args_str_loc=0x%016llx\n",default_boot_args_str_loc);
   
    default_boot_args_xref = find_literal_ref(default_boot_args_str_loc);
    debug("default_boot_args_xref=0x%016llx\n",default_boot_args_xref);

    vmem iter = _vmem->getIter(default_boot_args_xref);
    
    for (int i=0; i<10; i++){
        if ((--iter).supertype() == insn::sut_branch_imm) break;
    }
    
    if (iter().supertype() != insn::sut_branch_imm) {
        reterror("Case unimplemented!");
    }else{
        //always got to the "no bootarg"-case
        pushINSN(insn::new_immediate_b(iter.pc(), iter().imm()));

        default_boot_args_xref = (loc_t)iter().imm();//this is now the "always"-case
        debug("new default_boot_args_xref=0x%016llx\n",default_boot_args_xref);
    }
    
    {
        loc_t cert_str_loc = 0;
        debug("Relocating boot-args string...\n");

        /* Find the "Reliance on this cert..." string. */
        size_t args_len = strlen(bootargs)+1;
        size_t nopcnt = args_len/4;
        if (args_len & 3) nopcnt++;

        try {
            cert_str_loc = findstr("setpicture optmask", false);
        } catch (...) {
            cert_str_loc = findstr("/System/Library/Caches/com.apple.kernelcaches/kernelcache", true);
        }
        if (!cert_str_loc) cert_str_loc = findnops(nopcnt,true,0x00000000);
        retassure(cert_str_loc, "Unable to find new bootargs location string!\n");

        debug("found new bootargs location at 0x%016llx\n", cert_str_loc);

        /* Point the boot-args xref to the "Reliance on this cert..." string. */
        debug("Pointing default boot-args xref to 0x%016llx...\n", cert_str_loc);
        default_boot_args_str_loc = cert_str_loc;

        iter = default_boot_args_xref;

        if (iter() != insn::adr) {
            warning("Fallback method activated!");
            for (int i = 0; i<5; i++){
                loc_t empty_args_addr = 0;
                while (++iter != insn::adr && iter() != insn::adrp) retassure(iter() != insn::ret, "Reached end of function");
                empty_args_addr = iter().imm();
                if (iter() == insn::adrp){
                    retassure(++iter == insn::add || iter() == insn::nop, "Invalid addr ref");
                    empty_args_addr += iter().imm();
                }
                try{
                    if ((char*)_vmem->memoryForLoc(empty_args_addr) == 0 || strncmp((char*)_vmem->memoryForLoc(empty_args_addr), "-v", 2) == 0  || strncmp((char*)_vmem->memoryForLoc(empty_args_addr), "%s", 2) == 0){
                        if (iter - 1 == insn::adrp) --iter;
                        goto found_default_args;
                    }
                }catch (...){
                    //
                }
            }
            reterror("Failed to find default boot args");
        found_default_args:;
        }
        if (iter() == insn::adr){
            pushINSN(insn::new_general_adr(iter.pc(), (int64_t)default_boot_args_str_loc, iter().rd()));
        }else if (iter() == insn::adrp){
            pushINSN(insn::new_general_adrp(iter.pc(), ((int64_t)default_boot_args_str_loc) & ~0xfff, iter().rd()));
            pushINSN(insn::new_immediate_add(iter.pc()+4, ((int64_t)default_boot_args_str_loc) & 0xfff, iter().rd(),iter().rd()));
        }else{
            reterror("Bad reference insn");
        }
    }

    debug("Applying custom boot-args \"%s\"\n", bootargs);
    patches.push_back({default_boot_args_str_loc, bootargs, strlen(bootargs)+1});

    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS14::get_force_septype_local_patch(){
    UNCACHEPATCHES;
        
    loc_t loadaddrstr = findstr("loadaddr", true);
    debug("loadaddrstr=0x%016llx",loadaddrstr);

    loc_t filesizestr = findstr("filesize", true);
    debug("filesizestr=0x%016llx",filesizestr);

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
        if (x1 != 'sepi') continue;
        
        loc_t bof = find_bof(iter);
        debug("bof=0x%016llx",bof);
        
        loc_t loadaddr_ref = find_literal_ref(loadaddrstr,0,bof);
        debug("loadaddr_ref=0x%016llx",loadaddr_ref);
        if (loadaddr_ref > iter) continue;
        
        vmem iter2 = _vmem->getIter(loadaddr_ref);
        while (++iter2 != insn::bl)
            ;
        
        loc_t call_to_env_get_uint = iter2;
        debug("call_to_env_get_uint=0x%016llx",call_to_env_get_uint);
        
        loc_t env_get_uint = iter2().imm();
        debug("env_get_uint=0x%016llx",env_get_uint);

        loc_t arg0 = find_register_value(iter2, 0, bof);
        debug("arg0=0x%016llx",arg0);
        if (arg0 != loadaddrstr) continue;
        
        while ((++iter2).pc() < iter.pc()) {
            if (iter2().supertype() == insn::sut_branch_imm) {
                goto is_correct_func;
            }
        }
        continue;
    is_correct_func:
        bool fs_load_file_func_is_proxy = false;
        try {
            //now find fs_load_file
            while (true) {
                vmem iter3 = iter2;
                for (int i=0; i<5; i++) {
                    if (--iter3 == insn::add && iter3().rd() == 2 && iter3().rn() == 31) {
                        goto found_fs_load_file;
                    }
                }
                {   //check for proxy
                    iter3 = iter2().imm();
                    for (int i=0; i<5; i++) {
                        if (++iter3 == insn::b) break;
                    }
                    if (iter3() == insn::b){
                        for (int i=0; i<5; i++) {
                            if (--iter3 == insn::add && iter3().rd() == 2 && iter3().rn() == 31) {
                                debug("fs_load_file is a proxy!");
                                fs_load_file_func_is_proxy = true;
                                goto found_fs_load_file;
                            }
                        }
                    }
                }
                while (++iter2 != insn::bl)
                    ;
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
        if (!fs_load_file_func_is_proxy){
            iter2 -=3;
            ploc = iter2;
        } else {
            debug("proxyfunc workaround");
            loc_t shellcode = findnops(5);
            pushINSN(insn::new_immediate_b(iter2, shellcode));
            ploc = shellcode;
            pushINSN(insn::new_immediate_b(ploc+4*4,(iter2+1)));
            iter2 = iter2().imm();
        }
        debug("ploc=0x%016llx",ploc);
        pushINSN(insn::new_general_adr(ploc+4*0, filesizestr, 0));
        pushINSN(insn::new_immediate_bl(ploc+4*1, env_get_uint));
        pushINSN(insn::new_immediate_str_unsigned(ploc+4*2, iter2().imm(), iter2().rn(), 0));
        pushINSN(insn::new_immediate_movz(ploc+4*3, 0, 0, 0));
        
        addPatches(get_cmd_handler_patch("rsepfirmware", bof));
        break;
    }

    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder64_iOS14::get_skip_set_bpr_patch(){
    UNCACHEPATCHES;
    addPatches(ibootpatchfinder64_iOS13::get_skip_set_bpr_patch());
    
    /*
     Come on, seriously?
     iOS_15.3.1 iphone 7
0x00000001800c7eb0         mov        x8, #0x30
0x00000001800c7eb4         movk       x8, #0x102d, lsl #16
0x00000001800c7eb8         bl         set_bpr
     
     set_bpr:
0x00000001800c8c80         movk       x8, #0x2, lsl #32
0x00000001800c8c84         ldr        w9, [x8]
0x00000001800c8c88         orr        w9, w9, #0x1
0x00000001800c8c8c         str        w9, [x8]
0x00000001800c8c90         ret
     */
    
    std::set<uint64_t> bpr_regs = {0x2102d0030/*t8010*/, 0x2352d0030/*t8015*/, 0x23d2dc030/*t8110*/};
    
    vmem iter = _vmem->getIter();
    try {
        while (true) {
            while (++iter != insn::ldr || iter().subtype() != insn::st_immediate)
                ;
            vmem iter2 = iter;
            uint8_t rt = iter().rt();
            uint8_t rn = iter().rn();

            if (++iter2 != insn::orr || iter2().rd() != rt || iter2().rn() != rt || iter2().imm() != 1) continue;
            if (++iter2 != insn::str || iter2().rt() != rt || iter2().rn() != rn) continue;
            
            loc_t bof = find_bof(iter, true);
            debug("bof=0x%016llx",bof);
            
            uint64_t tgtval = find_register_value(iter, rn, bof);
            debug("tgtval=0x%016llx",tgtval);

            if (bpr_regs.find(tgtval) != bpr_regs.end()) {
                loc_t ppos = iter2-1;
//                debug("patch=0x%016llx",ppos);
                pushINSN(insn::new_general_nop(ppos));
                continue;
            }
            
            if (++iter2 != insn::ret) continue;
            
            loc_t candidate = iter;
            debug("candidate=0x%016llx",candidate);
            
            loc_t cref = -4;
            try {
                while ((cref = find_call_ref(bof,0,cref+4))) {
                    debug("cref=0x%016llx",cref);

                    uint64_t tgt2val = find_register_value(cref, rn, cref-0x10);
                    tgt2val += tgtval;
                    debug("tgt2val=0x%016llx",tgt2val);

                    if (bpr_regs.find(tgt2val) != bpr_regs.end()) {
                        loc_t ppos = cref;
//                        debug("patch=0x%016llx",ppos);
                        pushINSN(insn::new_general_nop(ppos));
                        break;
                    }
                }
            } catch (...) {
                //
            }
        }
    } catch (...) {
        //
    }
    retassure(patches.size(), "Failed to find a single patch");
    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder64_iOS14::get_always_sepfw_booted_patch(){
    UNCACHEPATCHES;

    loc_t str = findstr("sepfw-booted", true);
    debug("str=0x%016llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    --iter;
    
    retassure(iter().supertype() == insn::sut_branch_imm, "not implemented other case");
    
    pushINSN(insn::new_general_nop(iter));
    
    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder64_iOS14::get_tz0_lock_patch(){
    UNCACHEPATCHES;

    vmem iter = _vmem->getIter();
    
    /* iPhone 7 iOS_15.3.1 wtf???
     lock_tz0:
        0x0000000180103284         add        w9, w9, w10
        0x0000000180103288         str        w26, [x8, w9, uxtw]
        0x000000018010328c         ldr        w26, [sp, arg_7C]
        0x0000000180103290         ret
     */

    try {
        while (true) {
            while (++iter != insn::str || iter().subtype() != insn::st_register || iter().rt() < 18 || iter().rt() == 0x1f /*xzr*/)
                ;
            
            vmem iter2 = iter;
            
            for (int i=0; i<5; i++) {
                if (++iter2 == insn::ret) goto good_candidate;
            }
            continue;
            
        good_candidate:
            loc_t cref = 0;
            try {
                if (!(cref = find_call_ref(iter-1))) continue;
            } catch (...) {
                continue;
            }
            loc_t d = iter;
            debug("d=0x%016llx",d);
            
            loc_t bof = find_bof(cref);
            debug("bof=0x%016llx",bof);

            iter2 = cref;
            
            while (++iter2 != insn::ret)
                ;
            
            while (--iter2 != insn::ldp)
                ;
            
            while (--iter2 == insn::ldp)
                ;
            
            ++iter2;
            loc_t eof = iter2;
            debug("eof=0x%016llx",eof);

            pushINSN(insn::new_general_adr(iter, eof, 30));
            
            break;
        }
    } catch (...) {
        //will fail eventually. this is fine
    }
    
    retassure(patches.size(), "Failed to find patches");
    RETCACHEPATCHES;
}
