//
//  kernelpatchfinder64_iOS9.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 25.02.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//
#include <libgeneral/macros.h>

#include "kernelpatchfinder64_iOS9.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"


using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;


std::vector<patch> kernelpatchfinder64_iOS9::get_mount_patch(){
    UNCACHEPATCHES;
    
    loc_t mount = find_function_for_syscall(167);
    mount |= 0xffffffUL << (6*8);
    debug("mount=0x%016llx\n",mount);
    
    vmem iter = _vmem->getIter(mount);
    
    while (++iter != insn::bl);
    
    loc_t mount_internal = iter().imm();
    debug("mount_internal=0x%016llx\n",mount_internal);

    
    iter = mount_internal;
    
    while (++iter != insn::orr || iter().imm() != 0x10000);
    
    loc_t pos = iter;
    debug("pos=0x%016llx\n",pos);
    
    try {
        loc_t ref = find_branch_ref(pos, -0x100);
        debug("ref=0x%016llx\n",ref);
        iter = ref-4;
    } catch (...) {
        debug("Failed to find ref, assuming old style layout");
        iter = pos;
    }
    
    //patch MNT_RDONLY check
    while (++iter != insn::tbz && iter() != insn::tbnz);
    assure(iter().special() == 0);
    uint8_t flagsreg = iter().rt();
    if (iter() == insn::tbz) {
        pushINSN(insn::new_general_nop(iter));
    }else{
        pushINSN(insn::new_immediate_b(iter, iter().imm()));
    }
    
    //patch MNT_UNION check
    iter = pos;
    while (iter.pc() > mount_internal) {
        while (--iter != insn::tbz && iter() != insn::tbnz);
        if (iter().special() == 0x5 && iter().rt() == flagsreg) {
            debug("detected MNT_UNION check! patching...");
            if (iter() == insn::tbz) {
                pushINSN(insn::new_immediate_b(iter, iter().imm()));
            }else{
                pushINSN(insn::new_general_nop(iter));
            }
            break;
        }
    }
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS9::get_harcode_boot_manifest_patch(const void *hash, size_t hashSize){
    UNCACHEPATCHES;
    size_t realhashSize = hashSize;
    while (realhashSize & 3) realhashSize++;
    
    loc_t entrypoint = find_entry();
    debug("entry=0x%16llx",entrypoint);
    
    vmem iter = _vmem->getIter(entrypoint);
    
    loc_t hookpos = entrypoint;
    if (iter() == insn::b) {
        hookpos = iter().imm();
    }
    debug("hookpos=0x%16llx",hookpos);
    
    offset_t cmdlineOffset = find_boot_args_commandline_offset();
    offset_t deviceTreePOffset = (cmdlineOffset - sizeof(uint32_t) - sizeof(uint64_t)) & ~3;
    offset_t virtBaseOffset = 0x08;
    offset_t physBaseOffset = 0x10;
    
    debug("deviceTreePOffset=0x%016llx",deviceTreePOffset);
    
    uint32_t shellcode_insn_cnt = 25; //commitment
    loc_t shellcode = findnops(shellcode_insn_cnt + realhashSize/4);
    debug("shellcode=0x%016llx",shellcode);
    uint32_t loopdst = 9;
    uint32_t loop2dst = 19;
#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, deviceTreePOffset, 0, 5));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, virtBaseOffset, 0, 6));
    pushINSN(insn::new_register_add(cPC, 0, 5, 6, 5, true));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, physBaseOffset, 0, 6));
    pushINSN(insn::new_register_add(cPC, 0, 5, 6, 5, false));
    //load "boot-man" 0x6e61 6d2d 746f 6f62
    pushINSN(insn::new_immediate_movz(cPC, 0x6f62, 6, 0));
    pushINSN(insn::new_immediate_movk(cPC, 0x746f, 6, 16));
    
    //    pushINSN(insn::new_immediate_movk(cPC, 0x6d2d, 6, 32));
    //    pushINSN(insn::new_immediate_movk(cPC, 0x6e61, 6, 48));
    pushINSN(insn::new_immediate_movz(cPC, 0x6d2d, 4, 0));
    pushINSN(insn::new_immediate_movk(cPC, 0x6e61, 4, 16));
    
    assure(loopdst == insnNum);
    
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0, 5, 7, true));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 4, 5, 8, true));
    pushINSN(insn::new_immediate_add(cPC, 4, 5, 5));
    pushINSN(insn::new_register_cmp(cPC, 0, 6, 7, -1));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+loopdst*4, insn::NE));
    pushINSN(insn::new_register_cmp(cPC, 0, 4, 8, -1));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+loopdst*4, insn::NE));
    pushINSN(insn::new_immediate_add(cPC, 32, 5, 5));
    
    pushINSN(insn::new_general_adr(cPC, shellcode+shellcode_insn_cnt*4, 6));
    pushINSN(insn::new_immediate_movz(cPC, 0x30, 7, 0));
    assure(loop2dst == insnNum);
    pushINSN(insn::new_immediate_subs(cPC, 4, 7, 7));
    pushINSN(insn::new_register_ldr(cPC, 6, 7, 8, true));
    pushINSN(insn::new_register_str(cPC, 5, 7, 8, true));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+loop2dst*4, libinsn::arm64::insn::NE));
    {
        uint32_t opcode = (uint32_t)deref(hookpos);
        patches.push_back({cPC,&opcode,sizeof(opcode)});
    }
    pushINSN(insn::new_immediate_b(cPC, hookpos+4));
    assure(insnNum == shellcode_insn_cnt);
    patches.push_back({cPC,hash,hashSize});
    pushINSN(insn::new_immediate_b(hookpos, shellcode));
#undef cPC
    
    RETCACHEPATCHES;
}
