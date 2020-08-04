//
//  ibootpatchfinder64_iOS14.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>
#include "ibootpatchfinder64_iOS14.hpp"

using namespace std;
using namespace tihmstar::offsetfinder64;
using namespace tihmstar::libinsn;

#define iBOOT_BASE_OFFSET 0x300

ibootpatchfinder64_iOS14::ibootpatchfinder64_iOS14(const char *filename)
    : ibootpatchfinder64_base(filename)
{
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[iBOOT_BASE_OFFSET];
    _vmem = new vmem({{_buf,_bufSize,_base, vsegment::vmprot::kVMPROTREAD | vsegment::vmprot::kVMPROTWRITE | vsegment::vmprot::kVMPROTEXEC}});
    debug("iBoot base at=0x%016llx\n", _base);
}

ibootpatchfinder64_iOS14::ibootpatchfinder64_iOS14(const void *buffer, size_t bufSize, bool takeOwnership)
    : ibootpatchfinder64_base(buffer,bufSize,takeOwnership)
{
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[iBOOT_BASE_OFFSET];
    _vmem = new vmem({{_buf,_bufSize,_base, vsegment::vmprot::kVMPROTREAD | vsegment::vmprot::kVMPROTWRITE | vsegment::vmprot::kVMPROTEXEC}});
    debug("iBoot base at=0x%016llx\n", _base);
}


std::vector<patch> ibootpatchfinder64_iOS14::get_sigcheck_patch(){
    std::vector<patch> patches;
    loc_t findpos = 0;
    vmem iter(*_vmem);
    
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
    debug("findpos=%p",findpos);

    
    while (++iter != insn::ret);
    
    loc_t funcend = iter;
    debug("funcend=%p",funcend);

    {
        insn pins = insn::new_immediate_movz(funcend, 0, 0, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }

    {
        insn pins = insn::new_general_ret(funcend+4);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }

    
    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS14::get_change_reboot_to_fsboot_patch(){
    std::vector<patch> patches;

    loc_t rebootstr = findstr("reboot", true);
    debug("rebootstr=%p",rebootstr);

    loc_t rebootrefstr = _vmem->memmem(&rebootstr,sizeof(loc_t));
    debug("rebootrefstr=%p",rebootrefstr);
    
    loc_t rebootrefptr = rebootrefstr+8;
    debug("rebootrefptr=%p",rebootrefptr);
    
    loc_t fsbootstr = findstr("fsboot", true);
    debug("fsbootstr=%p",fsbootstr);

    patches.push_back({rebootrefstr,&fsbootstr,sizeof(loc_t)}); //rewrite pointer to point to fsboot

    loc_t fsbootrefstr = _vmem->memmem(&fsbootstr,sizeof(loc_t));
    debug("fsbootrefstr=%p",fsbootrefstr);
    
    loc_t fsbootfunction = _vmem->deref(fsbootrefstr+8);
    debug("fsbootfunction=%p",fsbootfunction);
    patches.push_back({rebootrefstr+8,&fsbootfunction,sizeof(loc_t)}); //rewrite pointer to point to fsboot

    return patches;
}

loc_t ibootpatchfinder64_iOS14::find_iBoot_logstr(uint64_t loghex, int skip, uint64_t shortdec){
    vmem iter(*_vmem);
    uint64_t longval = 0;
    uint64_t shortval = 0;

    while (true) {
        while (++iter != insn::movz || iter().rd() != 9);
        longval = iter().imm();

        {
            vmem prevIter{iter,iter.pc()-4};
            if (prevIter() == insn::movz && prevIter().rd() == 8) {
                shortval = prevIter().imm();
            }
        }
        while (++iter == insn::movk && iter().rd() == 9){

            uint64_t curval =  iter().imm();
            
            longval += curval;
        }
        if (longval == loghex && (shortdec == shortval || shortdec == 0)){
            if (skip-- == 0) return iter;
        }
    }
    
    return 0;
}
