//
//  offsetfinder64.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include "patchfinder64.hpp"

#include <liboffsetfinder64/libgeneral/macros.h>
#include "all_liboffsetfinder.hpp"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace offsetfinder64;

#pragma mark liboffsetfinder

#define HAS_BITS(a,b) (((a) & (b)) == (b))

#pragma mark constructor/destructor

patchfinder64::patchfinder64(bool freeBuf) :
    _freeBuf(freeBuf),
    _buf(NULL),
    _bufSize(0),
    _entrypoint(NULL),
    _base(NULL)
{
    //
}

patchfinder64::~patchfinder64(){
    if (_vmem) delete _vmem;
    if (_freeBuf) safeFreeConst(_buf);
}


#pragma mark patchfinder

loc_t patchfinder64::findstr(std::string str, bool hasNullTerminator){
    return _vmem->memmem(str.c_str(), str.size()+(hasNullTerminator));
}

loc_t patchfinder64::find_bof(loc_t pos){
    vsegment functop = _vmem->seg(pos);


    //find stp x29, x30, [sp, ...]
    while (functop() != insn::stp || functop().other() != 30 || functop().rn() != 31) --functop;

    try {
        //if there are more stp before, then this wasn't functop
        while (--functop == insn::stp);
        ++functop;
    } catch (...) {
        //
    }
    
    try {
        //there might be a sub before
        if (--functop != insn::sub || functop().rd() != 31 || functop().rn() != 31) ++functop;
    } catch (...) {
        //
    }
    
    return functop;
}


uint64_t patchfinder64::find_register_value(loc_t where, int reg, loc_t startAddr){
    vsegment functop = _vmem->seg(where);
    
    if (!startAddr) {
        functop = find_bof(where);
    }else{
        functop = startAddr;
    }
    
    uint64_t value[32] = {0};
    
    for (;(loc_t)functop.pc() < where;++functop) {
        
        switch (functop().type()) {
            case offsetfinder64::insn::adrp:
                value[functop().rd()] = functop().imm();
                //                printf("%p: ADRP X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
                break;
            case offsetfinder64::insn::add:
                value[functop().rd()] = value[functop().rn()] + functop().imm();
                //                printf("%p: ADD X%d, X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.rn(), (uint64_t)functop.imm());
                break;
            case offsetfinder64::insn::adr:
                value[functop().rd()] = functop().imm();
                //                printf("%p: ADR X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
                break;
            case offsetfinder64::insn::ldr:
                //                printf("%p: LDR X%d, [X%d, 0x%llx]\n", (void*)functop.pc(), functop.rt(), functop.rn(), (uint64_t)functop.imm());
                value[functop().rt()] = value[functop().rn()] + functop().imm(); // XXX address, not actual value
                break;
            default:
                break;
        }
    }
    return value[reg];
}

loc_t patchfinder64::find_literal_ref(loc_t pos, int ignoreTimes){
    vmem adrp(*_vmem);
    
    uint8_t rd = 0xff;
    uint64_t imm = 0;
    
    try {
        for (;;++adrp){
            if (adrp() == insn::adr) {
                if (adrp().imm() == (uint64_t)pos){
                    if (ignoreTimes) {
                        ignoreTimes--;
                        rd = 0xff;
                        imm = 0;
                        continue;
                    }
                    return (loc_t)adrp.pc();
                }
            }else if (adrp() == insn::adrp) {
                rd = adrp().rd();
                imm = adrp().imm();
            }else if (adrp() == insn::add && rd == adrp().rd()){
                if (imm + adrp().imm() == (int64_t)pos){
                    if (ignoreTimes) {
                        ignoreTimes--;
                        rd = 0xff;
                        imm = 0;
                        continue;
                    }
                    return (loc_t)adrp.pc();
                }
            }
        }
    } catch (tihmstar::out_of_range &e) {
        return 0;
    }
    return 0;
}

loc_t patchfinder64::find_branch_ref(loc_t pos, int ignoreTimes){
    vmem bl(*_vmem);
    try {
        if (bl() == insn::bl) goto isBL;
        while (true){
            while (++bl != insn::bl);
        isBL:
            if (bl().imm() == (uint64_t)pos && --ignoreTimes <0)
                return bl;
        }
    } catch (tihmstar::out_of_range &e) {
        return 0;
    }
    return 0;
}



//
