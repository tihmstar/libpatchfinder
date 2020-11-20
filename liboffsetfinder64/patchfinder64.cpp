//
//  offsetfinder64.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <string.h>

#include <libgeneral/macros.h>

#include "all_liboffsetfinder.hpp"
#include "patchfinder64.hpp"

using namespace std;
using namespace tihmstar;
using namespace offsetfinder64;
using namespace libinsn;

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

const void *patchfinder64::memoryForLoc(loc_t loc){
    return _vmem->memoryForLoc(loc);
}


loc_t patchfinder64::findstr(std::string str, bool hasNullTerminator, loc_t startAddr){
    return _vmem->memmem(str.c_str(), str.size()+(hasNullTerminator), startAddr);
}

loc_t patchfinder64::find_bof(loc_t pos){
    vsegment functop = _vmem->seg(pos);


    //find stp x29, x30, [sp, ...]
    while (functop() != insn::stp || functop().rt2() != 30 || functop().rn() != 31) --functop;

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

    try {
        //there might be a pacibsp
        if (--functop != insn::pacibsp) ++functop;
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
            case insn::adrp:
                value[functop().rd()] = functop().imm();
                //                printf("%p: ADRP X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
                break;
            case insn::add:
                value[functop().rd()] = value[functop().rn()] + functop().imm();
                //                printf("%p: ADD X%d, X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.rn(), (uint64_t)functop.imm());
                break;
            case insn::adr:
                value[functop().rd()] = functop().imm();
                //                printf("%p: ADR X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
                break;
            case insn::ldr:
                //                printf("%p: LDR X%d, [X%d, 0x%llx]\n", (void*)functop.pc(), functop.rt(), functop.rn(), (uint64_t)functop.imm());
                value[functop().rt()] = value[functop().rn()];
                if (functop().subtype() == insn::st_immediate) {
                    value[functop().rt()] += functop().imm(); // XXX address, not actual value
                }
                break;
            case insn::movz:
                value[functop().rd()] = functop().imm();
                break;
            case insn::movk:
                value[functop().rd()] |= functop().imm();
                break;
            case insn::mov:
                value[functop().rd()] = value[functop().rm()];
                break;
            default:
                break;
        }
    }
    return value[reg];
}

loc_t patchfinder64::find_literal_ref(loc_t pos, int ignoreTimes, loc_t startPos){
    vmem adrp(*_vmem, startPos);
    
    try {
        for (;;++adrp){
            if (adrp() == insn::adr) {
                if (adrp().imm() == (uint64_t)pos){
                    if (ignoreTimes) {
                        ignoreTimes--;
                        continue;
                    }
                    return (loc_t)adrp.pc();
                }
            }
            
            if (adrp() == insn::adrp) {
                uint8_t rd = 0xff;
                uint64_t imm = 0;
                rd = adrp().rd();
                imm = adrp().imm();
                
                vmem iter(*_vmem,adrp);

                for (int i=0; i<10; i++) {
                    ++iter;
                    if (iter() == insn::add && rd == iter().rd()){
                        if (imm + iter().imm() == (int64_t)pos){
                            if (ignoreTimes) {
                                ignoreTimes--;
                                break;
                            }
                            return (loc_t)iter.pc();
                        }
                    }else if (iter().supertype() == insn::sut_memory && iter().subtype() == insn::st_immediate && rd == iter().rn()){
                        if (imm + iter().imm() == (int64_t)pos){
                            if (ignoreTimes) {
                                ignoreTimes--;
                                break;
                            }
                            return (loc_t)iter.pc();
                        }
                    }
                }
            }
            
            if (adrp() == insn::movz) {
                uint8_t rd = 0xff;
                uint64_t imm = 0;
                rd = adrp().rd();
                imm = adrp().imm();

                vmem iter(*_vmem,adrp);

                for (int i=0; i<10; i++) {
                    ++iter;
                    if (iter() == insn::movk && rd == iter().rd()){
                        imm |= iter().imm();
                        if (imm == (int64_t)pos){
                            if (ignoreTimes) {
                                ignoreTimes--;
                                break;
                            }
                            return (loc_t)iter.pc();
                        }
                    }else if (iter() == insn::movz && rd == iter().rd()){
                        break;
                    }
                }
            }
        }
    } catch (tihmstar::out_of_range &e) {
        return 0;
    }
    return 0;
}

loc_t patchfinder64::find_call_ref(loc_t pos, int ignoreTimes, loc_t startPos){
    vmem bl(*_vmem, startPos);
    if (bl() == insn::bl) goto isBL;
    while (true){
        while (++bl != insn::bl);
    isBL:
        if (bl().imm() == (uint64_t)pos && --ignoreTimes <0)
            return bl;
    }
    reterror("call reference not found");
}


loc_t patchfinder64::find_branch_ref(loc_t pos, int limit, int ignoreTimes){
    vmem brnch(*_vmem, pos);

    if (limit < 0 ) {
        while (true) {
            while ((--brnch).supertype() != insn::supertype::sut_branch_imm){
                limit +=4;
                retassure(limit < 0, "search limit reached");
            }
            if (brnch().imm() == pos){
                if (ignoreTimes--  <=0)
                    return brnch;
            }
        }
    }else{
        while (true) {
           while ((++brnch).supertype() != insn::supertype::sut_branch_imm){
               limit -=4;
               retassure(limit > 0, "search limit reached");
           }
           if (brnch().imm() == pos){
               if (ignoreTimes--  <=0)
                   return brnch;
           }
        }
    }
    reterror("branchref not found");
}

loc_t patchfinder64::findnops(uint16_t nopCnt, bool useNops){
    uint32_t *needle = NULL;
    cleanup([&]{
        safeFree(needle);
    });
    loc_t pos = 0;
    needle = (uint32_t *)malloc(nopCnt*4);
    
    for (uint16_t i=0; i<nopCnt; i++) {
        needle[i] = *(uint32_t*)"\x1F\x20\x03\xD5";
    }

    
    pos = -4;
nextNops:
    pos = _vmem->memmem(needle, nopCnt*4,pos+4);
    std::pair<loc_t, loc_t> range(pos,pos+4*nopCnt);
    
    for (auto &r : _usedNops) {
        if (r.first > range.first && r.first < range.second) goto nextNops; //used range inside found range
        if (range.first > r.first && range.first < r.second) goto nextNops; //found range inside used range
    }

    if (useNops) {
        _usedNops.push_back(range);
    }
    
    return pos;
}

uint32_t patchfinder64::pageshit_for_pagesize(uint32_t pagesize){
    uint32_t pageshift = 0;
    while (pagesize>>=1) pageshift++;
    return pageshift;
}


uint64_t patchfinder64::pte_vma_to_index(uint32_t pagesize, uint8_t level, uint64_t address){
    switch (pagesize) {
        case 0x1000: //4K
            switch (level) {
                case 0:
                    return BIT_RANGE(address, 39, 47);
                case 1:
                    return BIT_RANGE(address, 30, 38);
                case 2:
                    return BIT_RANGE(address, 21, 29);
                case 3:
                    return BIT_RANGE(address, 12, 20);
                default:
                    reterror("[4K] bad level=%d",level);
            }
            break;
        case 0x4000: //16K
            switch (level) {
                case 0:
                    return BIT_AT(address, 47);
                case 1:
                    return BIT_RANGE(address, 36, 46);
                case 2:
                    return BIT_RANGE(address, 25, 35);
                case 3:
                    return BIT_RANGE(address, 14, 24);
                default:
                    reterror("[16K] bad level=%d",level);
            }
            break;
        case 0x10000: //64K
            switch (level) {
                case 1:
                    return BIT_RANGE(address, 42, 51);
                case 2:
                    return BIT_RANGE(address, 29, 41);
                case 3:
                    return BIT_RANGE(address, 16, 28);
                default:
                    reterror("[64K] bad level=%d",level);
            }
            break;
        default:
            reterror("bad pagesize");
    }
}

uint64_t patchfinder64::pte_index_to_vma(uint32_t pagesize, uint8_t level, uint64_t index){
    switch (pagesize) {
        case 0x1000: //4K
            switch (level) {
                case 0:
                    return (index << 39) & ((1UL<<(47+1))-1);
                case 1:
                    return (index << 30) & ((1UL<<(38+1))-1);
                case 2:
                    return (index << 21) & ((1UL<<(29+1))-1);
                case 3:
                    return (index << 12) & ((1UL<<(20+1))-1);
                default:
                    reterror("[4K] bad level=%d",level);
            }
            break;
        case 0x4000: //16K
            switch (level) {
                case 0:
                    return (index << 47) & ((1UL<<(47+1))-1);
                case 1:
                    return (index << 36) & ((1UL<<(46+1))-1);
                case 2:
                    return (index << 25) & ((1UL<<(35+1))-1);
                case 3:
                    return (index << 14) & ((1UL<<(24+1))-1);
                default:
                    reterror("[16K] bad level=%d",level);
            }
            break;
        case 0x10000: //64K
            switch (level) {
                case 1:
                    return (index << 42) & ((1UL<<(51+1))-1);
                case 2:
                    return (index << 29) & ((1UL<<(41+1))-1);
                case 3:
                    return (index << 16) & ((1UL<<(28+1))-1);
                default:
                    reterror("[64K] bad level=%d",level);
            }
            break;
        default:
            reterror("bad pagesize");
    }
}




//
