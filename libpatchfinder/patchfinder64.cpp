//
//  offsetfinder64.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>
#include "all64.h"
#include "../include/libpatchfinder/patchfinder64.hpp"
#include "StableHash.h"

#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

#pragma mark constructor/destructor

patchfinder64::patchfinder64(bool freeBuf) 
: patchfinder(freeBuf)
, _vmem(nullptr)
{
    //
}

patchfinder64::patchfinder64(patchfinder64 &&mv) 
: patchfinder(std::move(mv))
, _vmem(nullptr)
{
    _unusedNops = std::move(mv._unusedNops);
    _savedPatches = std::move(mv._savedPatches);
    _vmem = mv._vmem; mv._vmem = NULL;
}

patchfinder64::patchfinder64(loc_t base, const char *filename, std::vector<psegment> segments)
: patchfinder(true)
, _vmem(nullptr)
{
    struct stat fs = {0};
    int fd = 0;
    bool didConstructSuccessfully = false;
    cleanup([&]{
        if (fd>0) close(fd);
        if (!didConstructSuccessfully) {
            safeFreeConst(_buf);
        }
    })
    
    assure((fd = open(filename, O_RDONLY)) != -1);
    assure(!fstat(fd, &fs));
    assure((_buf = (uint8_t*)malloc( _bufSize = fs.st_size)));
    assure(read(fd,(void*)_buf,_bufSize)==_bufSize);
    
    _base = base;
    
    if (!segments.size()) {
        segments.push_back({
            .fileOffset = 0,
            .size = _bufSize,
            .vaddr = base,
            .perms = kPPROTALL
        });
    }
    
    std::vector<vsegment> vsegs;
    for (auto seg : segments){
        vsegment vseg{
            .buf = &_buf[seg.fileOffset],
            .size = seg.size,
            .vaddr = seg.vaddr,
            .perms = seg.perms ? (vmprot)seg.perms : (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)
        };
        retassure(vseg.buf >= _buf && vseg.buf + vseg.size <= &_buf[_bufSize], "segment out of bounds");
        vsegs.push_back(vseg);
    }
    _vmem = new vmem(vsegs);
}

patchfinder64::patchfinder64(loc_t base, const void *buffer, size_t bufSize, bool takeOwnership, std::vector<psegment> segments) 
: patchfinder(takeOwnership)
, _vmem(nullptr)
{
    _bufSize = bufSize;
    _buf = (uint8_t*)buffer;
    _base = base;

    if (!segments.size()) {
        segments.push_back({
            .fileOffset = 0,
            .size = _bufSize,
            .vaddr = base,
            .perms = kPPROTALL
        });
    }
    
    std::vector<vsegment> vsegs;
    for (auto seg : segments){
        vsegment vseg{
            .buf = &_buf[seg.fileOffset],
            .size = seg.size,
            .vaddr = seg.vaddr,
            .perms = seg.perms ? (vmprot)seg.perms : (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)
        };
        retassure(vseg.buf >= _buf && vseg.buf + vseg.size <= &_buf[_bufSize], "segment out of bounds");
        vsegs.push_back(vseg);
    }
    _vmem = new vmem(vsegs);
}

patchfinder64::~patchfinder64(){
    safeDelete(_vmem);
}

#pragma mark provider for parent
const void *patchfinder64::memoryForLoc(loc_t loc){
    return _vmem->memoryForLoc(loc);
}

patchfinder64::loc_t patchfinder64::findstr(std::string str, bool hasNullTerminator, loc_t startAddr){
    return memmem(str.c_str(), str.size()+(hasNullTerminator), startAddr);
}

patchfinder64::loc_t patchfinder64::find_bof(loc_t pos, bool mayLackPrologue){
    vmem functop = _vmem->seg(pos);


    //find stp x29, x30, [sp, ...]
    while (functop() != insn::stp || functop().rt2() != 30 || functop().rn() != 31){
        if (--functop == insn::ret && mayLackPrologue) return functop+1;
    }

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

patchfinder64::loc_t patchfinder64::find_bof_with_sting_ref(const char *str, bool hasNullTerminator){
    loc_t s = findstr(str, hasNullTerminator);
    assure(s);
    loc_t ref = find_literal_ref(s);
    assert(ref);
    return find_bof(ref);
}

uint64_t patchfinder64::find_register_value(loc_t where, int reg, loc_t startAddr){
    vmem functop = _vmem->seg(where);
    
    if (!startAddr) {
        functop = find_bof(where);
    }else{
        functop = startAddr;
    }
    
    uint64_t value[32] = {0};
    
    for (;(loc_t)functop.pc() < where;++functop) {
        auto insn = functop();
        switch (functop().type()) {
            case insn::adrp:
                value[insn.rd()] = insn.imm();
                //                printf("0x%016llx: ADRP X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
                break;
            case insn::add:
                value[insn.rd()] = value[insn.rn()] + insn.imm();
                //                printf("0x%016llx: ADD X%d, X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.rn(), (uint64_t)functop.imm());
                break;
            case insn::adr:
                value[insn.rd()] = insn.imm();
                //                printf("0x%016llx: ADR X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
                break;
            case insn::ldr:
                //                printf("0x%016llx: LDR X%d, [X%d, 0x%llx]\n", (void*)functop.pc(), functop.rt(), functop.rn(), (uint64_t)functop.imm());
                value[insn.rt()] = value[insn.rn()];
                if (insn.subtype() == insn::st_immediate) {
                    value[insn.rt()] += insn.imm(); // XXX address, not actual value
                }
                break;
            case insn::movz:
                value[insn.rd()] = insn.imm();
                break;
            case insn::movk:
                value[insn.rd()] |= insn.imm();
                break;
            case insn::mov:
                value[insn.rd()] = value[insn.rm()];
                break;
            case insn::orr:
                if (insn.subtype() == libinsn::arm64::insn::st_general) {
                    value[insn.rd()] = ((insn.rn() == 0x1f) ? /*wzr*/0 : value[insn.rn()]) + insn.imm();
                }
                break;
            default:
                break;
        }
    }
    return value[reg];
}

patchfinder64::loc_t patchfinder64::find_literal_ref(loc_t pos, int ignoreTimes, loc_t startPos){
    auto adrp = _vmem->getIter(startPos);
    
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
                
                vmem iter = _vmem->getIter(adrp);
                
                for (int i=0; i<10; i++) {
                    auto isn = ++iter;
                    if (isn == insn::add && rd == isn.rn()){
                        if (imm + isn.imm() == (int64_t)pos){
                            if (ignoreTimes) {
                                ignoreTimes--;
                                break;
                            }
                            return (loc_t)iter.pc();
                        }
                    }else if (isn.supertype() == insn::sut_memory && isn.subtype() == insn::st_immediate && rd == isn.rn()){
                        if (imm + isn.imm() == (int64_t)pos){
                            if (ignoreTimes) {
                                ignoreTimes--;
                                break;
                            }
                            return (loc_t)iter.pc();
                        }
                    }else if ((isn == insn::adr || isn == insn::adrp) && isn.rd() == rd){
                        //rd gets overwritten
                        break;
                    }
                }
            }
            
            if (adrp() == insn::movz) {
                uint8_t rd = 0xff;
                uint64_t imm = 0;
                rd = adrp().rd();
                imm = adrp().imm();
                
                if (imm == pos) {
                    if (ignoreTimes) {
                        ignoreTimes--;
                        continue;
                    }
                    return (loc_t)adrp.pc();
                }
                
                vmem iter = _vmem->getIter(adrp);
                                
                for (int i=0; i<10; i++) {
                    ++iter;
                retry:
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
                    } else if (iter() == insn::b){
                        if (iter.pc() == iter().imm()) break; //found b .
                        try {
                            iter = iter().imm(); //this can go out of memory and fail, ignore failure
                        } catch (...) {
                            break;
                        }
                        goto retry;
                    }
                }
            }
        }
    } catch (tihmstar::out_of_range &e) {
        return 0;
    }
    return 0;
}

patchfinder64::loc_t patchfinder64::find_call_ref(loc_t pos, int ignoreTimes, loc_t startPos){
    vmem bl = _vmem->getIter(startPos);
    if (bl() == insn::bl) goto isBL;
    while (true){
        while (++bl != insn::bl);
    isBL:
        if (bl().imm() == (uint64_t)pos && --ignoreTimes <0)
            return bl;
    }
    reterror("call reference not found");
}


patchfinder64::loc_t patchfinder64::find_branch_ref(loc_t pos, int limit, int ignoreTimes, loc_t startPos){
    if (!limit) {
        vmem iter = _vmem->getIter(startPos);
        while (true) {
            if (iter().supertype() == insn::supertype::sut_branch_imm) {
                if (iter().imm() == pos){
                    if (ignoreTimes-- <=0) return iter;
                }
            }
            ++iter;
        }
    }else{
        if (!startPos) startPos = pos;
        vmem brnch = _vmem->getIter(startPos);

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
    }
    reterror("branchref not found");
}

patchfinder64::loc_t patchfinder64::find_block_branch_ref(loc_t pos, int limit, int ignoreTimes, loc_t startPos){
    loc_t bof = find_bof(pos);
    
    vmem iter = _vmem->getIter(pos);
    while (iter > bof) {
        try {
            return find_branch_ref(iter, limit, ignoreTimes, startPos);
        } catch (...) {
            if ((--iter).supertype() == insn::sut_branch_imm && iter() != insn::bl){
                /*
                 Any non-bl immediate branch means we reached a different basic block
                 */
                break;
            }
            if (limit > 0){
                limit-=4;
            } else if (limit < 0){
                limit += 4;
            }
        }
    }
    reterror("Failed to find block branch ref");
}

patchfinder64::loc_t patchfinder64::findnops(uint16_t nopCnt, bool useNops, uint32_t nopOpcode){
    size_t tgtSize = nopCnt*4;
    if (!_unusedNops.size()) {
        vmem exec_mem = _vmem->getIter();
        
        bool isrunning = false;
        loc_t start = 0;
        
        try {
            while (true) {
                uint32_t op = (++exec_mem).opcode();
                if (op == nopOpcode || op == 0) {
                    if (!isrunning) {
                        isrunning = true;
                        start = exec_mem.pc();
                    }
                }else{
                    if (isrunning) {
                        isrunning = false;
                        size_t nps = exec_mem.pc()-start;
                        if (nps < 4*11) continue; //have a minimum of 10 free nops
                        _unusedNops.push_back({start,nps});
                    }
                }
            }
        } catch (...) {
            //
        }
        _unusedNops.push_back({0,0}); //mark as inited
    }
    retassure(_unusedNops.size(), "Failed to find nopspace");
    
    int besti = -1;
    size_t bestSize = 0;
    
    for (int i=0; i<_unusedNops.size(); i++) {
        auto np = _unusedNops.at(i);
        if (tgtSize <= np.second) {
            if (besti == -1 || np.second < bestSize) {
                besti = i;
                bestSize = np.second;
            }
        }
    }
    retassure(besti != -1, "Failed to find enough nopspace");
    auto foundnops = _unusedNops.at(besti);
    if (useNops) {
        _unusedNops.erase(_unusedNops.begin() + besti);
        size_t remainSpaceSize = 0;
        if (tgtSize < bestSize) {
            remainSpaceSize = foundnops.second - tgtSize;
            loc_t remainSpace = foundnops.first + tgtSize;
            _unusedNops.push_back({remainSpace,remainSpaceSize});
        }
        debug("consuming nops {0x%016llx,0x%016llx}",foundnops.first,foundnops.first+foundnops.second-remainSpaceSize);
    }
    return foundnops.first;
}

patchfinder64::loc_t patchfinder64::memmem(const void *little, size_t little_len, patchfinder::loc_t startLoc) const {
    return _vmem->memmem(little, little_len, startLoc);
}

patchfinder64::loc_t patchfinder64::memstr(const char *str) const {
    return _vmem->memstr(str);
}

patchfinder64::loc_t patchfinder64::deref(patchfinder::loc_t pos) const {
    return _vmem->deref(pos);
}

#pragma mark own functions
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
                    return (index << 39) & ((1ULL<<(47+1))-1);
                case 1:
                    return (index << 30) & ((1ULL<<(38+1))-1);
                case 2:
                    return (index << 21) & ((1ULL<<(29+1))-1);
                case 3:
                    return (index << 12) & ((1ULL<<(20+1))-1);
                default:
                    reterror("[4K] bad level=%d",level);
            }
            break;
        case 0x4000: //16K
            switch (level) {
                case 0:
                    return (index << 47) & ((1ULL<<(47+1))-1);
                case 1:
                    return (index << 36) & ((1ULL<<(46+1))-1);
                case 2:
                    return (index << 25) & ((1ULL<<(35+1))-1);
                case 3:
                    return (index << 14) & ((1ULL<<(24+1))-1);
                default:
                    reterror("[16K] bad level=%d",level);
            }
            break;
        case 0x10000: //64K
            switch (level) {
                case 1:
                    return (index << 42) & ((1ULL<<(51+1))-1);
                case 2:
                    return (index << 29) & ((1ULL<<(41+1))-1);
                case 3:
                    return (index << 16) & ((1ULL<<(28+1))-1);
                default:
                    reterror("[64K] bad level=%d",level);
            }
            break;
        default:
            reterror("bad pagesize");
    }
}

#pragma mark own functions virtual
uint16_t patchfinder64::getPointerAuthStringDiscriminator(const char *strDesc){
    return clang::getPointerAuthStringDiscriminator(strDesc);
}

patchfinder64::loc_t patchfinder64::find_PACedPtrRefWithStrDesc(const char *strDesc, int ignoreTimes, loc_t startPos){
    uint64_t desc = getPointerAuthStringDiscriminator(strDesc);
    vmem iter = _vmem->getIter(startPos);
    while (true) {
        while (++iter != insn::movk || iter().imm() != ((uint64_t)desc << 48));
        if (ignoreTimes-- == 0) return iter;
    }
}
