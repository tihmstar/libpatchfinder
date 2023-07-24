//
//  patchfinder32.cpp
//  patchfinder
//
//  Created by tihmstar on 06.07.21.
//
#include <libgeneral/macros.h>

#include "../include/libpatchfinder/patchfinder32.hpp"

#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;

#pragma mark constructor/destructor

patchfinder32::patchfinder32(bool freeBuf) :
    patchfinder(freeBuf),
    _vmemThumb(nullptr),
    _vmemArm(nullptr)
{
    //
}

patchfinder32::patchfinder32(patchfinder32 &&mv) :
    patchfinder(std::move(mv))
{
    _usedNops = std::move(mv._usedNops);
    _savedPatches = std::move(mv._savedPatches);
    _vmemThumb = mv._vmemThumb; mv._vmemThumb = NULL;
    _vmemArm = mv._vmemArm; mv._vmemArm = NULL;
}

patchfinder32::patchfinder32(loc_t base, const char *filename, std::vector<psegment> segments) :
    patchfinder(true)
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
    _vmemThumb = new vmem_thumb(vsegs);
    _vmemArm = new vmem_arm(vsegs);
}

patchfinder32::patchfinder32(loc_t base, const void *buffer, size_t bufSize, bool takeOwnership, std::vector<psegment> segments) :
    patchfinder(takeOwnership)
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
    _vmemThumb = new vmem_thumb(vsegs);
    _vmemArm = new vmem_arm(vsegs);
}

patchfinder32::~patchfinder32(){
    safeDelete(_vmemThumb);
    safeDelete(_vmemArm);
}

#pragma mark provider for parent
const void *patchfinder32::memoryForLoc(patchfinder::loc_t loc){
    return _vmemThumb->memoryForLoc((loc_t)loc);
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::findstr(std::string str, bool hasNullTerminator, patchfinder::patchfinder::loc_t startAddr){
    return _vmemThumb->memmem(str.c_str(), str.size()+(hasNullTerminator), (loc_t)startAddr);
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::find_bof(patchfinder::loc_t pos, bool mayLackPrologue){
    (void)mayLackPrologue;
    return find_bof_thumb((loc_t)pos);
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::find_register_value(patchfinder::loc_t where, int reg, patchfinder::loc_t startAddr){
    return find_register_value_thumb((loc_t)where, (uint8_t)reg, (loc_t)startAddr);
}


tihmstar::patchfinder::patchfinder::loc_t patchfinder32::find_literal_ref(patchfinder::loc_t pos, int ignoreTimes, patchfinder::loc_t startPos){
    return find_literal_ref_thumb((loc_t)pos, ignoreTimes, (loc_t)startPos);
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::find_call_ref(patchfinder::loc_t pos, int ignoreTimes, patchfinder::loc_t startPos){
    return find_call_ref_thumb((loc_t)pos, ignoreTimes, (loc_t)startPos);
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::find_branch_ref(patchfinder::loc_t pos, int limit, int ignoreTimes, patchfinder::loc_t startPos){
    return find_branch_ref_thumb((loc_t)pos, limit, ignoreTimes, (loc_t)startPos);
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::findnops(uint16_t nopCnt, bool useNops, uint32_t nopOpcode){
    uint32_t *needle = NULL;
    cleanup([&]{
        safeFree(needle);
    });
    loc_t pos = 0;
    needle = (uint32_t *)malloc(nopCnt*4);
    
    for (uint16_t i=0; i<nopCnt; i++) {
        needle[i] = nopOpcode;
    }

    
    pos = -4;
nextNops:
    pos = (loc_t)memmem(needle, nopCnt*4,pos+4);
    if (pos & 1){
        pos -= 3;
        goto nextNops;
    }
    std::pair<loc_t, loc_t> range(pos,pos+4*nopCnt);
    
    for (auto &r : _usedNops) {
        if (r.first >= range.first && r.first < range.second)
            goto nextNops; //used range inside found range
        if (range.first >= r.first && range.first < r.second)
            goto nextNops; //found range inside used range
    }

    if (useNops) {
        debug("consuming nops {0x%016llx,0x%016llx}",range.first,range.second);
        _usedNops.push_back(range);
    }
    
    return pos;
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::memmem(const void *little, size_t little_len, patchfinder::loc_t startLoc) const {
    return _vmemThumb->memmem(little, little_len, (loc_t)startLoc);
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::memstr(const char *str) const {
    return _vmemThumb->memstr(str);
}

tihmstar::patchfinder::patchfinder::loc_t patchfinder32::deref(patchfinder::loc_t pos) const {
    return _vmemThumb->deref(pos);
}

#pragma mark own functions
patchfinder32::loc_t patchfinder32::find_bof_thumb(loc_t pos){
    vmem_thumb functop = _vmemThumb->seg(pos);

    while (--functop != arm32::push || !functop().reglist().lr);
    
    return functop;
}

patchfinder32::loc_t patchfinder32::find_bof_arm(loc_t pos){
    vmem_arm functop = _vmemArm->seg(pos);

    while (--functop != arm32::push || !functop().reglist().lr);
    
    return functop;
}

uint32_t patchfinder32::find_register_value_thumb(loc_t where, uint8_t reg, loc_t startAddr){
    vmem_thumb functop = _vmemThumb->seg(where);
    
    if (!startAddr) {
        functop = find_bof_thumb(where);
    }else{
        functop = startAddr;
    }
    
    uint32_t value[15] = {0};
    
    for (;(loc_t)functop.pc() < where;++functop) {
        auto insn = functop();
        switch (insn.type()) {
            case arm32::adr:
                value[insn.rd()] = insn.imm();
                break;
            case arm32::add:
                value[insn.rd()] = value[insn.rn()] + insn.imm();
                break;
            case arm32::ldr:
                if (insn.subtype() == arm32::st_immediate) {
                    value[insn.rt()] += insn.imm(); // XXX address, not actual value
                }else{
                    value[insn.rt()] = value[insn.rn()];
                }
                break;
            case arm32::mov:
                if (insn.subtype() == arm32::st_immediate) {
                    value[insn.rd()] = insn.imm(); // XXX address, not actual value
                }else{
                    value[insn.rd()] = value[insn.rn()];
                }
                break;
            case arm32::lsl:
                if (insn.subtype() == arm32::st_immediate) {
                    value[insn.rd()] = value[insn.rm()] << insn.imm();
                }else{
                    value[insn.rd()] = value[insn.rm()] << insn.rn();
                }
                break;
            default:
                break;
        }
    }
    return value[reg];
}

patchfinder32::loc_t patchfinder32::find_literal_ref_arm(loc_t pos, int ignoreTimes, loc_t startPos){
    libinsn::vmem<arm32::arm> iter = _vmemArm->getIter(startPos);
    try {
        int64_t refval[16] = {};
        for (;;++iter){
            auto insn = iter();
            if (insn == arm32::ldr && insn.subtype() == arm32::st_literal) {
                loc_t literal_loc = insn.imm();
                uint8_t ldr_reg = insn.rt();
                try {
                    if ((refval[ldr_reg] = iter.deref(literal_loc)) == pos) {
                        if (! ignoreTimes--) return iter;
                    }
                } catch (...) {
                    //
                }
            }else if (insn == arm32::ldr && insn.subtype() == arm32::st_immediate){
                try {
                    int64_t val = refval[insn.rn()];
                    if (val != -1 && val + insn.imm() == pos){
                        if (! ignoreTimes--) return iter;
                    }
                    refval[insn.rt()] = -1;
                } catch (...) {
                    //
                }
            }else if (insn == arm32::add && insn.subtype() == arm32::st_register && insn.rm() == 15/*pc*/){
                uint8_t ldr_reg = insn.rd();
                refval[ldr_reg] += insn.pc() + 4;
                if (refval[ldr_reg] == pos) {
                    if (! ignoreTimes--) return iter;
                }
            }else if (insn == arm32::mov && insn.subtype() == arm32::st_immediate){
                uint8_t mov_reg = insn.rd();
                refval[mov_reg] = insn.imm();
                if (refval[mov_reg] == pos) {
                    if (! ignoreTimes--) return iter;
                }
            }else if (insn == arm32::movt && insn.subtype() == arm32::st_immediate){
                uint8_t mov_reg = insn.rd();
                refval[mov_reg] |= insn.imm();
                if (refval[mov_reg] == pos) {
                    if (! ignoreTimes--) return iter;
                }
            }
        }
    } catch (tihmstar::out_of_range &e) {
        return 0;
    }
    return 0;
}

patchfinder32::loc_t patchfinder32::find_literal_ref_thumb(loc_t pos, int ignoreTimes, loc_t startPos){
    vmem_thumb iter = _vmemThumb->getIter(startPos);
    try {
        int64_t refval[16] = {};
        for (;;++iter){
            auto insn = iter();
            if (insn == arm32::ldr && insn.subtype() == arm32::st_literal) {
                loc_t literal_loc = insn.imm();
                uint8_t ldr_reg = insn.rt();
                try {
                    if ((refval[ldr_reg] = iter.deref(literal_loc)) == pos) {
                        if (! ignoreTimes--) return iter;
                    }
                } catch (...) {
                    //
                }
            }else if (insn == arm32::ldr && insn.subtype() == arm32::st_immediate){
                try {
                    int64_t val = refval[insn.rn()];
                    if (val != -1 && val + insn.imm() == pos){
                        if (! ignoreTimes--) return iter;
                    }
                    refval[insn.rt()] = -1;
                } catch (...) {
                    //
                }
            }else if (insn == arm32::add && insn.subtype() == arm32::st_register && insn.rm() == 15/*pc*/){
                uint8_t ldr_reg = insn.rd();
                refval[ldr_reg] += insn.pc() + 4;
                if (refval[ldr_reg] == pos) {
                    if (! ignoreTimes--) return iter;
                }
            }else if (insn == arm32::mov && insn.subtype() == arm32::st_immediate){
                uint8_t mov_reg = insn.rd();
                refval[mov_reg] = insn.imm();
                if (refval[mov_reg] == pos) {
                    if (! ignoreTimes--) return iter;
                }
            }else if (insn == arm32::movt && insn.subtype() == arm32::st_immediate){
                uint8_t mov_reg = insn.rd();
                refval[mov_reg] |= insn.imm();
                if (refval[mov_reg] == pos) {
                    if (! ignoreTimes--) return iter;
                }
            }
        }
    } catch (tihmstar::out_of_range &e) {
        return 0;
    }
    return 0;
}

patchfinder32::loc_t patchfinder32::find_call_ref_thumb(loc_t pos, int ignoreTimes, loc_t startPos){
    vmem_thumb bl = _vmemThumb->getIter(startPos);
    if (bl() == arm32::bl) goto isBL;
    while (true){
        while (++bl != arm32::bl)
            ;
    isBL:
        if (bl().imm() == (loc_t)pos && --ignoreTimes <0)
            return bl;
    }
    reterror("call reference not found");
}

patchfinder32::loc_t patchfinder32::find_branch_ref_thumb(loc_t pos, int limit, int ignoreTimes, loc_t startPos){
    if (!limit){
        vmem_thumb iter = _vmemThumb->getIter(startPos);
        while (true) {
            if (iter().supertype() == arm32::sut_branch_imm) {
                if (iter().imm() == pos){
                    if (ignoreTimes-- <=0) return iter;
                }
            }
            ++iter;
        }
    }else{
        if (!startPos) startPos = pos;
        vmem_thumb brnch = _vmemThumb->getIter(pos);

        if (limit < 0 ) {
            while (true) {
                while ((--brnch).supertype() != arm32::sut_branch_imm){
                    limit += 2; //backwards is always 2
                    retassure(limit < 0, "search limit reached");
                }
                if ((loc_t)brnch().imm() == pos){
                    if (ignoreTimes--  <=0)
                        return brnch;
                }
            }
        }else{
            while (true) {
               while ((++brnch).supertype() != arm32::sut_branch_imm){
                   limit -= brnch().insnsize();;
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
