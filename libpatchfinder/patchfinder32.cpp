//
//  patchfinder32.cpp
//  patchfinder
//
//  Created by tihmstar on 06.07.21.
//

#include <string.h>

#include <libgeneral/macros.h>

#include "../include/libpatchfinder/patchfinder32.hpp"

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;

#pragma mark constructor/destructor

patchfinder32::patchfinder32(bool freeBuf) :
    _freeBuf(freeBuf),
    _buf(NULL),
    _bufSize(0),
    _entrypoint(0),
    _base(0),
    _vmem(nullptr)
{
    //
}

patchfinder32::patchfinder32(patchfinder32 &&mv) :
    _freeBuf(mv._freeBuf),
    _buf(mv._buf),
    _bufSize(mv._bufSize),
    _entrypoint(mv._entrypoint),
    _base(mv._base)
{
    mv._freeBuf = false; //if we take ownership, the old object should no longer free the buffer
    _vmem = mv._vmem; mv._vmem = NULL;
    _usedNops = std::move(mv._usedNops);
}


patchfinder32::~patchfinder32(){
    safeDelete(_vmem);
    if (_freeBuf) safeFreeConst(_buf);
}


#pragma mark patchfinder

const void *patchfinder32::memoryForLoc(loc_t loc){
    return _vmem->memoryForLoc(loc);
}


patchfinder32::loc_t patchfinder32::findstr(std::string str, bool hasNullTerminator, loc_t startAddr){
    return _vmem->memmem(str.c_str(), str.size()+(hasNullTerminator), startAddr);
}

patchfinder32::loc_t patchfinder32::find_bof_thumb(loc_t pos){
    libinsn::vmem<arm32::thumb> functop = _vmem->seg(pos);

    while (--functop != arm32::push || !functop().reglist().lr);
    
    return functop;
}
//
//
//uint64_t patchfinder32::find_register_value(loc_t where, int reg, loc_t startAddr){
//    vsegment functop = _vmem->seg(where);
//    
//    if (!startAddr) {
//        functop = find_bof(where);
//    }else{
//        functop = startAddr;
//    }
//    
//    uint64_t value[32] = {0};
//    
//    for (;(loc_t)functop.pc() < where;++functop) {
//        switch (functop().type()) {
//            case insn::adrp:
//                value[functop().rd()] = functop().imm();
//                //                printf("0x%016llx: ADRP X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
//                break;
//            case insn::add:
//                value[functop().rd()] = value[functop().rn()] + functop().imm();
//                //                printf("0x%016llx: ADD X%d, X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.rn(), (uint64_t)functop.imm());
//                break;
//            case insn::adr:
//                value[functop().rd()] = functop().imm();
//                //                printf("0x%016llx: ADR X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
//                break;
//            case insn::ldr:
//                //                printf("0x%016llx: LDR X%d, [X%d, 0x%llx]\n", (void*)functop.pc(), functop.rt(), functop.rn(), (uint64_t)functop.imm());
//                value[functop().rt()] = value[functop().rn()];
//                if (functop().subtype() == insn::st_immediate) {
//                    value[functop().rt()] += functop().imm(); // XXX address, not actual value
//                }
//                break;
//            case insn::movz:
//                value[functop().rd()] = functop().imm();
//                break;
//            case insn::movk:
//                value[functop().rd()] |= functop().imm();
//                break;
//            case insn::mov:
//                value[functop().rd()] = value[functop().rm()];
//                break;
//            default:
//                break;
//        }
//    }
//    return value[reg];
//}
//
patchfinder32::loc_t patchfinder32::find_literal_ref_thumb(loc_t pos, int ignoreTimes, loc_t startPos){
    libinsn::vmem<arm32::thumb> iter = _vmem->getIter(startPos);
    try {
        loc_t refval[16] = {};
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
    libinsn::vmem<arm32::thumb> bl = _vmem->getIter(startPos);
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


patchfinder32::loc_t patchfinder32::find_branch_ref_thumb(loc_t pos, int limit, int ignoreTimes){
    vmem_thumb brnch = _vmem->getIter(pos);

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
    reterror("branchref not found");
}

patchfinder32::loc_t patchfinder32::findnops(uint16_t nopCnt, bool useNops, uint32_t nopOpcode){
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
    pos = _vmem->memmem(needle, nopCnt*4,pos+4);
    std::pair<loc_t, loc_t> range(pos,pos+4*nopCnt);
    
    for (auto &r : _usedNops) {
        if (r.first > range.first && r.first < range.second) goto nextNops; //used range inside found range
        if (range.first > r.first && range.first < r.second) goto nextNops; //found range inside used range
    }

    if (useNops) {
        debug("consuming nops {0x%016llx,0x%016llx}",range.first,range.second);
        _usedNops.push_back(range);
    }
    
    return pos;
}


std::vector<patch> patchfinder32::get_replace_string_patch(std::string needle, std::string replacement){
    std::vector<patch> patches;

    retassure(needle.size() == replacement.size(), "needle.size() != replacement.size()");
    
    loc_t curloc = -1;
    
    try {
        while (true) {
            curloc = _vmem->memmem(needle.data(), needle.size(), curloc+1);
            patches.push_back({
                curloc,
                replacement.data(),
                replacement.size()
            });
        }
    } catch (...) {
        //
    }
    retassure(patches.size(), "Failed to find even a single instance of '%s'",needle.c_str());
    return patches;
}


//
