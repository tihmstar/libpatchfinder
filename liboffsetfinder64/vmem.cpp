//
//  vmem.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "vmem.hpp"
#include <libgeneral/macros.h>
#include "OFexception.hpp"
#include <string.h>
#include <algorithm>

using namespace tihmstar::offsetfinder64;

vmem::vmem(const std::vector<offsetfinder64::vsegment> segments, int perm) :
    _segments(segments),
    _segNum(0)
{
    if (perm) {
        _segments.erase(std::remove_if(_segments.begin(), _segments.end(), [&](const vsegment& obj){
            return (obj.perm() & perm) != perm;
        }), _segments.end());
    }
    std::sort(_segments.begin(),_segments.end(),[ ]( const vsegment& lhs, const vsegment& rhs){
        return lhs.base() < rhs.base();
    });
    
    assure(_segments.size());
}

vmem::vmem(const vmem& copy, offsetfinder64::loc_t pos, int perm) :
_segments(copy._segments),
_segNum(0)
{
    if (perm) {
        _segments.erase(std::remove_if(_segments.begin(), _segments.end(), [&](const vsegment& obj){
            return (obj.perm() & perm) != perm;
        }), _segments.end());
    }
    std::sort(_segments.begin(),_segments.end(),[ ]( const vsegment& lhs, const vsegment& rhs){
        return lhs.base() < rhs.base();
    });
    assure(_segments.size());
    *this = pos;
}


vsegment vmem::seg(loc_t pos){
    for (auto &seg : _segments) {
        if (seg.isInRange(pos)) {
            return {seg,pos};
        }
    }
    retcustomerror(out_of_range, "pos not in vmem");
}

uint64_t vmem::deref(loc_t pos){
    for (auto &seg : _segments) {
        if (seg.isInRange(pos)) {
            return seg.doublevalue(pos);
        }
    }
    retcustomerror(out_of_range, "pos not in segments");
}

loc_t vmem::memmem(const void *little, size_t little_len, loc_t startLoc){
    for (auto &seg : _segments) {
        if (startLoc && !seg.isInRange(startLoc))
            continue;
        if (loc_t rt = seg.memmem(little, little_len, startLoc)) {
            return rt;
        }
    }
    retcustomerror(not_found,"memmem failed to find \"%*s\"",little_len,little);
}

loc_t vmem::memstr(const char *little){
    for (auto &seg : _segments) {
        if (loc_t rt = seg.memmem(little, strlen(little))) {
            return rt;
        }
    }
    retcustomerror(not_found,"memstr failed to find \"%s\"",little);
}

bool vmem::isInRange(loc_t pos) noexcept{
    for (auto &seg : _segments) {
        if (seg.isInRange(pos)) {
            return true;
        }
    }
    return false;
}

#pragma mark iterator operator

insn vmem::operator++(){
    try {
        return ++_segments.at(_segNum);
    } catch (tihmstar::out_of_range &e) {
        //
    }
    retcustomassure(_segNum+1<_segments.size(), out_of_range, "overflow reached end of vmem");
    _segNum++;
    auto &seg = _segments.at(_segNum);
    seg = seg.base();
    return seg();
}

insn vmem::operator--(){
    try {
        return --_segments.at(_segNum);
    } catch (tihmstar::out_of_range &e) {
        //
    }
    retcustomassure(_segNum>0, out_of_range, "undeflow reached end of vmem");
    _segNum--;
    auto &seg = _segments.at(_segNum);
    seg = seg.base() + seg.size() - 4;
    return seg();
}

vmem &vmem::operator+=(int i){
    if (i<0) return this->operator-=(-i);
    try {
        _segments.at(_segNum)+=i;
        return *this;
    } catch (tihmstar::out_of_range &e) {
        //
    }
    retcustomassure(_segNum+1<_segments.size(), out_of_range, "overflow reached end of vmem");
    
    auto &curSeg = _segments.at(_segNum);
    int insnLeft = ((uint64_t)curSeg.base() + curSeg.size() - curSeg.pc())/4;
    _segNum++;
    auto &seg = _segments.at(_segNum);
    seg = seg.base();
    return operator+=(i - insnLeft);
}

vmem &vmem::operator-=(int i){
    if (i<0) return this->operator+=(-i);
    try {
        _segments.at(_segNum) -=i;
        return *this;
    } catch (tihmstar::out_of_range &e) {
        //
    }
    retcustomassure(_segNum>0, out_of_range, "underflow reached end of vmem");
    auto &curSeg = _segments.at(_segNum);
    int insnLeft = ((curSeg.pc() - (uint64_t)curSeg.base()))/4;
    _segNum--;
    
    auto &prevSeg = _segments.at(_segNum);
    prevSeg = prevSeg.base() + prevSeg.size() - 4;
    return operator-=(i - insnLeft);
}

insn vmem::myop_plus(int i, uint32_t segNum){
    if (i<0) return myop_minus(-i,segNum);
    try {
        return _segments.at(segNum) + i;
    } catch (tihmstar::out_of_range &e) {
        //
    }
    retcustomassure(segNum+1<_segments.size(), out_of_range, "overflow reached end of vmem");
    
    auto &curSeg = _segments.at(segNum);
    int insnLeft = ((uint64_t)curSeg.base() + curSeg.size() - curSeg.pc())/4;
    segNum++;
    _segments.at(segNum) = 0;
    return myop_plus(i - insnLeft,segNum);
}

insn vmem::myop_minus(int i, uint32_t segNum){
    if (i<0) return myop_minus(-i,segNum);
    try {
        return _segments.at(segNum) - i;
    } catch (tihmstar::out_of_range &e) {
        //
    }
    retcustomassure(_segNum>0, out_of_range, "underflow reached end of vmem");
    auto &curSeg = _segments.at(segNum);
    int insnLeft = ((curSeg.pc() - (uint64_t)curSeg.base()))/4;
    segNum--;
    
    auto &prevSeg = _segments.at(segNum);
    prevSeg = prevSeg.base() + prevSeg.size() - 4;
    return myop_minus(i - insnLeft,segNum);
}

insn vmem::operator+(int i){
    return myop_plus(i, _segNum);
}

insn vmem::operator-(int i){
    return myop_minus(i, _segNum);
}

vmem &vmem::operator=(loc_t pos){
    if (pos == 0) {
        _segments.at(_segNum = 0) = 0;
        return *this;
    }
    
    for (int i=0; i<_segments.size(); i++) {
        auto &seg = _segments.at(i);
        if (seg.isInRange(pos)) {
            _segNum = i;
            seg = pos;
            return *this;
        }
    }
    retcustomerror(out_of_range, "pos not within vmem");
}

#pragma mark segment info functions
int vmem::curPerm() const{
    return _segments.at(_segNum).perm();
}
                    
const void *vmem::memoryForLoc(loc_t loc){
    for (int i=0; i<_segments.size(); i++) {
        auto &seg = _segments.at(i);
        if (seg.isInRange(loc)) {
            return seg.memoryForLoc(loc);
        }
    }
    retcustomerror(out_of_range, "loc not within vmem");
}


vsegment vmem::curSeg(){
    return _segments.at(_segNum);
}

const vsegment vmem::curSeg() const{
    return _segments.at(_segNum);
}

                    
#pragma mark deref operator
uint64_t vmem::pc(){
    return curSeg().pc();
}

uint32_t vmem::value(){
    return curSeg().value();
}

uint64_t vmem::doublevalue(){
    return curSeg().doublevalue();
}

uint32_t vmem::value(loc_t p){
    return seg(p).value(p);
}

uint64_t vmem::doublevalue(loc_t p){
    return seg(p).doublevalue(p);
}

#pragma mark insn operator
insn vmem::getinsn(){
    return curSeg().getinsn();
}

insn vmem::operator()(){
    return getinsn();
}

vmem::operator loc_t() const{
    return (loc_t)curSeg();
}
