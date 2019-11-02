//
//  vsegment.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "vsegment.hpp"
#include "OFexception.hpp"
#include <liboffsetfinder64/libgeneral/macros.h>

using namespace tihmstar::offsetfinder64;


vsegment::vsegment(const void *buf, size_t size, loc_t vaddr, int perms) : _buf((const uint8_t*)buf), _size(size), _vaddr(vaddr), _perms(perms),_curpos(0)
{
    //
}


vsegment::vsegment(const vsegment &cpy) : _buf(cpy._buf), _size(cpy._size), _vaddr(cpy._vaddr), _perms(cpy._perms),_curpos(cpy._curpos)
{
    //
}

vsegment::vsegment(const vsegment &cpy, loc_t pos) : _buf(cpy._buf), _size(cpy._size), _vaddr(cpy._vaddr), _perms(cpy._perms),_curpos(0)
{
    assure(isInRange(pos));
    _curpos = pos - _vaddr;
}


bool vsegment::isInRange(loc_t p){
    return (p - _vaddr) < _size;
}

loc_t vsegment::memmem(const void *little, size_t little_len){
    loc_t rt = 0;
    if ((rt = (loc_t)::memmem(_buf, _size, little, little_len))) {
        rt = rt - (loc_t)_buf + _vaddr;
    }
    return rt;
}

#pragma mark iterator operator

insn vsegment::operator+(int i){
    if (i<0) return this->operator-(-i);
    retcustomassure(_curpos + 4*i < _size-4, out_of_range, "overflow");
    return vsegment(*this,_curpos+4*i).getinsn();
}

insn vsegment::operator-(int i){
    if (i<0) return this->operator+(-i);
    retcustomassure(_curpos >= 4*i, out_of_range, "underflow");
    return vsegment(*this,_curpos-4*i).getinsn();
}

insn vsegment::operator++(){
    retcustomassure(_curpos + 4 < _size-4, out_of_range, "overflow");
    _curpos+=4;
    return getinsn();
}

insn vsegment::operator--(){
    retcustomassure(_curpos >= 4, out_of_range, "underflow");
    _curpos-=4;
    return getinsn();
}

vsegment &vsegment::operator+=(int i){
    if (i<0) return this->operator-=(-i);
    retcustomassure(_curpos + 4*i < _size-4, out_of_range, "overflow");
    _curpos+=4*i;
    return *this;
}

vsegment &vsegment::operator-=(int i){
    if (i<0) return this->operator+=(-i);
    retcustomassure(_curpos >= 4*i, out_of_range, "underflow");
    _curpos-=4*i;
    return *this;
}

vsegment &vsegment::operator=(loc_t p){
    if (p == 0){
        _curpos = 0;
    }else{
        offset_t newPos = p-_vaddr;
        retcustomassure(newPos < _size-4 , out_of_range, "underflow");
        _curpos = newPos;
    }
    return *this;
}

#pragma mark deref operator

uint64_t vsegment::pc(){
    return (uint64_t)(_vaddr+_curpos);
}

uint32_t vsegment::value(loc_t p){
    offset_t off = (p - _vaddr);
    customassure(off < _size, out_of_range); //check for off being at least 1 byte
    if (off <= _size-4) {
        return *(uint32_t*)(_buf+(offset_t)(p-_vaddr));
    }
    
    //size is smaller than 4 bytes
    uint32_t ret = 0;
    for (int i=1; i<=_size-off; i++) {
        ret <<= 8;
        ret |= _buf[_size-i];
    }
    return ret;
}

uint64_t vsegment::doublevalue(loc_t p){
    offset_t off = (p - _vaddr);
    customassure(off < _size, out_of_range); //check for off being at least 1 byte
    if (off <= _size-8) {
        return *(uint64_t*)(_buf+(offset_t)(p-_vaddr));
    }
    
    //size is smaller than 8 bytes
    uint64_t ret = 0;
    for (int i=1; i<=_size-off; i++) {
        ret <<= 8;
        ret |= _buf[_size-i];
    }
    return ret;
}

uint32_t vsegment::value(){
    return *(uint32_t*)(_buf+_curpos);
}

uint64_t vsegment::doublevalue(){
    if (_curpos <= _size-8) {
        return *(uint64_t*)(_buf+_curpos);
    }
    return value();
}

#pragma mark insn operator

insn vsegment::getinsn(){
    return ::insn(value(),pc());
}

insn vsegment::operator()(){
    return ::insn(value(),pc());
}

vsegment::operator loc_t(){
    return (loc_t)pc();
}
