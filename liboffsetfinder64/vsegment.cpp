//
//  vmem.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "vmem.hpp"
#include "OFexception.hpp"
#include <libgeneral/macros.h>

using namespace tihmstar::offsetfinder64;


vmem::vmem(void *buf, size_t size, loc_t vaddr, int perms) : _buf((uint8_t*)buf), _size(size), _vaddr(vaddr), _perms(perms),_curpos(0)
{
    //
}


vmem::vmem(const vmem &cpy) : _buf(cpy._buf), _size(cpy._size), _vaddr(cpy._vaddr), _perms(cpy._perms),_curpos(cpy._curpos)
{
    //
}

vmem::vmem(const vmem &cpy, offset_t curpos) : _buf(cpy._buf), _size(cpy._size), _vaddr(cpy._vaddr), _perms(cpy._perms),_curpos(curpos)
{
    //
}

bool vmem::isInRange(loc_t p){
    return (p - _vaddr) < _size;
}

loc_t vmem::memmem(const void *little, size_t little_len){
    loc_t rt = NULL;
    if ((rt = (loc_t)::memmem(_buf, _size, little, little_len))) {
        rt = rt - _buf + _vaddr;
    }
    return rt;
}

#pragma mark iterator operator

vmem vmem::operator+(int i){
    retcustomassure(_curpos + 4*i < _size-4, out_of_range, "overflow");
    return vmem(*this,_curpos+4*i);
}

vmem vmem::operator-(int i){
    retcustomassure(_curpos >= 4*i, out_of_range, "underflow");
    return vmem(*this,_curpos-4*i);
}

vmem &vmem::operator++(){
    retcustomassure(_curpos + 4 < _size-4, out_of_range, "overflow");
    _curpos+=4;
    return *this;
}

vmem &vmem::operator--(){
    retcustomassure(_curpos >= 4, out_of_range, "underflow");
    _curpos-=4;
    return *this;
}

vmem &vmem::operator+=(int i){
    retcustomassure(_curpos + 4*i < _size-4, out_of_range, "overflow");
    _curpos+=4*i;
    return *this;
}

vmem &vmem::operator-=(int i){
    retcustomassure(_curpos >= 4*i, out_of_range, "underflow");
    _curpos-=4*i;
    return *this;
}

vmem &vmem::operator=(loc_t p){
    offset_t newPos = p-_vaddr;
    retcustomassure(newPos < _size-4 , out_of_range, "underflow");
    _curpos = newPos;
    return *this;
}

#pragma mark deref operator

uint64_t vmem::pc(){
    return (uint64_t)(_vaddr+_curpos);
}

uint32_t vmem::value(loc_t p){
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

uint64_t vmem::doublevalue(loc_t p){
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

uint32_t vmem::value(){
    return *(uint32_t*)(_buf+_curpos);
}

uint64_t vmem::doublevalue(){
    if (_curpos <= _size-8) {
        return *(uint64_t*)(_buf+_curpos);
    }
    return value();
}

#pragma mark insn operator

vmem::operator insn(){
    return insn(value(),pc());
}
