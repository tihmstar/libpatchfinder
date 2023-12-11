//
//  patch.cpp
//  libpatchfinder
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include "../include/libpatchfinder/patch.hpp"
#include <libgeneral/macros.h>

#include <string.h>

using namespace tihmstar::patchfinder;

patch::patch(uint64_t location, const void *patch, size_t patchSize, void(*slidefunc)(class patch *patch, uint64_t slide), bool dofree)
: _location(location), _patchSize(patchSize), _slidefunc(slidefunc), _dofree(dofree)
{
    _patch = malloc(_patchSize);
    memcpy((void*)_patch, patch, _patchSize);
    _slideme = (_slidefunc) ? true : false;
}

patch::patch(const patch& cpy) noexcept : _location(cpy._location), _patchSize(cpy._patchSize){
    _patch = malloc(_patchSize);
    memcpy((void*)_patch, cpy._patch, _patchSize);
    _slidefunc = cpy._slidefunc;
    _slideme = cpy._slideme;
}

patch::~patch(){
    if (_dofree) safeFreeConst(_patch);
}

patch &patch::operator=(const patch& cpy){
    _location = cpy._location;
    _patchSize = cpy._patchSize;
    _patch = malloc(_patchSize);
    memcpy((void*)_patch, cpy._patch, _patchSize);
    _slidefunc = cpy._slidefunc;
    _slideme = cpy._slideme;
    return *this;
}

void patch::slide(uint64_t slide){
    if (!_slideme)
        return;
    debug("sliding with 0x%016llx\n",slide);
    _slidefunc(this,slide);
    _slideme = false; //only slide once
}

