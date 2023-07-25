//
//  patchfinder.cpp
//  libpatchfinder
//
//  Created by erd on 29.06.23.
//

#include "../include/libpatchfinder/patchfinder.hpp"
#include <libgeneral/macros.h>

using namespace tihmstar::patchfinder;

#pragma mark constructor/destructor

patchfinder::patchfinder(bool freeBuf) :
    _freeBuf(freeBuf),
    _buf(NULL),
    _bufSize(0),
    _entrypoint(0),
    _base(0)
{
    //
}

patchfinder::patchfinder(tihmstar::patchfinder::patchfinder &&mv) :
    _freeBuf(mv._freeBuf),
    _buf(mv._buf),
    _bufSize(mv._bufSize),
    _entrypoint(mv._entrypoint),
    _base(mv._base)
{
    mv._freeBuf = false; //if we take ownership, the old object should no longer free the buffer
}

patchfinder::~patchfinder(){
    if (_freeBuf) safeFreeConst(_buf);
}

const void *patchfinder::buf() {
    return _buf;
}

size_t patchfinder::bufSize() {
    return _bufSize;
}

patchfinder::loc_t patchfinder::find_entry() {
    return _entrypoint;
}

patchfinder::loc_t patchfinder::find_base() {
    return _base;
}

#pragma mark no-provider
const void *patchfinder::memoryForLoc(loc_t loc){
    FAIL_UNIMPLEMENTED;
}


patchfinder::loc_t patchfinder::findstr(std::string str, bool hasNullTerminator, loc_t startAddr){
    FAIL_UNIMPLEMENTED;
}

patchfinder::loc_t patchfinder::find_bof(loc_t pos, bool mayLackPrologue){
    FAIL_UNIMPLEMENTED;
}


uint64_t patchfinder::find_register_value(loc_t where, int reg, loc_t startAddr){
    FAIL_UNIMPLEMENTED;
}

patchfinder::loc_t patchfinder::find_literal_ref(loc_t pos, int ignoreTimes, loc_t startPos){
    FAIL_UNIMPLEMENTED;
}

patchfinder::loc_t patchfinder::find_call_ref(loc_t pos, int ignoreTimes, loc_t startPos){
    FAIL_UNIMPLEMENTED;
}


patchfinder::loc_t patchfinder::find_branch_ref(loc_t pos, int limit, int ignoreTimes, loc_t startPos){
    FAIL_UNIMPLEMENTED;
}

patchfinder::loc_t patchfinder::findnops(uint16_t nopCnt, bool useNops, uint32_t nopOpcode){
    FAIL_UNIMPLEMENTED;
}

patchfinder::loc_t patchfinder::memmem(const void *little, size_t little_len, patchfinder::loc_t startLoc) const{
    FAIL_UNIMPLEMENTED;
}

patchfinder::loc_t patchfinder::memstr(const char *str) const{
    FAIL_UNIMPLEMENTED;
}

patchfinder::loc_t patchfinder::deref(patchfinder::loc_t pos) const{
    FAIL_UNIMPLEMENTED;
}

#pragma mark provider


std::vector<patch> patchfinder::get_replace_string_patch(std::string needle, std::string replacement){
    std::vector<patch> patches;

    retassure(needle.size() == replacement.size(), "needle.size() != replacement.size()");

    loc_t curloc = -1;

    try {
        while (true) {
            curloc = memmem(needle.data(), needle.size(), curloc+1);
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


#pragma mark static
void patchfinder::patchfinder::fail_unimplemented(void){
    reterror("not implemented by provider");
}

