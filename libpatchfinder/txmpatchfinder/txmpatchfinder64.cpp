//
//  txmpatchfinder64.cpp
//  libpatchfinder
//
//  Created by erd on 13.10.26.
//

#include <libgeneral/macros.h>

#include "../../include/libpatchfinder/txmpatchfinder/txmpatchfinder64.hpp"
#include "txmpatchfinder64_base.hpp"


using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;


txmpatchfinder64 *txmpatchfinder64::make_txmpatchfinder64(machopatchfinder64 &&mv){
    txmpatchfinder64 helper(std::move(mv));
    
    std::string version = helper.get_txm_version_number_string();
    info("txm version: %s",version.c_str());
    /*
        iPhone 12,1 iOS 27.0 txm version: 217.0.2
     */
    return new txmpatchfinder64_base(std::move(helper));
}

txmpatchfinder64::~txmpatchfinder64(){
    //
}

const void *txmpatchfinder64::memoryForLoc(loc64_t loc){
    return patchfinder64::memoryForLoc(loc);
}

std::vector<patch> txmpatchfinder64::get_replace_string_patch(std::string needle, std::string replacement){
    return patchfinder64::get_replace_string_patch(needle, replacement);
}

std::string txmpatchfinder64::get_txm_version_number_string(){
    return machopatchfinder64::get_source_version_string();
}

txmpatchfinder64 *txmpatchfinder64::make_txmpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership){
    return make_txmpatchfinder64(machopatchfinder64(buffer, bufSize, takeOwnership));
}

txmpatchfinder64 *txmpatchfinder64::make_txmpatchfinder64(const char *filename){
    return make_txmpatchfinder64(machopatchfinder64(filename));
}


txmpatchfinder64::txmpatchfinder64(machopatchfinder64 &&mv)
    : machopatchfinder64(std::move(mv))
{
    //
}

txmpatchfinder64::txmpatchfinder64(txmpatchfinder64 &&mv)
: machopatchfinder64(std::move(mv))
{
    //
}

txmpatchfinder64::txmpatchfinder64(const char *filename)
: machopatchfinder64(filename)
{
    //
}

txmpatchfinder64::txmpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership)
: machopatchfinder64(buffer, bufSize, takeOwnership)
{
    //
}
