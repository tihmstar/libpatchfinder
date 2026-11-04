//
//  txmpatchfinder.cpp
//  libpatchfinder
//
//  Created by erd on 13.10.26.
//

#include "../../include/libpatchfinder/txmpatchfinder/txmpatchfinder.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;

txmpatchfinder::~txmpatchfinder(){
    //
}

const void *txmpatchfinder::memoryForLoc(loc64_t loc){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> txmpatchfinder::get_replace_string_patch(std::string needle, std::string replacement){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> txmpatchfinder::get_codesignature_patches(){
    FAIL_UNIMPLEMENTED;
}
