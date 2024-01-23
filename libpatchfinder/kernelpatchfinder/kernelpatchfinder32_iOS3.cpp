//
//  kernelpatchfinder32_iOS3.cpp
//  libpatchfinder
//
//  Created by erd on 18.12.23.
//

#include "kernelpatchfinder32_iOS3.hpp"

#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;


std::vector<patch> kernelpatchfinder32_iOS3::get_codesignature_patches(){
    std::vector<patch> patches;
    addPatches(get_amfi_validateCodeDirectoryHashInDaemon_patch());
    addPatches(get_cs_enforcement_disable_amfi_patch());
    return patches;
}
