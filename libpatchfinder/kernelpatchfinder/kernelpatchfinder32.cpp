//
//  kernelpatchfinder32.cpp
//  libpatchfinder
//
//  Created by tihmstar on 09.07.21.
//

#include "../../include/libpatchfinder/kernelpatchfinder/kernelpatchfinder32.hpp"
#include "kernelpatchfinder32_base.hpp"
#include "kernelpatchfinder32_iOS6.hpp"
#include "kernelpatchfinder32_iOS9.hpp"
#include "kernelpatchfinder32_iOS11.hpp"

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;


kernelpatchfinder32 *kernelpatchfinder32::make_kernelpatchfinder32(machopatchfinder32 &&mv){
    kernelpatchfinder32 helper(std::move(mv));
    
    std::string version = helper.get_xnu_kernel_version();
    info("Kernel version: %s",version.c_str());
    
    if (version > "4000") {
        info("Detected iOS 11 kernel");
        return new kernelpatchfinder32_iOS11(std::move(helper));
    } else if (version > "3200") {
        info("Detected iOS 9 kernel");
        return new kernelpatchfinder32_iOS9(std::move(helper));
    } else if (version > "2100") {
        info("Detected iOS 6 kernel");
        return new kernelpatchfinder32_iOS6(std::move(helper));
    }


    return new kernelpatchfinder32_base(std::move(helper));
}

std::vector<patch> kernelpatchfinder32::get_replace_string_patch(std::string needle, std::string replacement){
    return patchfinder32::get_replace_string_patch(needle, replacement);
}

std::string kernelpatchfinder32::get_xnu_kernel_version(){
    patchfinder32::loc_t kerneluname = findstr("root:xnu-", false);
    debug("kerneluname=0x%08x",kerneluname);
    
    const char *mem = (const char *)memoryForLoc(kerneluname);
    std::string ret;
    mem+= sizeof("root:xnu-")-1;
    while (*mem && *mem != '/') ret += *mem++;

    return ret;
}

const void *kernelpatchfinder32::memoryForLoc(loc64_t loc){
    return patchfinder32::memoryForLoc((loc_t)loc);
}

kernelpatchfinder32 *kernelpatchfinder32::make_kernelpatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership){
    return make_kernelpatchfinder32(machopatchfinder32(buffer, bufSize, takeOwnership));
}

kernelpatchfinder32 *kernelpatchfinder32::make_kernelpatchfinder32(const char *filename){
    return make_kernelpatchfinder32(machopatchfinder32(filename));
}



kernelpatchfinder32::kernelpatchfinder32(machopatchfinder32 &&mv)
    : machopatchfinder32(std::move(mv)), _syscall_entry_size(0)
{
    //
}

kernelpatchfinder32::kernelpatchfinder32(kernelpatchfinder32 &&mv)
: machopatchfinder32(std::move(mv)), _syscall_entry_size(mv._syscall_entry_size)
{
    _unusedBSS = mv._unusedBSS;
}

kernelpatchfinder32::kernelpatchfinder32(const char *filename)
: machopatchfinder32(filename), _syscall_entry_size(0)
{
    //
}

kernelpatchfinder32::kernelpatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership)
: machopatchfinder32(buffer, bufSize, takeOwnership), _syscall_entry_size(0)
{
    //
}

kernelpatchfinder32::~kernelpatchfinder32(){
    //
}
