//
//  kernelpatchfinder32.cpp
//  libpatchfinder
//
//  Created by tihmstar on 09.07.21.
//
#include <libgeneral/macros.h>

#include "../../include/libpatchfinder/kernelpatchfinder/kernelpatchfinder32.hpp"
#include "kernelpatchfinder32_base.hpp"
#include "kernelpatchfinder32_iOS3.hpp"
#include "kernelpatchfinder32_iOS4.hpp"
#include "kernelpatchfinder32_iOS5.hpp"
#include "kernelpatchfinder32_iOS6.hpp"
#include "kernelpatchfinder32_iOS9.hpp"
#include "kernelpatchfinder32_iOS11.hpp"

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;


kernelpatchfinder32 *kernelpatchfinder32::make_kernelpatchfinder32(machopatchfinder32 &&mv){
    kernelpatchfinder32 helper(std::move(mv));
    
    std::string version = helper.get_xnu_kernel_version_number_string();
    info("Kernel version: %s",version.c_str());
    uint32_t vers = atoi(version.c_str());

    if (vers > 4000) {
        info("Detected iOS 11 kernel");
        return new kernelpatchfinder32_iOS11(std::move(helper));
    } else if (vers > 3200) {
        info("Detected iOS 9 kernel");
        return new kernelpatchfinder32_iOS9(std::move(helper));
    } else if (vers > 2100) {
        info("Detected iOS 6 kernel");
        return new kernelpatchfinder32_iOS6(std::move(helper));
    } else if (vers > 1800) {
        info("Detected iOS 5 kernel");
        return new kernelpatchfinder32_iOS5(std::move(helper));
    } else if (vers > 1504) { //root:xnu-1504.51.1
        info("Detected iOS 4 kernel");
        return new kernelpatchfinder32_iOS4(std::move(helper));
    } else if (vers > 1300) {
        info("Detected iOS 3 kernel");
        return new kernelpatchfinder32_iOS3(std::move(helper));
    }

    return new kernelpatchfinder32_base(std::move(helper));
}

kernelpatchfinder32::~kernelpatchfinder32(){
    //
}

std::vector<patch> kernelpatchfinder32::get_replace_string_patch(std::string needle, std::string replacement){
    return patchfinder32::get_replace_string_patch(needle, replacement);
}

uint32_t kernelpatchfinder32::get_cpid(){
    loc_t release_uname_str = findstr("RELEASE_ARM_", false);
    debug("release_uname_str=0x%08x",release_uname_str);
    const char *release_uname_str_ptr = (const char*)memoryForLoc(release_uname_str);
    release_uname_str_ptr+=sizeof("RELEASE_ARM_")-1;
    while (*release_uname_str_ptr && isalpha(*release_uname_str_ptr)) release_uname_str_ptr++;
    
    uint32_t cpid = strtoul(release_uname_str_ptr, NULL, 16);
    return cpid;
}

std::string kernelpatchfinder32::get_xnu_kernel_version_number_string(){
    loc_t kernel_version_number = findstr("root:xnu-", false);
    debug("kernel_version_number=0x%016llx",kernel_version_number);
    
    const char *mem = (const char *)memoryForLoc(kernel_version_number);
    std::string ret;
    mem+= sizeof("root:xnu-")-1;
    while (*mem && *mem != '/') ret += *mem++;

    return ret;
}

std::string kernelpatchfinder32::get_kernel_version_string(){
    loc_t kerneluname = findstr("Darwin Kernel Version", false);
    debug("kerneluname=0x%016llx",kerneluname);
    
    const char *mem = (const char *)memoryForLoc(kerneluname);
    return mem;
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
