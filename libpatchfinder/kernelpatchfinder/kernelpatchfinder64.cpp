//
//  kernelpatchfinder64.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//
#include <libgeneral/macros.h>

#include "../../include/libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp"
#include "kernelpatchfinder64_base.hpp"
#include "kernelpatchfinder64_iOS8.hpp"
#include "kernelpatchfinder64_iOS9.hpp"
#include "kernelpatchfinder64_iOS12.hpp"
#include "kernelpatchfinder64_iOS13.hpp"
#include "kernelpatchfinder64_iOS15.hpp"
#include "kernelpatchfinder64_iOS16.hpp"
#include "kernelpatchfinder64_iOS17.hpp"
#include "kernelpatchfinder64_iOS18.hpp"
#include "kernelpatchfinder64_iOS26.hpp"
#include "kernelpatchfinder64_iOS27.hpp"

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;


kernelpatchfinder64 *kernelpatchfinder64::make_kernelpatchfinder64(machopatchfinder64 &&mv){
    kernelpatchfinder64 helper(std::move(mv));
    
    std::string version = helper.get_xnu_kernel_version_number_string();
    info("Kernel version: %s",version.c_str());
    uint32_t vers = atoi(version.c_str());

    if (vers > 13400) {
        info("Detected iOS 27 kernel");
        return new kernelpatchfinder64_iOS27(std::move(helper));
    }else if (vers > 12300) {
        info("Detected iOS 26 kernel");
        return new kernelpatchfinder64_iOS26(std::move(helper));
    }else if (vers > 11200) {
        info("Detected iOS 18 kernel");
        return new kernelpatchfinder64_iOS18(std::move(helper));
    }else if (vers > 10000) {
        info("Detected iOS 17 kernel");
        return new kernelpatchfinder64_iOS17(std::move(helper));
    }else if (vers > 8700) {
        info("Detected iOS 16 kernel");
        return new kernelpatchfinder64_iOS16(std::move(helper));
    }else if (vers > 8000) {
        info("Detected iOS 15 kernel");
        return new kernelpatchfinder64_iOS15(std::move(helper));
    }else if (vers > 6150) {
        info("Detected iOS 13 kernel");
        return new kernelpatchfinder64_iOS13(std::move(helper));
    }else if (vers > 4900) {
        info("Detected iOS 12 kernel");
        return new kernelpatchfinder64_iOS12(std::move(helper));
    }else if (vers > 3200) {
        info("Detected iOS 9 kernel");
        return new kernelpatchfinder64_iOS9(std::move(helper));
    }else if (vers > 2700) {
        info("Detected iOS 8 kernel");
        return new kernelpatchfinder64_iOS8(std::move(helper));
    }

    return new kernelpatchfinder64_base(std::move(helper));
}

kernelpatchfinder64::~kernelpatchfinder64(){
    //
}

uint32_t kernelpatchfinder64::get_cpid(){
    loc_t release_uname_str = findstr("RELEASE_ARM64_", false);
    debug("release_uname_str=0x%016llx",release_uname_str);
    const char *release_uname_str_ptr = (const char*)_vmem->memoryForLoc(release_uname_str);
    release_uname_str_ptr+=sizeof("RELEASE_ARM64_")-1;
    while (*release_uname_str_ptr && isalpha(*release_uname_str_ptr)) release_uname_str_ptr++;
    
    uint32_t cpid = strtoul(release_uname_str_ptr, NULL, 16);
    return cpid;
}

std::string kernelpatchfinder64::get_xnu_kernel_version_number_string(){
    patchfinder64::loc_t kernel_version_number = findstr("root:xnu-", false);
    debug("kernel_version_number=0x%016llx",kernel_version_number);
    
    const char *mem = (const char *)memoryForLoc(kernel_version_number);
    std::string ret;
    mem+= sizeof("root:xnu-")-1;
    while (*mem && *mem != '/') ret += *mem++;

    return ret;
}

std::string kernelpatchfinder64::get_kernel_version_string(){
    patchfinder64::loc_t kerneluname = findstr("Darwin Kernel Version", false);
    debug("kerneluname=0x%016llx",kerneluname);
    
    const char *mem = (const char *)memoryForLoc(kerneluname);
    return mem;
}

const void *kernelpatchfinder64::memoryForLoc(loc64_t loc){
    return patchfinder64::memoryForLoc(loc);
}

std::vector<patch> kernelpatchfinder64::get_replace_string_patch(std::string needle, std::string replacement){
    return patchfinder64::get_replace_string_patch(needle, replacement);
}

kernelpatchfinder64 *kernelpatchfinder64::make_kernelpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership){
    return make_kernelpatchfinder64(machopatchfinder64(buffer, bufSize, takeOwnership));
}

kernelpatchfinder64 *kernelpatchfinder64::make_kernelpatchfinder64(const char *filename){
    return make_kernelpatchfinder64(machopatchfinder64(filename));
}



kernelpatchfinder64::kernelpatchfinder64(machopatchfinder64 &&mv)
    : machopatchfinder64(std::move(mv))
{
    //
}

kernelpatchfinder64::kernelpatchfinder64(kernelpatchfinder64 &&mv)
: machopatchfinder64(std::move(mv))
{
    _unusedBSS = mv._unusedBSS;
}

kernelpatchfinder64::kernelpatchfinder64(const char *filename)
: machopatchfinder64(filename)
{
    //
}

kernelpatchfinder64::kernelpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership)
: machopatchfinder64(buffer, bufSize, takeOwnership)
{
    //
}
