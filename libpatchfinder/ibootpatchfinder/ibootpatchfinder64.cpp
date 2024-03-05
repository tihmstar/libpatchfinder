//
//  ibootpatchfinder64.cpp
//  libpatchfinder
//
//  Created by tihmstar on 28.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include "../../include/libpatchfinder/ibootpatchfinder/ibootpatchfinder64.hpp"
#include "ibootpatchfinder64_base.hpp"
#include "ibootpatchfinder64_iOS9.hpp"
#include "ibootpatchfinder64_iOS10.hpp"
#include "ibootpatchfinder64_iOS12.hpp"
#include "ibootpatchfinder64_iOS13.hpp"
#include "ibootpatchfinder64_iOS14.hpp"
#include "ibootpatchfinder64_iOS15.hpp"
#include "ibootpatchfinder64_iOS16.hpp"
#include "ibootpatchfinder64_iOS17.hpp"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;

#define IBOOT_VERS_STR_OFFSET 0x280
#define iBOOT_BASE_OFFSET 0x318
#define iBOOT_14_BASE_OFFSET 0x300
#define KERNELCACHE_PREP_STRING "__PAGEZERO"
#define ENTERING_RECOVERY_CONSOLE "Entering recovery mode, starting command prompt"
#define DEBUG_ENABLED_DTRE_VAR_STR "debug-enabled"
#define DEFAULT_BOOTARGS_STR "rd=md0 nand-enable-reformat=1 -progress"
#define DEFAULT_BOOTARGS_STR_13 "rd=md0 -progress -restore"
#define CERT_STR "Apple Inc.1"

ibootpatchfinder64::ibootpatchfinder64(bool freeBuf)
: patchfinder64(freeBuf)
{
    //
}

ibootpatchfinder64::ibootpatchfinder64(ibootpatchfinder64 &&mv)
: patchfinder64(std::move(mv))
{
    _vers = mv._vers;
}

ibootpatchfinder64 *ibootpatchfinder64::make_ibootpatchfinder64(const char * filename){
    bool didConstructSuccessfully = false;
    int fd = 0;
    uint8_t *buf = NULL;
    cleanup([&]{
        if (fd>0) close(fd);
        if (!didConstructSuccessfully) {
            safeFreeConst(buf);
        }
    })
    struct stat fs = {0};
    size_t bufSize = 0;
    
    assure((fd = open(filename, O_RDONLY)) != -1);
    assure(!fstat(fd, &fs));
    assure((buf = (uint8_t*)malloc(bufSize = fs.st_size)));
    assure(read(fd,(void*)buf,bufSize)== bufSize);
    

    auto ret = make_ibootpatchfinder64(buf, bufSize, true);
    didConstructSuccessfully = true;
    return ret;
}

ibootpatchfinder64 *ibootpatchfinder64::make_ibootpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership){
    uint8_t *buf = NULL;
    uint32_t vers = 0;

    buf = (uint8_t*)buffer;
    assure(bufSize > 0x1000);
    
    assure(!strncmp((char*)&buf[IBOOT_VERS_STR_OFFSET], "iBoot", sizeof("iBoot")-1));
    retassure(*(uint32_t*)&buf[0] == 0x90000000
              || (((uint32_t*)buf)[0] == 0x14000001 && ((uint32_t*)buf)[4] == 0x90000000)
              || (((uint32_t*)buf)[0] == 0xD53C1102 && ((uint32_t*)buf)[3] == 0xD51C1102)
              , "invalid magic");

    retassure(vers = atoi((char*)&buf[IBOOT_VERS_STR_OFFSET+6]), "No iBoot version found!\n");
    debug("iBoot-%d inputted\n", vers);

    if (vers >= 10000) {
        printf("iOS 17 iBoot detected!\n");
        return new ibootpatchfinder64_iOS17(buf,bufSize,takeOwnership);
    }else if (vers >= 8400) {
        printf("iOS 16 iBoot detected!\n");
        return new ibootpatchfinder64_iOS16(buf,bufSize,takeOwnership);
    }else if (vers >= 7400) {
        printf("iOS 15 iBoot detected!\n");
        return new ibootpatchfinder64_iOS15(buf,bufSize,takeOwnership);
    }else if (vers >= 6603) {
        printf("iOS 14 iBoot detected!\n");
        return new ibootpatchfinder64_iOS14(buf,bufSize,takeOwnership);
    }else if (vers >= 5540) {
        printf("iOS 13 iBoot detected!\n");
        return new ibootpatchfinder64_iOS13(buf,bufSize,takeOwnership);
    }else if (vers >= 4510) {
        printf("iOS 12 iBoot detected!\n");
        return new ibootpatchfinder64_iOS12(buf,bufSize,takeOwnership);
    }else if (vers >= 3300) {
        printf("iOS 10 iBoot detected!\n");
        return new ibootpatchfinder64_iOS10(buf,bufSize,takeOwnership);
    }else if (vers >= 2800) {
        printf("iOS 9 iBoot detected!\n");
        return new ibootpatchfinder64_iOS9(buf,bufSize,takeOwnership);
    }else if (vers >= 1940) {
        printf("iOS 7 iBoot detected!\n");
        return new ibootpatchfinder64_iOS7(buf,bufSize,takeOwnership);
    }

    return new ibootpatchfinder64_base(buf,bufSize,takeOwnership);
}

ibootpatchfinder64::~ibootpatchfinder64(){
    //
}

ibootpatchfinder64::loc_t ibootpatchfinder64::findnops(uint16_t nopCnt, bool useNops, uint32_t nopOpcode){
    if (_unusedNops.size() == 0) {
        patchfinder64::findnops(nopCnt,false,nopOpcode);
        
        loc_t strsection = findstr("Apple Mobile Device", false) & ~3;
        loc_t end_of_code = find_bof(strsection, true);
        for (int i=0; i<_unusedNops.size(); i++) {
            auto e = _unusedNops.at(i);
            if (e.first > end_of_code) {
                _unusedNops.erase(_unusedNops.begin() + i);
                i--;
            }
        }
    }
    
    return patchfinder64::findnops(nopCnt,useNops,nopOpcode);
}

ibootpatchfinder::loc64_t ibootpatchfinder64::find_base(){
    return patchfinder64::find_base();
}

std::vector<patch> ibootpatchfinder64::get_replace_string_patch(std::string needle, std::string replacement){
    return patchfinder64::get_replace_string_patch(needle, replacement);
}
