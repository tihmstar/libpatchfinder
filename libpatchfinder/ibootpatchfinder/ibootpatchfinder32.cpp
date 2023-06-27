//
//  ibootpatchfinder32.cpp
//  libpatchfinder
//
//  Created by tihmstar on 07.07.21.
//

#include "../../include/libpatchfinder/ibootpatchfinder/ibootpatchfinder32.hpp"
#include "ibootpatchfinder32_base.hpp"
#include "ibootpatchfinder32_iOS5.hpp"
#include "ibootpatchfinder32_iOS11.hpp"
#include "ibootpatchfinder32_iOS12.hpp"
#include "ibootpatchfinder32_iOS13.hpp"
#include <string.h>

#ifndef HAVE_MEMMEM
static void *memmem(const void *haystack_start, size_t haystack_len, const void *needle_start, size_t needle_len){
    const unsigned char *haystack = (const unsigned char *)haystack_start;
    const unsigned char *needle = (const unsigned char *)needle_start;
    const unsigned char *h = NULL;
    const unsigned char *n = NULL;
    size_t x = needle_len;
    
    /* The first occurrence of the empty string is deemed to occur at
     the beginning of the string.  */
    if (needle_len == 0) {
        return (void *)haystack_start;
    }
    
    /* Sanity check, otherwise the loop might search through the whole
     memory.  */
    if (haystack_len < needle_len) {
        return NULL;
    }
    
    for (; *haystack && haystack_len--; haystack++) {
        x = needle_len;
        n = needle;
        h = haystack;
        
        if (haystack_len < needle_len)
            break;
        
        if ((*haystack != *needle) || (*haystack + needle_len != *needle + needle_len))
            continue;
        
        for (; x; h++, n++) {
            x--;
            
            if (*h != *n)
                break;
            
            if (x == 0)
                return (void *)haystack;
        }
    }
    return NULL;
}
#endif

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;

#define IBOOT_VERS_STR_OFFSET 0x280
#define IBOOT32_RESET_VECTOR_BYTES 0xEA00000E

ibootpatchfinder32::ibootpatchfinder32(bool freeBuf)
: patchfinder32(freeBuf)
{
    //
}

ibootpatchfinder32 *ibootpatchfinder32::make_ibootpatchfinder32(const char * filename){
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
    

    auto ret = make_ibootpatchfinder32(buf, bufSize, true);
    didConstructSuccessfully = true;
    return ret;
}

ibootpatchfinder32 *ibootpatchfinder32::make_ibootpatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership){
    uint8_t *buf = NULL;
    uint32_t vers = 0;

    buf = (uint8_t*)buffer;
    assure(bufSize > 0x1000);
    
    retassure(*(uint32_t*)&buf[0] == IBOOT32_RESET_VECTOR_BYTES, "invalid magic");
    if (!strncmp((char*)&buf[IBOOT_VERS_STR_OFFSET], "iBoot", sizeof("iBoot")-1)){
        retassure(vers = atoi((char*)&buf[IBOOT_VERS_STR_OFFSET+6]), "No iBoot version found!\n");
    }else{
        //iOS 1 iBoot??
        const char *ibootstr = (char*)memmem(buf, bufSize, "iBoot-", sizeof("iBoot-")-1);
        retassure(ibootstr, "No iBoot version found!\n");
        retassure(vers = atoi(ibootstr+6), "No iBoot version found!\n");
    }
    debug("iBoot-%d inputted\n", vers);

    if (vers >= 5000) {
        info("iOS 13 iBoot detected!");
        return new ibootpatchfinder32_iOS13(buf,bufSize,takeOwnership);
    } else if (vers >= 4510) {
        info("iOS 12 iBoot detected!");
        return new ibootpatchfinder32_iOS12(buf,bufSize,takeOwnership);
    } else if (vers >= 4000) {
        info("iOS 11 iBoot detected!");
        return new ibootpatchfinder32_iOS11(buf,bufSize,takeOwnership);
    } else if (vers >= 1200) {
        info("iOS 5 iBoot detected!");
        return new ibootpatchfinder32_iOS5(buf,bufSize,takeOwnership);
    }

    return new ibootpatchfinder32_base(buf,bufSize,takeOwnership);
}

ibootpatchfinder32::~ibootpatchfinder32(){
    //
}

//ibootpatchfinder32::loc_t ibootpatchfinder32::findnops(uint16_t nopCnt, bool useNops, uint32_t nopOpcode){
//    if (_unusedNops.size() == 0) {
//        patchfinder32::findnops(nopCnt,false,nopOpcode);
//        
//        loc_t strsection = findstr("Apple Mobile Device", false) & ~3;
//        loc_t end_of_code = find_bof(strsection,true);
//        for (int i=0; i<_unusedNops.size(); i++) {
//            auto e = _unusedNops.at(i);
//            if (e.first > end_of_code) {
//                _unusedNops.erase(_unusedNops.begin() + i);
//                i--;
//            }
//        }
//    }
//    
//    return patchfinder32::findnops(nopCnt,useNops,nopOpcode);
//}

ibootpatchfinder::loc64_t ibootpatchfinder32::find_base(){
    return patchfinder32::find_base();
}

std::vector<patch> ibootpatchfinder32::get_replace_string_patch(std::string needle, std::string replacement){
    return patchfinder32::get_replace_string_patch(needle, replacement);
}
