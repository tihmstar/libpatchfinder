//
//  machopatchfinder64.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "machopatchfinder64.hpp"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <libgeneral/macros.h>
#ifdef HAVE_IMG4TOOL
#include <img4tool/img4tool.hpp>
#endif //HAVE_IMG4TOOL

using namespace tihmstar::offsetfinder64;

#pragma mark macho external

__attribute__((always_inline)) struct load_command *find_load_command64(struct mach_header_64 *mh, uint32_t lc){
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == lc)
            return lcmd;
    }
    
    retcustomerror(load_command_not_found, lc);
    return NULL;
}

__attribute__((always_inline)) struct symtab_command *find_symtab_command(struct mach_header_64 *mh){
    return (struct symtab_command *)find_load_command64(mh, LC_SYMTAB);
}

__attribute__((always_inline)) struct dysymtab_command *find_dysymtab_command(struct mach_header_64 *mh){
    return (struct dysymtab_command *)find_load_command64(mh, LC_DYSYMTAB);
}

__attribute__((always_inline)) struct section_64 *find_section(struct segment_command_64 *seg, const char *sectname){
    struct section_64 *sect = (struct section_64 *)(seg + 1);
    for (uint32_t i=0; i<seg->nsects; i++, sect++) {
        if (strcmp(sect->sectname, sectname) == 0)
            return sect;
    }
    reterror("Failed to find section %s", sectname);
    return NULL;
}

#pragma mark macho local

__attribute__((always_inline)) struct symtab_command *machopatchfinder64::getSymtab(){
    if (!__symtab){
        try {
            __symtab = find_symtab_command((struct mach_header_64 *)_buf);
        } catch (tihmstar::load_command_not_found &e) {
            if (e.cmd() != LC_SYMTAB)
                throw;
            retcustomerror(symtab_not_found, "symtab not found. Is this a dumped kernel?");
        }
    }
    return __symtab;
}

void machopatchfinder64::loadSegments(){
    std::vector<offsetfinder64::vsegment> segments;
    struct mach_header_64 *mh = (struct mach_header_64*)_buf;
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == LC_SEGMENT_64){
            struct segment_command_64* seg = (struct segment_command_64*)lcmd;
            segments.push_back({_buf+seg->fileoff,seg->filesize, (loc_t)seg->vmaddr, seg->maxprot});
            if (i==0){
                _base = (loc_t)seg->vmaddr; //first segment is base. Is this correct??
            }
        }
        if (lcmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(lcmd + 1);
            uint32_t flavor = ptr[0];
            struct _tread{
                uint64_t x[29];    /* General purpose registers x0-x28 */
                uint64_t fp;    /* Frame pointer x29 */
                uint64_t lr;    /* Link register x30 */
                uint64_t sp;    /* Stack pointer x31 */
                uint64_t pc;     /* Program counter */
                uint32_t cpsr;    /* Current program status register */
            } *thread = (struct _tread*)(ptr + 2);
            if (flavor == 6) {
                _entrypoint = (offsetfinder64::loc_t)(thread->pc);
            }
        }
    }
    _vmem = new vmem(segments,0);
    
    try {
        _vmem->deref(_entrypoint);
        info("Detected non-slid kernel.");
    } catch (tihmstar::out_of_range &e) {
#warning TODO
        reterror("Detected slid kernel. but slid kernel is currently not supported");
        //        info("Detected slid kernel. Using kernelslide=%p",(void*)_kslide);
        //        _kernel_entry += _kslide;
        //        _kernelIsSlid = true;
    }
    try {
        _vmem->deref(_entrypoint);
    } catch (tihmstar::out_of_range &e) {
        reterror("Error occured when handling kernel entry checks");
    }
    
    info("Inited offsetfinder64 %s %s",VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA);
    try {
        getSymtab();
    } catch (tihmstar::symtab_not_found &e) {
        info("Symtab not found. Assuming we are operating on a dumped kernel");
    }
    printf("\n");
}

machopatchfinder64::machopatchfinder64(const char *filename) :
    patchfinder64(true),
    __symtab(NULL)
{
    struct stat fs = {0};
    int fd = 0;
    bool didConstructSuccessfully = false;
#ifdef HAVE_IMG4TOOL
    img4tool::ASN1DERElement *img4tmp = NULL;
#endif //HAVE_IMG4TOOL
    cleanup([&]{
        if (fd>0) close(fd);
        if (!didConstructSuccessfully) {
            safeFreeConst(_buf);
        }
#ifdef HAVE_IMG4TOOL
        if (img4tmp) {
            delete img4tmp;
        }
#endif //HAVE_IMG4TOOL
    })
    
    assure((fd = open(filename, O_RDONLY)) != -1);
    assure(!fstat(fd, &fs));
    assure((_buf = (uint8_t*)malloc( _bufSize = fs.st_size)));
    assure(read(fd,(void*)_buf,_bufSize)==_bufSize);
    
    
#ifdef HAVE_IMG4TOOL
    //check if feedfacf, fat, compressed (lzfse/lzss), img4, im4p
    try {
        img4tmp = new img4tool::ASN1DERElement(_buf,_bufSize);
    } catch (...) {
        //
    }
    if (img4tmp) {
        if (img4tool::isIMG4(*img4tmp)) {
            *img4tmp = img4tool::getIM4PFromIMG4(*img4tmp);
        }
        if (img4tool::isIM4P(*img4tmp)) {
            *img4tmp = img4tool::getPayloadFromIM4P(*img4tmp);
            
            assure(img4tmp->ownsBuffer());
            free((void*)_buf);
            
            assure(_buf = (uint8_t*)malloc(_bufSize = img4tmp->size()));
            memcpy((void*)_buf, img4tmp->buf(), _bufSize);
        }
    }
#else
    printf("Warning: compiled without img4tool, extracting from IMG4/IM4P disabled!\n");
#endif //HAVE_IMG4TOOL
    
    if (*(uint32_t*)_buf == 0xbebafeca || *(uint32_t*)_buf == 0xcafebabe) {
        bool swap = *(uint32_t*)_buf == 0xbebafeca;
    
        uint8_t* tryfat = [=]() -> uint8_t* {
            // just select first slice
            uint32_t* kdata32 = (uint32_t*) _buf;
            uint32_t narch = kdata32[1];
            if (swap) narch = ntohl(narch);
    
            if (narch != 1) {
                printf("expected 1 arch in fat file, got %u\n", narch);
                return NULL;
            }
    
            uint32_t offset = kdata32[2 + 2];
            if (swap) offset = ntohl(offset);
    
            if (offset != sizeof(uint32_t)*(2 + 5)) {
                printf("wat, file offset not sizeof(fat_header) + sizeof(fat_arch)?!\n");
            }
    
            uint32_t filesize = kdata32[2 + 3];
            if (swap) filesize = ntohl(filesize);
    
            uint8_t *ret = (uint8_t*) malloc(filesize);
            if (ret != NULL) {
                memcpy(ret, _buf + offset, filesize);
            }
            return ret;
        }();
    
        if (tryfat) {
            printf("got fat macho with first slice at %u\n", (uint32_t) (tryfat - _buf));
            free((void*)_buf);
            _buf = tryfat;tryfat = NULL;
        } else {
            printf("got fat macho but failed to parse\n");
        }
    }
    
    assure(*(uint32_t*)_buf == 0xfeedfacf);
    
    loadSegments();
    didConstructSuccessfully = true;
}



loc_t machopatchfinder64::find_sym(const char *sym){
    const uint8_t *psymtab = _buf + getSymtab()->symoff;
    const uint8_t *pstrtab = _buf + getSymtab()->stroff;
    
    struct nlist_64 *entry = (struct nlist_64 *)psymtab;
    for (uint32_t i = 0; i < getSymtab()->nsyms; i++, entry++)
        if (!strcmp(sym, (char*)(pstrtab + entry->n_un.n_strx)))
            return (loc_t)entry->n_value;
    
    retcustomerror(symbol_not_found,sym);
    return 0;//never reached
}
