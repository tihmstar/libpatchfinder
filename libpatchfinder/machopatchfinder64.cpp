//
//  machopatchfinder64.cpp
//  libpatchfinder
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef HAVE_IMG4TOOL
#include <img4tool/img4tool.hpp>
#endif //HAVE_IMG4TOOL

#include "../include/libpatchfinder/machopatchfinder64.hpp"

using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

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

__attribute__((always_inline)) const std::vector<std::pair<const struct symtab_command *,uint8_t *>> &machopatchfinder64::getSymtabs(){
    retcustomassure(symtab_not_found, __symtabs.size(), "symtab not found. Is this a dumped kernel?");
    return __symtabs;
}

std::vector<vsegment> machopatchfinder64::loadSegmentsForMachHeader(void *mh){
    std::vector<vsegment> segments;
    struct mach_header_64 *mhr = (struct mach_header_64*)mh;
    struct load_command *lcmd = (struct load_command *)(mhr + 1);
    bool has_text_exec = false;
    for (uint32_t i=0; i<mhr->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == LC_SEGMENT_64){
            struct segment_command_64* seg = (struct segment_command_64*)lcmd;
            if (seg->filesize == 0) {
                debug("ignoring segment '%s' with zero size",seg->segname);
                continue;
            }
            /*
             idk what this weird thing is, but a TEXT section is never writable o.O
             Note: this is iOS8 related issue
             */
            bool isWeirdPrelinkText = (strcmp(seg->segname, "__PRELINK_TEXT") == 0 && seg->maxprot == (kVMPROTREAD | kVMPROTWRITE));
            if (strcmp(seg->segname, "__TEXT_EXEC") == 0) has_text_exec = true;
            segments.push_back({_buf+seg->fileoff,seg->filesize, seg->vmaddr, (vmprot)(isWeirdPrelinkText ? (kVMPROTEXEC | kVMPROTREAD) : seg->maxprot), seg->segname});
        }
    }
    return segments;
}


void machopatchfinder64::loadSegments(){
    std::vector<vsegment> segments;
    std::vector<vsegment> segments2;
    struct mach_header_64 *mh = (struct mach_header_64*)_buf;
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    bool has_text_exec = false;
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == LC_SEGMENT_64){
            struct segment_command_64* seg = (struct segment_command_64*)lcmd;
            if (seg->filesize == 0) {
                debug("ignoring segment '%s' with zero size",seg->segname);
                continue;
            }
            /*
             idk what this weird thing is, but a TEXT section is never writable o.O
             Note: this is iOS8 related issue
             */
            bool isWeirdPrelinkText = (strcmp(seg->segname, "__PRELINK_TEXT") == 0 && seg->maxprot == (kVMPROTREAD | kVMPROTWRITE));
            if (strcmp(seg->segname, "__TEXT_EXEC") == 0) has_text_exec = true;
            segments.push_back({_buf+seg->fileoff,seg->filesize, (patchfinder64::loc_t)seg->vmaddr, (vmprot)(isWeirdPrelinkText ? (kVMPROTEXEC | kVMPROTREAD) : seg->maxprot), seg->segname});
            if (!_base){
                _base = (patchfinder64::loc_t)seg->vmaddr; //first segment is base. Is this correct??
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
                _entrypoint = (patchfinder64::patchfinder64::loc_t)(thread->pc);
            }
        }
        if (lcmd->cmd == LC_FILESET_ENTRY) {
            struct fileset_entry_command *fe = (fileset_entry_command*)lcmd;
            struct mach_header_64 *header = (struct mach_header_64*)&_buf[fe->fileoff];
            try {
                auto symtab = find_symtab_command((struct mach_header_64 *)header);
                __symtabs.push_back({symtab,(uint8_t*)header});
            } catch (tihmstar::load_command_not_found &e) {
                //
            }
            auto s = loadSegmentsForMachHeader(header);
            segments2.insert(segments2.end(), s.begin(), s.end());
        }
    }
    try {
        auto symtab = find_symtab_command((struct mach_header_64 *)_buf);
        __symtabs.push_back({symtab,(uint8_t*)_buf});
    } catch (tihmstar::load_command_not_found &e) {
        //
    }
    if (segments2.size()) segments = segments2;
    
    if (has_text_exec) {
        warning("We encountered __TEXT_EXEC section, marking normal __TEXT section as non-executable!");
        std::vector<vsegment> newsegments;
        for (auto &seg : segments) {
            int prot = (int)seg.perms;
            if (seg.segname == "__TEXT") prot &= ~kVMPROTEXEC;
            newsegments.push_back({seg.buf,seg.size,seg.vaddr, (vmprot)prot, seg.segname});
        }
        segments = newsegments;
    }
    _vmem = new vmem(segments,0,kVMPROTALL);
    
    try {
        deref(_entrypoint);
        info("Detected non-slid kernel.");
    } catch (tihmstar::out_of_range &e) {
        reterror("Detected slid kernel. but slid kernel is currently not supported");
    }
    try {
        deref(_entrypoint);
    } catch (tihmstar::out_of_range &e) {
        reterror("Error occured when handling kernel entry checks");
    }
    
    info("Inited machopatchfinder64 %s %s",VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA);
}

void machopatchfinder64::init(){
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
    
            if (!_freeBuf) {
                //if we don't own the buffer, then we can simply move by the required offset.
                //a higher level instance will take care of properly freeing the buffer so we can avoid reallocation
                assure(filesize <= _bufSize - offset);
                _bufSize = filesize;
                return (uint8_t*)_buf + offset;
            }
            
            uint8_t *ret = (uint8_t*) malloc(filesize);
            if (ret != NULL) {
                assure(filesize <= _bufSize - offset);
                _bufSize = filesize;
                memcpy(ret, _buf + offset, filesize);
            }
            return ret;
        }();
    
        if (tryfat) {
            printf("got fat macho with first slice at %u\n", (uint32_t) (tryfat - _buf));
            if (_freeBuf) {
                free((void*)_buf);
            }
            _buf = tryfat;tryfat = NULL;
        } else {
            printf("got fat macho but failed to parse\n");
        }
    }
    
    assure(*(uint32_t*)_buf == 0xfeedfacf);
    
    loadSegments();
}


machopatchfinder64::machopatchfinder64(const char *filename) :
    patchfinder64(true)
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
            
            assure(_buf = (uint8_t*)malloc(_bufSize = img4tmp->payloadSize()));
            memcpy((void*)_buf, img4tmp->payload(), _bufSize);
        }
    }
#else
    printf("Warning: compiled without img4tool, extracting from IMG4/IM4P disabled!\n");
#endif //HAVE_IMG4TOOL

    init();

    didConstructSuccessfully = true;
}

machopatchfinder64::machopatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership) :
patchfinder64(takeOwnership)
{
    _bufSize = bufSize;
    _buf = (uint8_t*)buffer;
    init();
}

machopatchfinder64::machopatchfinder64(machopatchfinder64 &&mv)
: patchfinder64(std::move(mv)),
__symtabs(mv.__symtabs)
{
    _bufSize = mv._bufSize;
    _buf = mv._buf;
}

patchfinder64::loc_t machopatchfinder64::find_sym(const char *sym){
    for (auto symtab : getSymtabs()){
        const uint8_t *psymtab = _buf + symtab.first->symoff;
        const uint8_t *pstrtab = _buf + symtab.first->stroff;
        
        struct nlist_64 *entry = (struct nlist_64 *)psymtab;
        for (uint32_t i = 0; i < symtab.first->nsyms; i++, entry++){
            char *stab_sym = (char*)(pstrtab + entry->n_un.n_strx);
            if (!strcmp(sym, stab_sym)){
                return (patchfinder64::loc_t)entry->n_value;
            }
        }
    }
    
    retcustomerror(symbol_not_found,sym);
}

std::string machopatchfinder64::sym_for_addr(patchfinder64::loc_t addr){
    for (auto symtab : getSymtabs()){
        const uint8_t *psymtab = _buf + symtab.first->symoff;
        const uint8_t *pstrtab = _buf + symtab.first->stroff;
        
        struct nlist_64 *entry = (struct nlist_64 *)psymtab;
        for (uint32_t i = 0; i < symtab.first->nsyms; i++, entry++)
            if (addr == (patchfinder64::loc_t)entry->n_value)
                return (const char*)(pstrtab + entry->n_un.n_strx);
    }

    retcustomerror(symbol_not_found,"No symbol for address=0x%016llx",addr);
}

patchfinder64::loc_t machopatchfinder64::bl_jump_stub_ptr_loc(patchfinder64::loc_t bl_insn){
    vmem iter = _vmem->getIter(bl_insn);
    assure(iter() == insn::bl);
    
    iter = (patchfinder64::loc_t)iter().imm();
    
    vmem ldr = _vmem->getIter((iter+1));
    if (!((iter() == insn::adrp && ldr() == insn::ldr && (iter+2) == insn::br))) {
        retcustomerror(bad_branch_destination, "branch destination not jump_stub_call");
    }
    return (patchfinder64::loc_t)iter().imm() + ldr().imm();
}
