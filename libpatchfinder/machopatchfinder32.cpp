//
//  machopatchfinder32.cpp
//  patchfinder
//
//  Created by tihmstar on 06.07.21.
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

#ifdef HAVE_IMG3TOOL
#include <img3tool/img3tool.hpp>
#endif //HAVE_IMG3TOOL


#include "../include/libpatchfinder/machopatchfinder32.hpp"

using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

#pragma mark macho external

__attribute__((always_inline)) struct load_command *find_load_command32(struct mach_header *mh, uint32_t lc){
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == lc)
            return lcmd;
    }

    retcustomerror(load_command_not_found, lc);
}

__attribute__((always_inline)) struct symtab_command *find_symtab_command(struct mach_header *mh){
    return (struct symtab_command *)find_load_command32(mh, LC_SYMTAB);
}

__attribute__((always_inline)) struct dysymtab_command *find_dysymtab_command(struct mach_header *mh){
    return (struct dysymtab_command *)find_load_command32(mh, LC_DYSYMTAB);
}

__attribute__((always_inline)) struct section *find_section(struct segment_command *seg, const char *sectname){
    struct section *sect = (struct section *)(seg + 1);
    for (uint32_t i=0; i<seg->nsects; i++, sect++) {
        if (strcmp(sect->sectname, sectname) == 0)
            return sect;
    }
    reterror("Failed to find section %s", sectname);
}

#pragma mark macho local

__attribute__((always_inline)) const struct symtab_command *machopatchfinder32::getSymtab(){
    if (!__symtab){
        try {
            __symtab = find_symtab_command((struct mach_header*)_buf);
        } catch (tihmstar::load_command_not_found &e) {
            if (e.cmd() != LC_SYMTAB)
                throw;
            retcustomerror(symtab_not_found, "symtab not found. Is this a dumped kernel?");
        }
    }
    return __symtab;
}

void machopatchfinder32::loadSegments(){
    std::vector<vsegment> segments;
    struct mach_header *mh = (struct mach_header*)_buf;
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    bool has_text_exec = false;
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == LC_SEGMENT){
            struct segment_command* seg = (struct segment_command*)lcmd;
            if (seg->filesize == 0) {
                debug("ignoring segment '%s' with zero size",seg->segname);
                continue;
            }
            /*
             idk what this weird thing is, but a TEXT section is always executeable o.O
             Note: this is iOS4 related issue
             */
            bool isWeirdPrelinkText = (strcmp(seg->segname, "__PRELINK_TEXT") == 0 && !(seg->maxprot & kVMPROTEXEC ));
            if (strcmp(seg->segname, "__TEXT_EXEC") == 0) has_text_exec = true;
            segments.push_back({_buf+seg->fileoff,seg->filesize, (loc_t)seg->vmaddr, (vmprot)(isWeirdPrelinkText ? (kVMPROTEXEC | kVMPROTREAD) : seg->maxprot), seg->segname});
            if (i==0){
                _base = (loc_t)seg->vmaddr; //first segment is base. Is this correct??
            }
        }
        if (lcmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(lcmd + 1);
            uint32_t flavor = ptr[0];
            struct _tread{
                uint32_t r[13];    /* General purpose registers x0-x28 */
                uint32_t sp;    /* Stack pointer r13 */
                uint32_t lr;    /* Link register r14 */
                uint32_t pc;     /* Program counter */
                uint32_t cpsr;    /* Current program status register */
            } *thread = (struct _tread*)(ptr + 2);
            if (flavor == 1) {
                _entrypoint = (patchfinder32::loc_t)(thread->pc);
            }
        }
    }
    if (has_text_exec) {
        warning("We encountered __TEXT_EXEC section, marking normal __TEXT section as non-executable!");
        std::vector<vsegment> newsegments;
        for (auto &seg : segments) {
            int prot = (int)seg.perms;
            if (seg.segname == "__TEXT") prot &= ~kVMPROTEXEC;
            newsegments.push_back({seg.buf, seg.size, seg.vaddr, (vmprot)prot, seg.segname});
        }
        segments = newsegments;
    }
    _vmemThumb = new vmem_thumb(segments,0, kVMPROTALL);
    _vmemArm = new vmem_arm(segments,0, kVMPROTALL);

    try {
        _vmemThumb->deref(_entrypoint);
        info("Detected non-slid kernel.");
    } catch (tihmstar::out_of_range &e) {
        reterror("Detected slid kernel. but slid kernel is currently not supported");
    }
    try {
        _vmemThumb->deref(_entrypoint);
    } catch (tihmstar::out_of_range &e) {
        reterror("Error occured when handling kernel entry checks");
    }
    
    info("Inited machopatchfinder32 %s %s",VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA);
    try {
        getSymtab();
    } catch (tihmstar::symtab_not_found &e) {
        info("Symtab not found. Assuming we are operating on a dumped kernel");
    }
    printf("\n");
}

void machopatchfinder32::init(){
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

    assure(*(uint32_t*)_buf == 0xfeedface);

    loadSegments();
}


machopatchfinder32::machopatchfinder32(const char *filename) :
    patchfinder32(true),
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
            
            assure(_buf = (uint8_t*)malloc(_bufSize = img4tmp->payloadSize()));
            memcpy((void*)_buf, img4tmp->payload(), _bufSize);
        }
    }
#else
    warning("compiled without img4tool, extracting from IMG4/IM4P disabled!\n");
#endif //HAVE_IMG4TOOL
    
#ifdef HAVE_IMG3TOOL
    {
        std::vector<uint8_t> img3payload;
        try {
            img3payload = img3tool::getPayloadFromIMG3(_buf, _bufSize);
        } catch (...) {
            //
        }
        if (img3payload.size()) {
            retassure(_buf = (const uint8_t *)realloc((void*)_buf, _bufSize = img3payload.size()),"Failed to realloc buffer");
            memcpy((void*)_buf, img3payload.data(), _bufSize);
        }
    }
#else
    warning("compiled without img3tool, extracting from IMG3 disabled!\n");
#endif

    init();

    didConstructSuccessfully = true;
}

machopatchfinder32::machopatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership) :
patchfinder32(takeOwnership),
__symtab(NULL)
{
    _bufSize = bufSize;
    _buf = (uint8_t*)buffer;
    init();
}

machopatchfinder32::machopatchfinder32(machopatchfinder32 &&mv)
: patchfinder32(std::move(mv)),
__symtab(mv.__symtab)
{
    _bufSize = mv._bufSize;
    _buf = mv._buf;
}

patchfinder32::loc_t machopatchfinder32::find_sym(const char *sym){
    const uint8_t *psymtab = _buf + getSymtab()->symoff;
    const uint8_t *pstrtab = _buf + getSymtab()->stroff;

    struct nlist *entry = (struct nlist *)psymtab;
    for (uint32_t i = 0; i < getSymtab()->nsyms; i++, entry++)
        if (!strcmp(sym, (char*)(pstrtab + entry->n_un.n_strx)))
            return (loc_t)entry->n_value;

    retcustomerror(symbol_not_found,sym);
}

std::string machopatchfinder32::sym_for_addr(loc_t addr){
    const uint8_t *psymtab = _buf + getSymtab()->symoff;
    const uint8_t *pstrtab = _buf + getSymtab()->stroff;

    struct nlist *entry = (struct nlist *)psymtab;
    for (uint32_t i = 0; i < getSymtab()->nsyms; i++, entry++)
        if (addr == (loc_t)entry->n_value) {
            return (const char*)(pstrtab + entry->n_un.n_strx);
        }

    retcustomerror(symbol_not_found,"No symbol for address=0x%08x",addr);
}

machopatchfinder32::loc_t machopatchfinder32::bl_jump_stub_ptr_loc(loc_t bl_insn){
    vmem_thumb iter = _vmemThumb->getIter(bl_insn);
    assure(iter() == arm32::bl);

    iter = iter().imm();
    
    loc_t ldrdst = 0;

    assure(iter() == arm32::mov);
    ldrdst = iter().imm();
    
    assure(++iter == arm32::movt); //might also be NOP ??
    ldrdst += iter().imm();
    
    assure(++iter == arm32::add && iter().rm() == 15);
    ldrdst += (iter.pc() & 2) ? (iter.pc() + 2) : (iter.pc() + 4);
    return ldrdst;
}
