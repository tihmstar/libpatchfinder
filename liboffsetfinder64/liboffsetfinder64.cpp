//
//  offsetfinder64.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <liboffsetfinder64/liboffsetfinder64.hpp>


extern "C"{
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "img4.h"
#include "lzssdec.h"
}

#define info(a ...) ({printf(a),printf("\n");})
#define log(a ...) ({if (dbglog) printf(a),printf("\n");})
#define warning(a ...) ({if (dbglog) printf("[WARNING] "), printf(a),printf("\n");})
#define error(a ...) ({printf("[Error] "),printf(a),printf("\n");})

#define safeFree(ptr) ({if (ptr) free(ptr),ptr=NULL;})

#define reterror(err) throw tihmstar::exception(__LINE__,err)
#define assure(cond) if ((cond) == 0) throw tihmstar::exception(__LINE__, "assure failed")
#define doassure(cond,code) do {if (!(cond)){(code);assure(cond);}} while(0)
#define retassure(cond, err) if ((cond) == 0) throw tihmstar::exception(__LINE__,err)
#define assureclean(cond) do {if (!(cond)){clean();assure(cond);}} while(0)

#ifdef DEBUG
#define OFFSETFINDER64_VERSION_COMMIT_COUNT "Debug"
#define OFFSETFINDER64_VERSION_COMMIT_SHA "Build: " __DATE__ " " __TIME__

uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }

#else
#define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#define BIT_AT(v,pos) ( (v >> pos) % 2 )
#endif

using namespace std;
using namespace tihmstar;
using namespace patchfinder64;

using segment_t = std::vector<offsetfinder64::text_t>;

#define HAS_BITS(a,b) (((a) & (b)) == (b))
#define _symtab getSymtab()
int decompress_lzss(u_int8_t *dst, u_int8_t *src, u_int32_t srclen);

namespace patchfinder64 {
    class insn;
}


#pragma mark macho external

__attribute__((always_inline)) struct load_command *find_load_command64(struct mach_header_64 *mh, uint32_t lc){
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == lc)
            return lcmd;
    }
    
    reterror("Failed to find load command "+ to_string(lc));
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
    reterror("Failed to find section "+ string(sectname));
    return NULL;
}

offsetfinder64::offsetfinder64(const char* filename) : _freeKernel(true),__symtab(NULL){
    struct stat fs = {0};
    int fd = 0;
    char *img4tmp = NULL;
    auto clean =[&]{
        if (fd>0) close(fd);
    };
    assure((fd = open(filename, O_RDONLY)) != -1);
    assureclean(!fstat(fd, &fs));
    assureclean((_kdata = (uint8_t*)malloc( _ksize = fs.st_size)));
    assureclean(read(fd,_kdata,_ksize)==_ksize);
    
    //check if feedfacf, lzss, img4, im4p
    img4tmp = (char*)_kdata;
    if (sequenceHasName(img4tmp, (char*)"IMG4")){
        img4tmp = getElementFromIMG4((char*)_kdata, (char*)"IM4P");
    }
    if (sequenceHasName(img4tmp, (char*)"IM4P")){
        /*extract file from IM4P*/
        char *extractFile = [](char *buf, char **dstBuf)->char*{
            int elems = asn1ElementsInObject(buf);
            if (elems < 4){
                error("not enough elements in SEQUENCE %d\n",elems);
                return NULL;
            }
            
            char *dataTag = asn1ElementAtIndex(buf, 3)+1;
            t_asn1ElemLen dlen = asn1Len(dataTag);
            char *data = dataTag+dlen.sizeBytes;
            
            char *kernel = NULL;
            if ((kernel = tryLZSS(data, (size_t*)&dlen.dataLen))){
                data = kernel;
                printf("lzsscomp detected, uncompressing...\n");
            }
            return kernel;
        }(img4tmp,&extractFile);
        /* done extract file from IM4P*/
        
        free(_kdata);
        _kdata = (uint8_t*)extractFile;
    }
    
    assureclean(*(uint32_t*)_kdata == 0xfeedfacf);
    
    loadSegments(0);
    clean();
}

void offsetfinder64::loadSegments(uint64_t slide){
    _kslide = slide;
    struct mach_header_64 *mh = (struct mach_header_64*)_kdata;
    struct load_command *lcmd = (struct load_command *)(mh + 1);
    for (uint32_t i=0; i<mh->ncmds; i++, lcmd = (struct load_command *)((uint8_t *)lcmd + lcmd->cmdsize)) {
        if (lcmd->cmd == LC_SEGMENT_64){
            struct segment_command_64* seg = (struct segment_command_64*)lcmd;
            _segments.push_back({_kdata+seg->fileoff,seg->filesize, (loc_t)seg->vmaddr, (seg->maxprot & VM_PROT_EXECUTE) !=0});
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
                _kernel_entry = (patchfinder64::loc_t)(thread->pc);
            }
        }
    }
    
    info("Inited offsetfinder64 %s %s\n",OFFSETFINDER64_VERSION_COMMIT_COUNT, OFFSETFINDER64_VERSION_COMMIT_SHA);
    
}

offsetfinder64::offsetfinder64(void* buf, size_t size, uint64_t slide) : _freeKernel(false),_kdata((uint8_t*)buf),_ksize(size),__symtab(NULL){
    loadSegments(slide);
}

const void *offsetfinder64::kdata(){
    return _kdata;
}

loc_t offsetfinder64::find_entry(){
    return _kernel_entry;
}


#pragma mark macho offsetfinder
__attribute__((always_inline)) struct symtab_command *offsetfinder64::getSymtab(){
    if (!__symtab)
        __symtab = find_symtab_command((struct mach_header_64 *)_kdata);
    return __symtab;
}

#pragma mark offsetfidner

loc_t offsetfinder64::memmem(const void *little, size_t little_len){
    for (auto seg : _segments) {
        if (loc_t rt = (loc_t)::memmem(seg.map, seg.size, little, little_len)) {
            return rt-seg.map+seg.base+_kslide;
        }
    }
    return 0;
}


loc_t offsetfinder64::find_sym(const char *sym){
    uint8_t *psymtab = _kdata + _symtab->symoff;
    uint8_t *pstrtab = _kdata + _symtab->stroff;

    struct nlist_64 *entry = (struct nlist_64 *)psymtab;
    for (uint32_t i = 0; i < _symtab->nsyms; i++, entry++)
        if (!strcmp(sym, (char*)(pstrtab + entry->n_un.n_strx)))
            return (loc_t)entry->n_value;

    reterror("Failed to find symbol "+string(sym));
    return 0;
}

loc_t offsetfinder64::find_syscall0(){
#define SIG_SYSCALL_3 "\x06\x00\x00\x00\x03\x00\x0c\x00"
    loc_t sys3 = memmem(SIG_SYSCALL_3, sizeof(SIG_SYSCALL_3)-1);
    return sys3 - (3 * 0x18) + 0x8;
}


#pragma mark patchfinder64
namespace tihmstar{
    namespace patchfinder64{
        
        class insn{
        public:
            enum segtype{
                kText_only,
                kData_only,
                kText_and_Data
            };
        private:
            std::pair <loc_t,int> _p;
            std::vector<offsetfinder64::text_t> _segments;
            offset_t _kslide;
            segtype _segtype;
        public:
            insn(segment_t segments, offset_t kslide, loc_t p = 0, segtype segType = kText_only) : _segments(segments), _kslide(kslide), _segtype(segType){
                std::sort(_segments.begin(),_segments.end(),[ ]( const offsetfinder64::text_t& lhs, const offsetfinder64::text_t& rhs){
                    return lhs.base < rhs.base;
                });
                if (_segtype != kText_and_Data) {
                    _segments.erase(std::remove_if(_segments.begin(), _segments.end(), [&](const offsetfinder64::text_t obj){
                        return (!obj.isExec) == (_segtype == kText_only);
                    }));
                }
                if (p == 0) {
                    p = _segments.at(0).base;
                }
                for (int i=0; i<_segments.size(); i++){
                    auto seg = _segments[i];
                    if ((loc_t)seg.base <= p && p < (loc_t)seg.base+seg.size){
                        _p = {p,i};
                        return;
                    }
                }
                reterror("initializing insn with out of range location");
            }
            
            insn(const insn &cpy, loc_t p=0){
                _segments = cpy._segments;
                _kslide = cpy._kslide;
                _segtype = cpy._segtype;
                if (p==0) {
                    _p = cpy._p;
                }else{
                    for (int i=0; i<_segments.size(); i++){
                        auto seg = _segments[i];
                        if ((loc_t)seg.base <= p && p < (loc_t)seg.base+seg.size){
                            _p = {p,i};
                            return;
                        }
                    }
                    reterror("initializing insn with out of range location");
                }
            }
            
            insn &operator++(){
                _p.first+=4;
                if (_p.first >=_segments[_p.second].base+_segments[_p.second].size){
                    if (_p.second+1 < _segments.size()) {
                        _p.first = _segments[++_p.second].base;
                    }else{
                        _p.first-=4;
                        throw out_of_range("overflow");
                    }
                }
                return *this;
            }
            insn &operator--(){
                _p.first-=4;
                if (_p.first < _segments[_p.second].base){
                    if (_p.second-1 >0) {
                        --_p.second;
                        _p.first = _segments[_p.second].base+_segments[_p.second].size;
                    }else{
                        _p.first+=4;
                        throw out_of_range("underflow");
                    }
                }
                return *this;
            }
            insn operator+(int i){
                insn cpy(*this);
                if (i>0) {
                    while (i--)
                        ++cpy;
                }else{
                    while (i++)
                        --cpy;
                }
                return cpy;
            }
            insn operator-(int i){
                return this->operator+(-i);
            }
            insn &operator+=(int i){
                if (i>0) {
                    while (i-->0)
                        this->operator++();
                }else{
                    while (i++>0)
                        this->operator--();
                }
                return *this;
            }
            insn &operator-=(int i){
                return this->operator+=(-i);
            }
            
        public: //helpers
            __attribute__((always_inline)) static int64_t signExtend64(uint64_t v, int vSize){
                uint64_t e = (v & 1 << (vSize-1))>>(vSize-1);
                for (int i=vSize; i<64; i++)
                    v |= e << i;
                return v;
            }
            __attribute__((always_inline)) static int highestSetBit(uint64_t x){
                for (int i=63; i>=0; i--) {
                    if (x & ((uint64_t)1<<i))
                        return i;
                }
                return -1;
            }
            __attribute__((always_inline)) static int lowestSetBit(uint64_t x){
                for (int i=0; i<=63; i++) {
                    if (x & (1<<i))
                        return i;
                }
                return 64;
            }
            __attribute__((always_inline)) static uint64_t replicate(uint8_t val, int bits){
                uint64_t ret = val;
                unsigned shift;
                for (shift = bits; shift < 64; shift += bits) {    // XXX actually, it is either 32 or 64
                    ret |= (val << shift);
                }
                return ret;
            }
            
            __attribute__((always_inline)) static uint64_t ones(uint64_t n){
                uint64_t ret = 0;
                while (n--) {
                    ret <<=1;
                    ret |= 1;
                }
                return ret;
            }
            __attribute__((always_inline)) static uint64_t ROR(uint64_t x, int shift, int len){
                while (shift--) {
                    x |= (x & 1) << len;
                    x >>=1;
                }
                return x;
            }
            __attribute__((always_inline)) static pair<int64_t, int64_t> DecodeBitMasks(uint64_t immN, uint8_t imms, uint8_t immr, bool immediate){
                int64_t tmask = 0, wmask = 0;
                int8_t levels = 0;
                
                int len = highestSetBit( (uint64_t)((immN<<6) | ((~imms) & 0b111111)) );
                assure(len != -1); //reserved value
                levels = ones(len);
                
                assure(immediate && (imms & levels) != levels); //reserved value
                
                uint8_t S = imms & levels;
                uint8_t R = immr & levels;
                
                uint8_t esize = 1 << len;
                
                uint8_t welem = ones(S + 1);
                wmask = replicate(ROR(welem, R, 32),esize);
#warning TODO incomplete function implementation!
                return {wmask,0};
            }
            uint64_t pc(){
                return (uint64_t)_p.first + (uint64_t)_kslide;
            }
            uint32_t value(){
                return (*(uint32_t*)(loc_t)(*this));
            }
            uint64_t doublevalue(){
                return (*(uint64_t*)(loc_t)(*this));
            }
            
        public: //static type determinition
            static uint64_t deref(segment_t segments, offset_t kslide, loc_t p){
                return *(uint64_t*)(loc_t)insn(segments, kslide, p,kText_and_Data);
            }
            static bool is_adrp(uint32_t i){
                return BIT_RANGE(i, 24, 28) == 0b10000 && (i>>31);
            }
            static bool is_adr(uint32_t i){
                return BIT_RANGE(i, 24, 28) == 0b10000 && !(i>>31);
            }
            static bool is_add(uint32_t i){
                return BIT_RANGE(i, 24, 28) == 0b10001;
            }
            static bool is_bl(uint32_t i){
                return (i>>26) == 0b100101;
            }
            static bool is_cbz(uint32_t i){
                return BIT_RANGE(i, 24, 30) == 0b0110100;
            }
            static bool is_ret(uint32_t i){
                return ((0b11111 << 5) | i) == 0b11010110010111110000001111100000;
            }
            static bool is_tbnz(uint32_t i){
                return BIT_RANGE(i, 24, 30) == 0b0110111;
            }
            static bool is_br(uint32_t i){
                return ((0b11111 << 5) | i) == 0b11010110000111110000001111100000;
            }
            static bool is_ldr(uint32_t i){
#warning TODO recheck this mask
                return (((i>>22) | 0b0100000000) == 0b1111100001 && ((i>>10) % 4)) || ((i>>22 | 0b0100000000) == 0b1111100101) || ((i>>23) == 0b00011000);
            }
            static bool is_cbnz(uint32_t i){
                return BIT_RANGE(i, 24, 30) == 0b0110101;
            }
            static bool is_movk(uint32_t i){
                return BIT_RANGE(i, 23, 30) == 0b11100101;
            }
            static bool is_orr(uint32_t i){
                return BIT_RANGE(i, 23, 30) == 0b01100100;
            }
            static bool is_tbz(uint32_t i){
                return BIT_RANGE(i, 24, 30) == 0b0110110;
            }
            static bool is_ldxr(uint32_t i){
                return (BIT_RANGE(i, 24, 29) == 0b001000) && (i >> 31) && BIT_AT(i, 22);
            }
            static bool is_str(uint32_t i){
#warning TODO redo this! currently only recognises STR (immediate)
                return (BIT_RANGE(i, 22, 29) == 0b11100100) && (i >> 31);
            }
            static bool is_stp(uint32_t i){
#warning TODO redo this! currently only recognises STR (immediate)
                return (BIT_RANGE(i, 25, 30) == 0b010100) && !BIT_AT(i, 22);
            }
            static bool is_movz(uint32_t i){
                return (BIT_RANGE(i, 23, 30) == 0b10100101);
            }
            static bool is_bcond(uint32_t i){
                return (BIT_RANGE(i, 24, 31) == 0b01010100) && !BIT_AT(i, 4);
            }
            
            
        public: //type
            enum type{
                unknown,
                adrp,
                adr,
                bl,
                cbz,
                ret,
                tbnz,
                add,
                br,
                ldr,
                cbnz,
                movk,
                orr,
                tbz,
                ldxr,
                str,
                stp,
                movz,
                bcond
            };
            enum subtype{
                st_general,
                st_register,
                st_immediate,
                st_literal
            };
            enum supertype{
                sut_general,
                sut_branch_imm
            };
            enum cond{
                NE = 000,
                EG = 000,
                CS = 001,
                CC = 001,
                MI = 010,
                PL = 010,
                VS = 011,
                VC = 011,
                HI = 100,
                LS = 100,
                GE = 101,
                LT = 101,
                GT = 110,
                LE = 110,
                AL = 111
            };
            type type(){
                uint32_t val = value();
                if (is_adrp(val))
                    return adrp;
                else if (is_adr(val))
                    return adr;
                else if (is_add(val))
                    return add;
                else if (is_bl(val))
                    return bl;
                else if (is_cbz(val))
                    return cbz;
                else if (is_ret(val))
                    return ret;
                else if (is_tbnz(val))
                    return tbnz;
                else if (is_br(val))
                    return br;
                else if (is_ldr(val))
                    return ldr;
                else if (is_cbnz(val))
                    return cbnz;
                else if (is_movk(val))
                    return movk;
                else if (is_orr(val))
                    return orr;
                else if (is_tbz(val))
                    return tbz;
                else if (is_ldxr(val))
                    return ldxr;
                else if (is_str(val))
                    return str;
                else if (is_stp(val))
                    return stp;
                else if (is_movz(val))
                    return movz;
                else if (is_bcond(val))
                    return bcond;
                
                return unknown;
            }
            subtype subtype(){
                uint32_t i = value();
                if (is_ldr(i)) {
                    if ((((i>>22) | (1 << 8)) == 0b1111100001) && BIT_RANGE(i, 10, 11) == 0b10)
                        return st_register;
                    else if (i>>31)
                        return st_immediate;
                    else
                        return st_literal;
                    
                }
                return st_general;
            }
            supertype supertype(){
                switch (type()) {
                    case bl:
                    case cbz:
                    case cbnz:
                    case tbnz:
                    case bcond:
                        return sut_branch_imm;
                        
                    default:
                        return sut_general;
                }
            }
            int64_t imm(){
                switch (type()) {
                    case unknown:
                        reterror("can't get imm value of unknown instruction");
                        break;
                    case adrp:
                        return ((pc()>>12)<<12) + signExtend64(((((value() % (1<<24))>>5)<<2) | BIT_RANGE(value(), 29, 30))<<12,32);
                    case adr:
                        return pc() + signExtend64((BIT_RANGE(value(), 5, 23)<<2) | (BIT_RANGE(value(), 29, 30)), 21);
                    case add:
                        return BIT_RANGE(value(), 10, 21) << (((value()>>22)&1) * 12);
                    case bl:
                        return signExtend64(value() % (1<<26), 25); //untested
                    case cbz:
                    case cbnz:
                    case tbnz:
                    case bcond:
                        return signExtend64(BIT_RANGE(value(), 5, 23), 19); //untested
                    case movk:
                    case movz:
                        return BIT_RANGE(value(), 5, 20);
                    case ldr:
                        if(subtype() != st_immediate){
                            reterror("can't get imm value of ldr that has non immediate subtype");
                            break;
                        }
                        if(BIT_RANGE(value(), 24, 25)){
                            // Unsigned Offset
                            return BIT_RANGE(value(), 10, 21) << (value()>>30);
                        }else{
                            // Signed Offset
                            return signExtend64(BIT_RANGE(value(), 12, 21), 9); //untested
                        }
                    case str:
#warning TODO rewrite this! currently only unsigned offset supported
                        // Unsigned Offset
                        return BIT_RANGE(value(), 10, 21) << (value()>>30);
                    case orr:
                        return DecodeBitMasks(BIT_AT(value(), 22),BIT_RANGE(value(), 10, 15),BIT_RANGE(value(), 16,21), true).first;
                    case tbz:
                        return BIT_RANGE(value(), 5, 18);
                    case stp:
                        return signExtend64(BIT_RANGE(value(), 15, 21),7) << (2+(value()>>31));
                    default:
                        reterror("failed to get imm value");
                        break;
                }
                return 0;
            }
            uint8_t rd(){
                switch (type()) {
                    case unknown:
                        reterror("can't get rd of unknown instruction");
                        break;
                    case adrp:
                    case adr:
                    case add:
                    case movk:
                    case orr:
                    case movz:
                        return (value() % (1<<5));
                        
                    default:
                        reterror("failed to get rd");
                        break;
                }
            }
            uint8_t rn(){
                switch (type()) {
                    case unknown:
                        reterror("can't get rn of unknown instruction");
                        break;
                    case add:
                    case ret:
                    case br:
                    case orr:
                    case ldxr:
                    case str:
                    case ldr:
                    case stp:
                        return BIT_RANGE(value(), 5, 9);
                        
                    default:
                        reterror("failed to get rn");
                        break;
                }
            }
            uint8_t rt(){
                switch (type()) {
                    case unknown:
                        reterror("can't get rt of unknown instruction");
                        break;
                    case cbz:
                    case cbnz:
                    case tbnz:
                    case tbz:
                    case ldxr:
                    case str:
                    case ldr:
                    case stp:
                        return (value() % (1<<5));
                        
                    default:
                        reterror("failed to get rt");
                        break;
                }
            }
            uint8_t other(){
                switch (type()) {
                    case unknown:
                        reterror("can't get other of unknown instruction");
                        break;
                    case tbz:
                        return ((value() >>31) << 5) | BIT_RANGE(value(), 19, 23);
                    case stp:
                        return BIT_RANGE(value(), 10, 14); //Rt2
                    case bcond:
                        return 0; //condition
                    default:
                        reterror("failed to get other");
                        break;
                }
            }
        public: //cast operators
            operator loc_t(){
                return (loc_t)(_p.first - _segments[_p.second].base + _segments[_p.second].map);
            }
            operator enum type(){
                return type();
            }
        };
        
        loc_t find_literal_ref(segment_t segemts, offset_t kslide, loc_t pos){
            insn adrp(segemts,kslide);
            
            uint8_t rd = 0xff;
            uint64_t imm = 0;
            try {
                while (1){
                    if (adrp == insn::adr) {
                        if (adrp.imm() == (uint64_t)pos)
                            return (loc_t)adrp.pc();
                    }else if (adrp == insn::adrp) {
                        rd = adrp.rd();
                        imm = adrp.imm();
                    }else if (adrp == insn::add && rd == adrp.rd()){
                        if (imm + adrp.imm() == (int64_t)pos)
                            return (loc_t)adrp.pc();
                    }
                    ++adrp;
                }
                
                
            } catch (std::out_of_range &e) {
                return 0;
            }
            return 0;
        }
        loc_t find_rel_branch_source(insn bdst, bool searchUp, int ignoreTimes=0){
            insn bsrc(bdst);
            
            while (true) {
                if (searchUp)
                    while ((--bsrc).supertype() != insn::sut_branch_imm);
                else
                    while ((++bsrc).supertype() != insn::sut_branch_imm);
                
                if (bsrc.imm()*4 + bsrc.pc() == bdst.pc()) {
                    if (ignoreTimes) {
                        ignoreTimes--;
                        continue;
                    }
                    return (loc_t)bsrc.pc();
                }
            }
            return 0;
        }

    };
};

namespace tihmstar{
    namespace patchfinder64{
        
        
        loc_t jump_stub_call_ptr_loc(insn bl_insn){
            assure(bl_insn == insn::bl);
            insn fdst(bl_insn,(loc_t)(bl_insn.imm()*4+bl_insn.pc()));
            insn ldr((fdst+1));
            retassure((fdst == insn::adrp && ldr == insn::ldr && (fdst+2) == insn::br), "branch destination not jump_stub_call");
            return (loc_t)fdst.imm() + ldr.imm();
        }
        
        bool is_call_to_jump_stub(insn bl_insn){
            try {
                jump_stub_call_ptr_loc(bl_insn);
                return true;
            } catch (tihmstar::exception &e) {
                return false;
            }
        }
        
    }
}

#pragma mark common patchs
constexpr char patch_nop[] = "\x1F\x20\x03\xD5";
constexpr size_t patch_nop_size = sizeof(patch_nop)-1;

uint64_t offsetfinder64::find_register_value(loc_t where, int reg){
    insn functop(_segments, _kslide, where);
    
    //might be functop
    //good enough for my purpose
    while (--functop != insn::stp || (functop+1) != insn::stp || (functop+2) != insn::stp);
    
    uint64_t value[32] = {0};
    
    for (;(loc_t)functop.pc() < where;++functop) {
        
        switch (functop.type()) {
            case patchfinder64::insn::adrp:
                value[functop.rd()] = functop.imm();
//                printf("%p: ADRP X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
                break;
            case patchfinder64::insn::add:
                value[functop.rd()] = value[functop.rn()] + functop.imm();
//                printf("%p: ADD X%d, X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.rn(), (uint64_t)functop.imm());
                break;
            case patchfinder64::insn::adr:
                value[functop.rd()] = functop.imm();
//                printf("%p: ADR X%d, 0x%llx\n", (void*)functop.pc(), functop.rd(), functop.imm());
                break;
            case patchfinder64::insn::ldr:
//                printf("%p: LDR X%d, [X%d, 0x%llx]\n", (void*)functop.pc(), functop.rt(), functop.rn(), (uint64_t)functop.imm());
                value[functop.rt()] = value[functop.rn()] + functop.imm(); // XXX address, not actual value
                break;
            default:
                break;
        }
    }
    return value[reg];
}

#pragma mark v0rtex
loc_t offsetfinder64::find_zone_map(){
    loc_t str = memmem("zone_init", sizeof("zone_init"));
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");

    insn ptr(_segments,_kslide,ref);
    
    loc_t ret = 0;
    
    while (++ptr != insn::adrp);
    ret = (loc_t)ptr.imm();
    
    while (++ptr != insn::add);
    ret += ptr.imm();
    
    return ret;
}

loc_t offsetfinder64::find_kernel_map(){
    return find_sym("_kernel_map");
}

loc_t offsetfinder64::find_kernel_task(){
    return find_sym("_kernel_task");
}

loc_t offsetfinder64::find_realhost(){
    loc_t sym = find_sym("_KUNCExecute");
    
    insn ptr(_segments,_kslide,sym);
    
    loc_t ret = 0;
    
    while (++ptr != insn::adrp);
    ret = (loc_t)ptr.imm();
    
    while (++ptr != insn::add);
    ret += ptr.imm();
    
    return ret;
}

loc_t offsetfinder64::find_bzero(){
    return find_sym("___bzero");
}

loc_t offsetfinder64::find_bcopy(){
    return find_sym("_bcopy");
}

loc_t offsetfinder64::find_copyout(){
    return find_sym("_copyout");
}

loc_t offsetfinder64::find_copyin(){
    return find_sym("_copyin");
}

loc_t offsetfinder64::find_ipc_port_alloc_special(){
    loc_t sym = find_sym("_KUNCGetNotificationID");
    insn ptr(_segments,_kslide,sym);
    
    while (++ptr != insn::bl);
    while (++ptr != insn::bl);
    
    return (loc_t)ptr.pc() + 4*ptr.imm();
}

loc_t offsetfinder64::find_ipc_kobject_set(){
    loc_t sym = find_sym("_KUNCGetNotificationID");
    insn ptr(_segments,_kslide,sym);
    
    while (++ptr != insn::bl);
    while (++ptr != insn::bl);
    while (++ptr != insn::bl);
    
    return (loc_t)ptr.pc() + 4*ptr.imm();
}

loc_t offsetfinder64::find_ipc_port_make_send(){
    loc_t sym = find_sym("_convert_task_to_port");
    insn ptr(_segments,_kslide,sym);
    while (++ptr != insn::bl);
    while (++ptr != insn::bl);
    
    return (loc_t)ptr.pc() + 4*ptr.imm();
}

loc_t offsetfinder64::find_chgproccnt(){
    loc_t str = memmem("\"chgproccnt: lost user\"", sizeof("\"chgproccnt: lost user\""));
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");
    
    insn functop(_segments,_kslide,ref);
    
    while (--functop != insn::stp);
    while (--functop == insn::stp);
    ++functop;
    
    return (loc_t)functop.pc();
}

loc_t offsetfinder64::find_kauth_cred_ref(){
    return find_sym("_kauth_cred_ref");
}

loc_t offsetfinder64::find_osserializer_serialize(){
    return find_sym("__ZNK12OSSerializer9serializeEP11OSSerialize");
}

uint32_t offsetfinder64::find_vtab_get_external_trap_for_index(){
    loc_t sym = find_sym("__ZTV12IOUserClient");
    sym += 2*sizeof(uint64_t);
    
    loc_t nn = find_sym("__ZN12IOUserClient23getExternalTrapForIndexEj");
    
    insn data(_segments,_kslide,sym,insn::kText_and_Data);
    --data;
    for (int i=0; i<0x200; i++) {
        if ((++data).doublevalue() == (uint64_t)nn)
            return i;
        ++data;
    }
    return 0;
}

uint32_t offsetfinder64::find_vtab_get_retain_count(){
    loc_t sym = find_sym("__ZTV12IOUserClient");
    sym += 2*sizeof(uint64_t);
    
    loc_t nn = find_sym("__ZNK8OSObject14getRetainCountEv");
    
    insn data(_segments,_kslide,sym,insn::kText_and_Data);
    --data;
    for (int i=0; i<0x200; i++) {
        if ((++data).doublevalue() == (uint64_t)nn)
            return i;
        ++data;
    }
    return 0;
}

uint32_t offsetfinder64::find_proc_ucred(){
    loc_t sym = find_sym("_proc_ucred");
    return (uint32_t)insn(_segments,_kslide,sym).imm();
}

uint32_t offsetfinder64::find_task_bsd_info(){
    loc_t sym = find_sym("_get_bsdtask_info");
    return (uint32_t)insn(_segments,_kslide,sym).imm();
}

uint32_t offsetfinder64::find_vm_map_hdr(){
    loc_t sym = find_sym("_vm_map_create");
    
    insn stp(_segments, _kslide, sym);
    
    while (++stp != insn::bl);

    while (++stp != insn::cbz);
    
    while (++stp != insn::stp);
    
    return (uint32_t)stp.imm();
}

typedef struct mig_subsystem_struct {
    uint32_t min;
    uint32_t max;
    char *names;
} mig_subsys;

mig_subsys task_subsys ={ 0xd48, 0xd7a , NULL};
uint32_t offsetfinder64::find_task_itk_self(){
    loc_t task_subsystem=memmem(&task_subsys, 4);
    assure(task_subsystem);
    task_subsystem += 4*sizeof(uint64_t); //index0 now
    
    insn mach_ports_register(_segments,_kslide, (loc_t)insn::deref(_segments, _kslide, task_subsystem+3*5*8));
    
    while (++mach_ports_register != insn::bl || mach_ports_register.imm()*4+mach_ports_register.pc() != (uint64_t)find_sym("_lck_mtx_lock"));
    
    insn ldr(mach_ports_register);
    
    while (++ldr != insn::ldr || (ldr+2) != insn::ldr);
    
    return (uint32_t)ldr.imm();
}

uint32_t offsetfinder64::find_task_itk_registered(){
    loc_t task_subsystem=memmem(&task_subsys, 4);
    assure(task_subsystem);
    task_subsystem += 4*sizeof(uint64_t); //index0 now
    
    insn mach_ports_register(_segments,_kslide, (loc_t)insn::deref(_segments, _kslide, task_subsystem+3*5*8));
    
    while (++mach_ports_register != insn::bl || mach_ports_register.imm()*4+mach_ports_register.pc() != (uint64_t)find_sym("_lck_mtx_lock"));
    
    insn ldr(mach_ports_register);
    
    while (++ldr != insn::ldr || (ldr+2) != insn::ldr);
    ldr +=2;
    
    return (uint32_t)ldr.imm();
}


//IOUSERCLIENT_IPC
mig_subsys host_priv_subsys = { 400, 426 } ;
uint32_t offsetfinder64::find_iouserclient_ipc(){
    loc_t host_priv_subsystem=memmem(&host_priv_subsys, 8);
    assure(host_priv_subsystem);

    insn memiterator(_segments,_kslide,host_priv_subsystem,insn::kData_only);
    loc_t thetable = 0;
    while (1){
        --memiterator;--memiterator; //dec 8 byte
        struct _anon{
            uint64_t ptr;
            uint64_t z0;
            uint64_t z1;
            uint64_t z2;
        } *obj = (struct _anon*)(loc_t)memiterator;
        
        if (!obj->z0 && !obj->z1 &&
            !memcmp(&obj[0], &obj[1], sizeof(struct _anon)) &&
            !memcmp(&obj[0], &obj[2], sizeof(struct _anon)) &&
            !memcmp(&obj[0], &obj[3], sizeof(struct _anon)) &&
            !memcmp(&obj[0], &obj[4], sizeof(struct _anon)) &&
            !obj[-1].ptr && obj[-1].z0 == 1 && !obj[-1].z1) {
            thetable = (loc_t)memiterator.pc();
            break;
        }
    }
    
    loc_t iokit_user_client_trap_func = (loc_t)insn::deref(_segments, _kslide, thetable + 100*4*8 - 8);
    
    insn bl_to_iokit_add_connect_reference(_segments,_kslide,iokit_user_client_trap_func);
    while (++bl_to_iokit_add_connect_reference != insn::bl);
    
    insn iokit_add_connect_reference(bl_to_iokit_add_connect_reference,(loc_t)(bl_to_iokit_add_connect_reference.imm()*4 + bl_to_iokit_add_connect_reference.pc()));
    
    while (++iokit_add_connect_reference != insn::add || iokit_add_connect_reference.rd() != 8 || ++iokit_add_connect_reference != insn::ldxr || iokit_add_connect_reference.rn() != 8);

    return (uint32_t)((--iokit_add_connect_reference).imm());
}

uint32_t offsetfinder64::find_ipc_space_is_task(){
    loc_t str = memmem("\"ipc_task_init\"", sizeof("\"ipc_task_init\""));
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");
    
    loc_t bref = find_rel_branch_source(insn(_segments,_kslide,ref), true, 2);
    
    insn istr(_segments,_kslide,bref);
    
    while (++istr != insn::str);
    
    return (uint32_t)istr.imm();
}

uint32_t offsetfinder64::find_sizeof_task(){
    loc_t str = memmem("tasks", sizeof("tasks"));
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");
    
    insn thebl(_segments, _kslide, ref);
    
    while (++thebl != insn::bl || (loc_t)(thebl.pc() + 4*thebl.imm()) != find_sym("_zinit"));
    
    --thebl;
    
    return (uint32_t)thebl.imm();
}

loc_t offsetfinder64::find_rop_add_x0_x0_0x10(){
    constexpr char ropbytes[] = "\x00\x40\x00\x91\xC0\x03\x5F\xD6";
    return [](const void *little, size_t little_len, vector<text_t>segments, offset_t kslide)->loc_t{
        for (auto seg : segments) {
            if (!seg.isExec)
                continue;
            
            if (loc_t rt = (loc_t)::memmem(seg.map, seg.size, little, little_len)) {
                return rt-seg.map+seg.base+kslide;
            }
        }
        return 0;
    }(ropbytes,sizeof(ropbytes)-1,_segments,_kslide);
}

loc_t offsetfinder64::find_rop_ldr_x0_x0_0x10(){
    constexpr char ropbytes[] = "\x00\x08\x40\xF9\xC0\x03\x5F\xD6";
    return [](const void *little, size_t little_len, vector<text_t>segments, offset_t kslide)->loc_t{
        for (auto seg : segments) {
            if (!seg.isExec)
                continue;
            
            if (loc_t rt = (loc_t)::memmem(seg.map, seg.size, little, little_len)) {
                return rt-seg.map+seg.base+kslide;
            }
        }
        return 0;
    }(ropbytes,sizeof(ropbytes)-1,_segments,_kslide);
}

#pragma mark patch_finders
void slide_ptr(class patch *p,uint64_t slide){
    slide += *(uint64_t*)p->_patch;
    memcpy((void*)p->_patch, &slide, 8);
}

patch offsetfinder64::find_sandbox_patch(){
    loc_t str = memmem("process-exec denied while updating label", sizeof("process-exec denied while updating label")-1);
    retassure(str, "Failed to find str");

    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");

    insn bdst(_segments, _kslide, ref);
    for (int i=0; i<4; i++) {
        while (--bdst != insn::bl){
        }
    }
    --bdst;
    
    loc_t cbz = find_rel_branch_source(bdst, true);
    
    return patch(cbz, patch_nop, patch_nop_size);
}


patch offsetfinder64::find_amfi_substrate_patch(){
    loc_t str = memmem("AMFI: hook..execve() killing pid %u: %s", sizeof("AMFI: hook..execve() killing pid %u: %s")-1);
    retassure(str, "Failed to find str");

    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");

    insn funcend(_segments, _kslide, ref);
    while (++funcend != insn::ret);
    
    insn tbnz(funcend);
    while (--tbnz != insn::tbnz);
    
    constexpr char mypatch[] = "\x1F\x20\x03\xD5\x00\x78\x16\x12\x1F\x20\x03\xD5\x00\x00\x80\x52\xE9\x01\x80\x52";
    return {(loc_t)tbnz.pc(),mypatch,sizeof(mypatch)-1};
}

patch offsetfinder64::find_cs_enforcement_disable_amfi(){
    loc_t str = memmem("csflags", sizeof("csflags"));
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");

    insn cbz(_segments, _kslide, ref);
    while (--cbz != insn::cbz);
    
    insn movz(cbz);
    while (++movz != insn::movz);
    --movz;

    int anz = static_cast<int>((movz.pc()-cbz.pc())/4 +1);
    
    char mypatch[anz*4];
    for (int i=0; i<anz; i++) {
        ((uint32_t*)mypatch)[i] = *(uint32_t*)patch_nop;
    }
    
    return {(loc_t)cbz.pc(),mypatch,static_cast<size_t>(anz*4)};
}

patch offsetfinder64::find_i_can_has_debugger_patch_off(){
    loc_t str = memmem("Darwin Kernel", sizeof("Darwin Kernel")-1);
    retassure(str, "Failed to find str");
    
    str -=4;
    
    return {str,"\x01",1};
}

patch offsetfinder64::find_amfi_patch_offsets(){
    loc_t str = memmem("int _validateCodeDirectoryHashInDaemon", sizeof("int _validateCodeDirectoryHashInDaemon")-1);
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");

    insn bl_amfi_memcp(_segments, _kslide, ref);

    loc_t jscpl = 0;
    while (1) {
        while (++bl_amfi_memcp != insn::bl);
        
        try {
            jscpl = jump_stub_call_ptr_loc(bl_amfi_memcp);
        } catch (tihmstar::exception &e) {
            continue;
        }
        if (insn::deref(_segments, _kslide, jscpl) == (uint64_t)find_sym("_memcmp"))
            break;
    }
    
    /* find*/
    //movz w0, #0x0
    //ret
    insn ret0(_segments, _kslide, find_sym("_memcmp"));
    for (;; --ret0) {
#warning TODO change this to proper instruction parsing
        if (ret0.value() == *(uint32_t*)"\x00\x00\x80\x52" //movz       w0, #0x0
            && (ret0+1) == insn::ret) {
            break;
        }
    }
    
    uint64_t gadget = ret0.pc();
    return {jscpl,&gadget,sizeof(gadget),slide_ptr};
}

patch offsetfinder64::find_proc_enforce(){
    loc_t str = memmem("Enforce MAC policy on process operations", sizeof("Enforce MAC policy on process operations")-1);
    retassure(str, "Failed to find str");
    
    loc_t valref = memmem(&str, sizeof(str));
    retassure(valref, "Failed to find val ref");
    
    loc_t proc_enforce_ptr = valref - (5 * sizeof(uint64_t));
    
    loc_t proc_enforce_val_loc = (loc_t)insn::deref(_segments, _kslide, proc_enforce_ptr);
    
    uint8_t mypatch = 1;
    return {proc_enforce_val_loc,&mypatch,1};
}

vector<patch> offsetfinder64::find_nosuid_off(){
    loc_t str = memmem("\"mount_common(): mount of %s filesystem failed with %d, but vnode list is not empty.\"", sizeof("\"mount_common(): mount of %s filesystem failed with %d, but vnode list is not empty.\"")-1);
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");

    insn ldr(_segments, _kslide,ref);
    
    while (--ldr != insn::ldr);
    
    loc_t cbnz = find_rel_branch_source(ldr, 1);
    
    insn bl_vfs_context_is64bit(ldr,cbnz);
    while (--bl_vfs_context_is64bit != insn::bl || bl_vfs_context_is64bit.imm()*4+bl_vfs_context_is64bit.pc() != (uint64_t)find_sym("_vfs_context_is64bit"));
    
    //patch1
    insn movk(bl_vfs_context_is64bit);
    while (--movk != insn::movk || movk.imm() != 8);
    
    //patch2
    insn orr(bl_vfs_context_is64bit);
    while (--orr != insn::orr || movk.imm() != 8);
    
    return {{(loc_t)movk.pc(),patch_nop,patch_nop_size},{(loc_t)orr.pc(),"\xE9\x03\x08\x2A",4}}; // mov w9, w8
}

patch offsetfinder64::find_remount_patch_offset(){
    loc_t off = find_syscall0();
    
    loc_t syscall_mac_mount = (off + 3*(424-1)*sizeof(uint64_t));

    loc_t __mac_mount = (loc_t)insn::deref(_segments, _kslide, syscall_mac_mount);
    
    insn patchloc(_segments, _kslide, __mac_mount);
    
    while (++patchloc != insn::tbz || patchloc.rt() != 8 || patchloc.other() != 6);
    
    --patchloc;
    
    constexpr char mypatch[] = "\xC8\x00\x80\x52"; //movz w8, #0x6
    return {(loc_t)patchloc.pc(),mypatch,sizeof(mypatch)-1};
}

patch offsetfinder64::find_lwvm_patch_offsets(){
    loc_t str = memmem("_mapForIO", sizeof("_mapForIO")-1);
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");
    
    insn functop(_segments,_kslide,ref);
    
    while (--functop != insn::stp || (functop+1) != insn::stp || (functop+2) != insn::stp || (functop-2) != insn::ret);
    
    insn dstfunc(functop);
    loc_t destination = 0;
    while (1) {
        while (++dstfunc != insn::bl);
        
        try {
            destination = jump_stub_call_ptr_loc(dstfunc);
        } catch (tihmstar::exception &e) {
            continue;
        }
        if (insn::deref(_segments, _kslide, destination) == (uint64_t)find_sym("_PE_i_can_has_kernel_configuration"))
            break;
    }
    
    while (++dstfunc != insn::bcond || dstfunc.other() != insn::cond::NE);
    
    loc_t target = (loc_t)( dstfunc.pc() + 4*dstfunc.imm());
    
    return {destination,&target,sizeof(target),slide_ptr};
}

loc_t offsetfinder64::find_sbops(){
    loc_t str = memmem("Seatbelt sandbox policy", sizeof("Seatbelt sandbox policy")-1);
    retassure(str, "Failed to find str");
    
    loc_t ref = memmem(&str, sizeof(str));
    retassure(ref, "Failed to find ref");
    
    return (loc_t)insn::deref(_segments, _kslide, ref+0x18);
}

#pragma mark KPP bypass
loc_t offsetfinder64::find_gPhysBase(){
    loc_t str = memmem("\"pmap_map_high_window_bd: area too large", sizeof("\"pmap_map_high_window_bd: area too large")-1);
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(_segments, _kslide, str);
    retassure(ref, "literal ref to str");
    
    insn tgtref(_segments, _kslide, ref);

    loc_t gPhysBase = 0;
    
    while (++tgtref != insn::adrp);
    gPhysBase = (loc_t)tgtref.imm();
    
    while (++tgtref != insn::ldr);
    gPhysBase += tgtref.imm();
    
    return gPhysBase;
}

loc_t offsetfinder64::find_kernel_pmap(){
    return find_sym("_kernel_pmap");
}

loc_t offsetfinder64::find_cpacr_write(){
    return memmem("\x40\x10\x18\xD5", 4);
}


offsetfinder64::~offsetfinder64(){
    if (_freeKernel) safeFree(_kdata);
}










//
