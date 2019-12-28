//
//  insn.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include "all_liboffsetfinder.hpp"
#include <liboffsetfinder64/insn.hpp>
#include <liboffsetfinder64/OFexception.hpp>

using namespace tihmstar::offsetfinder64;


insn::insn(uint32_t opcode, uint64_t pc) : _opcode(opcode), _pc(pc), _type(unknown){
    //
}

#pragma mark reference manual helpers
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

__attribute__((always_inline)) static uint64_t replicate(uint64_t val, int bits){
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

static inline uint64_t ror(uint64_t elt, unsigned size)
{
    return ((elt & 1) << (size-1)) | (elt >> 1);
}

static inline uint64_t AArch64_AM_decodeLogicalImmediate(uint64_t val, unsigned regSize){
    // Extract the N, imms, and immr fields.
    unsigned N = (val >> 12) & 1;
    unsigned immr = (val >> 6) & 0x3f;
    unsigned imms = val & 0x3f;
    unsigned i;
    
    // assert((regSize == 64 || N == 0) && "undefined logical immediate encoding");
//    int len = 31 - countLeadingZeros((N << 6) | (~imms & 0x3f));
    int len = highestSetBit( (uint64_t)((N<<6) | ((~imms) & 0b111111)) );

    // assert(len >= 0 && "undefined logical immediate encoding");
    unsigned size = (1 << len);
    unsigned R = immr & (size - 1);
    unsigned S = imms & (size - 1);
    // assert(S != size - 1 && "undefined logical immediate encoding");
    uint64_t pattern = (1ULL << (S + 1)) - 1;
    for (i = 0; i < R; ++i)
        pattern = ror(pattern, size);
    
    // Replicate the pattern to fill the regSize.
    while (size != regSize) {
        pattern |= (pattern << size);
        size *= 2;
    }
    
    return pattern;
}

__attribute__((always_inline)) static std::pair<int64_t, int64_t> DecodeBitMasks(uint64_t immN, uint8_t imms, uint8_t immr, bool immediate){
    uint64_t tmask = 0, wmask = 0;
    int8_t levels = 0; //6bit

    int len = highestSetBit( (uint64_t)((immN<<6) | ((~imms) & 0b111111)) );
    assure(len != -1); //reserved value
    levels = ones(len);

    assure(immediate && (imms & levels) != levels); //reserved value

    uint8_t S = imms & levels;
    uint8_t R = immr & levels;

    uint8_t esize = 1 << len;

    uint8_t diff = S - R; // 6-bit subtract with borrow
    
    uint8_t d = (diff & ((1<<len)-1)) << 1;
    
    uint64_t welem = ones(S + 1);
    uint64_t telem = ones(d + 1);
    
    uint64_t asd = ROR(welem, R, 32);
    
    wmask = replicate(ROR(welem, R, 32),esize);
    tmask = replicate(telem,esize);
#warning TODO incomplete function implementation!
    return {wmask,tmask};
}

#pragma mark static type determinition

bool insn::is_adrp(uint32_t i){
    return BIT_RANGE(i, 24, 28) == 0b10000 && (i>>31);
}

bool insn::is_adr(uint32_t i){
    return BIT_RANGE(i, 24, 28) == 0b10000 && !(i>>31);
}

bool insn::is_add(uint32_t i){
    return BIT_RANGE(i, 24, 30) == 0b0010001;
}

bool insn::is_sub(uint32_t i){
    return BIT_RANGE(i, 24, 30) == 0b1010001;
}

bool insn::is_bl(uint32_t i){
    return (i>>26) == 0b100101;
}

bool insn::is_cbz(uint32_t i){
    return BIT_RANGE(i, 24, 30) == 0b0110100;
}

bool insn::is_ret(uint32_t i){
    return ((0b11111 << 5) | i) == 0b11010110010111110000001111100000;
}

bool insn::is_tbnz(uint32_t i){
    return BIT_RANGE(i, 24, 30) == 0b0110111;
}

bool insn::is_br(uint32_t i){
    return ((0b11111 << 5) | i) == 0b11010110000111110000001111100000;
}

bool insn::is_ldr(uint32_t i){
#warning TODO recheck this mask
    return (((i>>22) | 0b0100000000) == 0b1111100001 && ((i>>10) % 4)) || ((i>>22 | 0b0100000000) == 0b1111100101) || ((i>>23) == 0b00011000);
}

bool insn::is_ldrh(uint32_t i){
    return ((BIT_RANGE(i, 21, 31) == 0b01000011) && (BIT_RANGE(i, 10, 11) == 0b10)) /* register*/
        || ((BIT_RANGE(i, 21, 31) == 0b01111000010)
            && ((BIT_RANGE(i, 10, 11) == 0b01) /* imm post-index*/ || (BIT_RANGE(i, 10, 11) == 0b11) /* imm pre-index*/ ))
        || (BIT_RANGE(i, 22, 31) == 0b0111100101) /*unsigned offset */;
}

bool insn::is_cbnz(uint32_t i){
    return BIT_RANGE(i, 24, 30) == 0b0110101;
}

bool insn::is_movk(uint32_t i){
    return BIT_RANGE(i, 23, 30) == 0b11100101;
}

bool insn::is_orr(uint32_t i){
    return BIT_RANGE(i, 23, 30) == 0b01100100;
}

bool insn::is_and(uint32_t i){
    return BIT_RANGE(i, 23, 30) == 0b00100100; //immediate
//    return BIT_RANGE(i, 24, 30) == 0b0001010; //shifted register
}

bool insn::is_tbz(uint32_t i){
    return BIT_RANGE(i, 24, 30) == 0b0110110;
}

bool insn::is_ldxr(uint32_t i){
    return (BIT_RANGE(i, 24, 29) == 0b001000) && (i >> 31) && BIT_AT(i, 22);
}

bool insn::is_ldrb(uint32_t i){
    return BIT_RANGE(i, 21, 31) == 0b00111000010 || //Immediate post/pre -indexed
           BIT_RANGE(i, 22, 31) == 0b0011100101  || //Immediate unsigned offset
           (BIT_RANGE(i, 21, 31) == 0b00111000011 && BIT_RANGE(i, 10, 11) == 0b10); //Register
}

bool insn::is_str(uint32_t i){
#warning TODO redo this! currently only recognises STR (immediate)
    return (BIT_RANGE(i, 22, 29) == 0b11100100) && (i >> 31);
}

bool insn::is_strb(uint32_t i){
    return ((BIT_RANGE(i, 21, 31) == 0b00111000001) && (BIT_RANGE(i, 10, 11) == 0b10) /* register*/)
        /* immediate */
        || ((BIT_RANGE(i, 21, 31) == 0b00111000000)
                && ((BIT_RANGE(i, 10, 11) == 0b01) || (BIT_RANGE(i, 10, 11) == 0b11)))
        || (BIT_RANGE(i, 22, 31) == 0b0011100100); /* unsigned offset */
}

bool insn::is_stp(uint32_t i){
#warning TODO redo this! currently only recognises STR (immediate)
    return (BIT_RANGE(i, 25, 30) == 0b010100) && !BIT_AT(i, 22);
}

bool insn::is_movz(uint32_t i){
    return (BIT_RANGE(i, 23, 30) == 0b10100101);
}

bool insn::is_mov(uint32_t i){
    return (BIT_RANGE(i, 24, 30) == 0b0101010) && (BIT_AT(i, 21) == 0);
}

bool insn::is_bcond(uint32_t i){
    return (BIT_RANGE(i, 24, 31) == 0b01010100) && !BIT_AT(i, 4);
}

bool insn::is_b(uint32_t i){
    return (BIT_RANGE(i, 26, 31) == 0b000101);
}

bool insn::is_nop(uint32_t i){
    return (BIT_RANGE(i, 12, 31) == 0b11010101000000110010) && (0b11111 % (1<<5));
}

bool insn::is_csel(uint32_t i){
    return (BIT_RANGE(i, 21, 30) == 0b0011010100) && (BIT_RANGE(i, 10, 11) == 0b00);
}

bool insn::is_mrs(uint32_t i){
    return (BIT_RANGE(i, 20, 31) == 0b110101010011);
}

bool insn::is_subs(uint32_t i){
    return (BIT_RANGE(i, 21, 30) == 0x1101011001)/* register_extended */ || (BIT_RANGE(i, 24, 30) == 0b1101011)/* register */ || (BIT_RANGE(i, 24, 30) == 0b1110001)/* immediate */;
}

bool insn::is_ccmp(uint32_t i){
    return (BIT_RANGE(i, 21, 30) == 0b1111010010)/* register */;
}


uint32_t insn::opcode(){
    return _opcode;
}

uint64_t insn::pc(){
    return _pc;
}

enum insn::type insn::type(){
    if (_type != unknown) {
        return _type;
    }
    else if (is_adrp(_opcode))
        _type = adrp;
    else if (is_adr(_opcode))
        _type = adr;
    else if (is_add(_opcode))
        _type = add;
    else if (is_sub(_opcode))
        _type = sub;
    else if (is_bl(_opcode))
        _type = bl;
    else if (is_cbz(_opcode))
        _type = cbz;
    else if (is_ret(_opcode))
        _type = ret;
    else if (is_tbnz(_opcode))
        _type = tbnz;
    else if (is_br(_opcode))
        _type = br;
    else if (is_ldr(_opcode))
        _type = ldr;
    else if (is_ldrh(_opcode))
        _type = ldrh;
    else if (is_cbnz(_opcode))
        _type = cbnz;
    else if (is_movk(_opcode))
        _type = movk;
    else if (is_orr(_opcode))
        _type = orr;
    else if (is_and(_opcode))
        _type = and_;
    else if (is_tbz(_opcode))
        _type = tbz;
    else if (is_ldxr(_opcode))
        _type = ldxr;
    else if (is_ldrb(_opcode))
        _type = ldrb;
    else if (is_str(_opcode))
        _type = str;
    else if (is_strb(_opcode))
        _type = strb;
    else if (is_stp(_opcode))
        _type = stp;
    else if (is_movz(_opcode))
        _type = movz;
    else if (is_bcond(_opcode))
        _type = bcond;
    else if (is_b(_opcode))
        _type = b;
    else if (is_nop(_opcode))
        _type = nop;
    else if (is_csel(_opcode))
        _type = csel;
    else if (is_mov(_opcode))
        _type = mov;
    else if (is_mrs(_opcode))
        _type = mrs;
    else if (is_subs(_opcode))
        _type = subs;
    else if (is_ccmp(_opcode))
        _type = ccmp;

    return _type;
}

enum insn::subtype insn::subtype(){
    switch (type()) {
        case ldrh:
            if (((BIT_RANGE(_opcode, 21, 31) == 0b01000011) && (BIT_RANGE(_opcode, 10, 11) == 0b10))) {
                return st_register;
            }else{
                return st_immediate;
            }
        case ldr:
            if ((((_opcode>>22) | (1 << 8)) == 0b1111100001) && BIT_RANGE(_opcode, 10, 11) == 0b10)
                return st_register;
            else if (_opcode>>31)
                return st_immediate;
            else
                return st_literal;
            break;
        case ldrb:
            if (BIT_RANGE(_opcode, 21, 31) == 0b00111000011 && BIT_RANGE(_opcode, 10, 11) == 0b10)
                return st_register;
            else
                return st_immediate;
            break;
        case strb:
            if ((BIT_RANGE(_opcode, 21, 31) == 0b00111000001) && (BIT_RANGE(_opcode, 10, 11) == 0b10) /* register*/) {
                return st_register;
            }else{
                return st_immediate;
            }
        case subs:
            if (BIT_RANGE(_opcode, 21, 30) == 0x1101011001 /* register_extended */) {
                return st_register_extended;
            }else if (BIT_RANGE(_opcode, 24, 30) == 0b1101011/* register */) {
                return st_register;
            }else if (BIT_RANGE(_opcode, 24, 30) == 0b1110001 /* immediate */){
                return st_immediate;
            }else{
                reterror("unexpected subtype");
            }
        case ccmp:
            if (BIT_RANGE(_opcode, 21, 30) == 0b1111010010/* register */){
                return st_register;
            }else{
                reterror("unexpected subtype");
            }
        case movz:
        case movk:
            return st_immediate;
        case mov:
            return st_register;
        default:
            return st_general;
    }
}

enum insn::supertype insn::supertype(){
    switch (type()) {
        case bl:
        case cbz:
        case cbnz:
        case tbnz:
        case bcond:
        case b:
            return sut_branch_imm;

        case ldr:
        case ldrh:
        case ldrb:
        case ldxr:
        case str:
        case strb:
        case stp:
            return sut_memory;
        default:
            return sut_general;
    }
}

#pragma mark register

int64_t insn::imm(){
    switch (type()) {
        case unknown:
            reterror("can't get imm value of unknown instruction");
            break;
        case adrp:
            return ((_pc>>12)<<12) + signExtend64(((((_opcode % (1<<24))>>5)<<2) | BIT_RANGE(_opcode, 29, 30))<<12,32);
        case adr:
            return _pc + signExtend64((BIT_RANGE(_opcode, 5, 23)<<2) | (BIT_RANGE(_opcode, 29, 30)), 21);
        case add:
        case sub:
            return BIT_RANGE(_opcode, 10, 21) << (((_opcode>>22)&1) * 12);
        case bl:
            return _pc + (signExtend64(_opcode % (1<<26), 25) << 2); //untested
        case cbz:
        case cbnz:
        case bcond:
            return _pc + (signExtend64(BIT_RANGE(_opcode, 5, 23), 19)<<2); //untested
        case tbnz:
            return _pc + (signExtend64(BIT_RANGE(_opcode, 5, 18), 13)<<2); //untested
        case movk:
        case movz:
            return BIT_RANGE(_opcode, 5, 20) << (BIT_RANGE(_opcode, 21, 22) * 16);
        case ldr:
            if(subtype() != st_immediate){
                reterror("can't get imm value of ldr that has non immediate subtype");
                break;
            }
            if(BIT_RANGE(_opcode, 24, 25)){
                // Unsigned Offset
                return BIT_RANGE(_opcode, 10, 21) << (_opcode>>30);
            }else{
                // Signed Offset
                return signExtend64(BIT_RANGE(_opcode, 12, 21), 9); //untested
            }
        case strb:
            if(subtype() != st_immediate){
                reterror("can't get imm value of ldr that has non immediate subtype");
                break;
            }
            if ((BIT_RANGE(_opcode, 22, 31) == 0b0011100100) /* unsigned offset */) {
                return BIT_RANGE(_opcode, 12, 20);
            }else{
                return BIT_RANGE(_opcode, 10, 21);
            }
        case ldrh:
            if(subtype() != st_immediate){
                reterror("can't get imm value of ldr that has non immediate subtype");
                break;
            }
            if (((BIT_RANGE(_opcode, 21, 31) == 0b01111000010)
                 && ((BIT_RANGE(_opcode, 10, 11) == 0b01) /* imm post-index*/ || (BIT_RANGE(_opcode, 10, 11) == 0b11) /* imm pre-index*/ ))){
                return BIT_RANGE(_opcode, 12, 20);
            }else{
                return BIT_RANGE(_opcode, 10, 21) << BIT_RANGE(_opcode, 30, 31);
            }
        case ldrb:
            if (st_immediate) {
                if (BIT_RANGE(_opcode, 22, 31) == 0b0011100101) { //unsigned
                    return BIT_RANGE(_opcode, 10, 21) << BIT_RANGE(_opcode, 30, 31);
                }else{  //pre/post indexed
                    return BIT_RANGE(_opcode, 12, 20) << BIT_RANGE(_opcode, 30, 31);
                }
            }else{
                reterror("ldrb must be st_immediate for imm to be defined!");
            }
        case str:
#warning TODO rewrite this! currently only unsigned offset supported
            // Unsigned Offset
            return BIT_RANGE(_opcode, 10, 21) << (_opcode>>30);
        case orr:
            return DecodeBitMasks(BIT_AT(_opcode, 22),BIT_RANGE(_opcode, 10, 15),BIT_RANGE(_opcode, 16,21), true).first;
        case and_:
        {
            int64_t val = DecodeBitMasks(BIT_AT(_opcode, 22),BIT_RANGE(_opcode, 10, 15),BIT_RANGE(_opcode, 16,21), true).first;
            if (!BIT_AT(_opcode, 31))
                val |= (((uint64_t)1<<32)-1) << 32;
            return val;
        }
        case tbz:
            return BIT_RANGE(_opcode, 5, 18);
        case stp:
            return signExtend64(BIT_RANGE(_opcode, 15, 21),7) << (2+(_opcode>>31));
        case b:
            return _pc + ((_opcode % (1<< 26))<<2);
        default:
            reterror("failed to get imm value");
            break;
    }
    return 0;
}

uint8_t insn::rd(){
    switch (type()) {
        case unknown:
            reterror("can't get rd of unknown instruction");
            break;
        case subs:
        case adrp:
        case adr:
        case add:
        case sub:
        case movk:
        case orr:
        case and_:
        case movz:
        case mov:
        case csel:
            return (_opcode % (1<<5));

        default:
            reterror("failed to get rd");
            break;
    }
}

uint8_t insn::rn(){
    switch (type()) {
        case unknown:
            reterror("can't get rn of unknown instruction");
            break;
        case subs:
        case add:
        case sub:
        case ret:
        case br:
        case orr:
        case and_:
        case ldxr:
        case ldrb:
        case str:
        case strb:
        case ldr:
        case ldrh:
        case stp:
        case csel:
        case mov:
        case ccmp:
            return BIT_RANGE(_opcode, 5, 9);

        default:
            reterror("failed to get rn");
            break;
    }
}

uint8_t insn::rt(){
    switch (type()) {
        case unknown:
            reterror("can't get rt of unknown instruction");
            break;
        case cbz:
        case cbnz:
        case tbnz:
        case tbz:
        case ldxr:
        case ldrb:
        case str:
        case strb:
        case ldr:
        case ldrh:
        case stp:
        case mrs:
            return (_opcode % (1<<5));

        default:
            reterror("failed to get rt");
            break;
    }
}

uint8_t insn::rt2(){
    switch (type()) {
        case stp:
            return BIT_RANGE(_opcode, 10, 14);

        default:
            reterror("failed to get rt2");
            break;
    }
}

uint8_t insn::rm(){
    switch (type()) {
        case ccmp:
            retassure(subtype() == st_register, "wrong subtype");
        case csel:
        case mov:
        case subs:
            return BIT_RANGE(_opcode, 16, 20);
        default:
            reterror("failed to get rm");
            break;
    }
}

insn::cond insn::condition(){
    uint8_t ret = 0;
    switch (type()) {
        case ccmp:
            ret = BIT_RANGE(_opcode, 12, 15);
            break;
            
        default:
            reterror("failed to get condition");
            break;
    }
    return (insn::cond)ret;
}

uint64_t insn::special(){
    switch (type()) {
        case mrs:
            return BIT_RANGE(_opcode, 5, 19);
        case ccmp:
            return BIT_RANGE(_opcode, 0, 3);
        default:
            reterror("failed to get special");
            break;
    }
}


#pragma mark cast operators
insn::operator enum type(){
    return type();
}

insn::operator loc_t(){
    return (loc_t)_pc;
}

#pragma mark new insn constructors

insn insn::new_general_adr(loc_t pc, int64_t imm, uint8_t rd){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b10000, 24);
    ret._opcode |= (rd % (1<<5));
    int64_t diff = imm - ret.imm();
#warning TODO is this distance validation correct??
    if (diff > 0) {
        assure(diff < (1LL<<19));
    }else{
        assure(-diff < (1LL<<19));
    }
    ret._opcode |= SET_BITS(BIT_RANGE(diff,0,1), 29);
    ret._opcode |= SET_BITS(BIT_RANGE(diff,2,19), 5);
    
    return ret;
}

insn insn::new_register_mov(loc_t pc, int64_t imm, uint8_t rd, uint8_t rn, uint8_t rm){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b0101010, 24) | SET_BITS(1, 31);
    ret._opcode |= (rd % (1<<5));
    ret._opcode |= SET_BITS(rm & 0b11111, 16) ;
    ret._opcode |= SET_BITS(rn & 0b11111, 5) ;
    ret._opcode |= SET_BITS(imm & 0b111111, 10) ;
    
    return ret;
}

insn insn::new_immediate_bl(loc_t pc, int64_t imm){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b100101, 26);
    imm -= (uint64_t)pc;
    imm >>=2;
    ret._opcode |= imm & ((1<<26)-1);
    
    return ret;
}

insn insn::new_immediate_b(loc_t pc, int64_t imm){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b000101, 26);
    imm -= pc;
    imm >>=2;
    ret._opcode |= imm & ((1<<27)-1);
    
    return ret;
}

insn insn::new_immediate_movz(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm){
    insn ret(0,pc);

    ret._opcode |= SET_BITS(0b10100101, 23) | SET_BITS(1, 31);//64bit val (x regs, not w regs)
    ret._opcode |= (rd % (1<<5));
    ret._opcode |= SET_BITS(imm & ((1<<16)-1), 5);
    ret._opcode |= SET_BITS(rm & 0b11, 21); //set shift here
    
    return ret;
}

insn insn::new_immediate_movk(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm){
    insn ret(0,pc);

    ret._opcode |= SET_BITS(0b11100101, 23) | SET_BITS(1, 31);//64bit val (x regs, not w regs)
    ret._opcode |= (rd % (1<<5));
    ret._opcode |= SET_BITS(imm & ((1<<16)-1), 5);
    ret._opcode |= SET_BITS(rm & 0b11, 21); //set shift here
    
    return ret;
}

insn insn::new_immediate_ldr(loc_t pc, int64_t imm, uint8_t rn, uint8_t rt){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b1111100101, 22);
    imm >>= (ret._opcode >> 30);
    imm %= (1 << 11);
    imm <<= 10;
    ret._opcode |= imm;
    
    ret._opcode |= SET_BITS(rn % (1<< 4), 5);
    ret._opcode |= SET_BITS(rt % (1<< 4), 0);

    return ret;
}

insn insn::new_register_ccmp(loc_t pc, cond condition, uint8_t flags, uint8_t rn, uint8_t rm){
    insn ret(0,pc);

    ret._opcode |= SET_BITS(0b1111010010, 21) | SET_BITS(1, 31);//64bit val (x regs, not w regs)

    ret._opcode |= SET_BITS(rm % (1<<5), 16);
    ret._opcode |= SET_BITS((uint8_t)condition % (1<<4), 12);
    ret._opcode |= SET_BITS(rn % (1<<5), 5);
    ret._opcode |= SET_BITS(flags % (1<<5), 0);

    return ret;
}
