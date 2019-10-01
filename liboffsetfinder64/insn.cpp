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


insn::insn(uint32_t opcode, uint64_t pc) : _opcode(opcode), _pc(pc){
    //
}

insn::insn(loc_t pc, enum type t, enum subtype subt, int64_t imm, uint8_t rd, uint8_t rn, uint8_t rt, uint8_t other) :
    _pc((uint64_t)pc),
    _opcode(0)
{
    switch (t) {
        case adr:
            {
                _opcode |= SET_BITS(0b10000, 24);
                _opcode |= (rd % (1<<5));
                int64_t diff = imm - this->imm();
#warning TODO is this distance validation correct??
                if (diff > 0) {
                    assure(diff < (1LL<<19));
                }else{
                    assure(-diff < (1LL<<19));
                }
                _opcode |= SET_BITS(BIT_RANGE(diff,0,1), 29);
                _opcode |= SET_BITS(BIT_RANGE(diff,2,19), 5);
            }
            break;
            
        default:
            reterror("opcode generation not implemented");
    }
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

bool insn::is_stp(uint32_t i){
#warning TODO redo this! currently only recognises STR (immediate)
    return (BIT_RANGE(i, 25, 30) == 0b010100) && !BIT_AT(i, 22);
}

bool insn::is_movz(uint32_t i){
    return (BIT_RANGE(i, 23, 30) == 0b10100101);
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

uint32_t insn::opcode(){
    return _opcode;
}

enum insn::type insn::type(){
    if (is_adrp(_opcode))
        return adrp;
    else if (is_adr(_opcode))
        return adr;
    else if (is_add(_opcode))
        return add;
    else if (is_sub(_opcode))
        return sub;
    else if (is_bl(_opcode))
        return bl;
    else if (is_cbz(_opcode))
        return cbz;
    else if (is_ret(_opcode))
        return ret;
    else if (is_tbnz(_opcode))
        return tbnz;
    else if (is_br(_opcode))
        return br;
    else if (is_ldr(_opcode))
        return ldr;
    else if (is_cbnz(_opcode))
        return cbnz;
    else if (is_movk(_opcode))
        return movk;
    else if (is_orr(_opcode))
        return orr;
    else if (is_and(_opcode))
        return and_;
    else if (is_tbz(_opcode))
        return tbz;
    else if (is_ldxr(_opcode))
        return ldxr;
    else if (is_ldrb(_opcode))
        return ldrb;
    else if (is_str(_opcode))
        return str;
    else if (is_stp(_opcode))
        return stp;
    else if (is_movz(_opcode))
        return movz;
    else if (is_bcond(_opcode))
        return bcond;
    else if (is_b(_opcode))
        return b;
    else if (is_nop(_opcode))
        return nop;

    return unknown;
}

enum insn::subtype insn::subtype(){
    if (is_ldr(_opcode)) {
        if ((((_opcode>>22) | (1 << 8)) == 0b1111100001) && BIT_RANGE(_opcode, 10, 11) == 0b10)
            return st_register;
        else if (_opcode>>31)
            return st_immediate;
        else
            return st_literal;
    }else if (is_ldrb(_opcode)){
        if (BIT_RANGE(_opcode, 21, 31) == 0b00111000011 && BIT_RANGE(_opcode, 10, 11) == 0b10)
            return st_register;
        else
            return st_immediate;
    }
    return st_general;
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
        case tbnz:
        case bcond:
            return _pc + (signExtend64(BIT_RANGE(_opcode, 5, 23), 19)<<2); //untested
        case movk:
        case movz:
            return BIT_RANGE(_opcode, 5, 20);
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
        case adrp:
        case adr:
        case add:
        case sub:
        case movk:
        case orr:
        case and_:
        case movz:
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
        case add:
        case sub:
        case ret:
        case br:
        case orr:
        case and_:
        case ldxr:
        case ldrb:
        case str:
        case ldr:
        case stp:
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
        case ldr:
        case stp:
            return (_opcode % (1<<5));

        default:
            reterror("failed to get rt");
            break;
    }
}

uint8_t insn::other(){
    switch (type()) {
        case unknown:
            reterror("can't get other of unknown instruction");
            break;
        case tbz:
            return ((_opcode >>31) << 5) | BIT_RANGE(_opcode, 19, 23);
        case stp:
            return BIT_RANGE(_opcode, 10, 14); //Rt2
        case bcond:
            return 0; //condition
        case ldrb:
            if (subtype() == st_register)
                reterror("ERROR: unimplemented!");
            else
                reterror("ldrb must be st_register for this to be defined!");
        default:
            reterror("failed to get other");
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
