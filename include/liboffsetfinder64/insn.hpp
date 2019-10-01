//
//  insn.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef insn_hpp
#define insn_hpp

#include <liboffsetfinder64/common.h>
#include <vector>

namespace tihmstar{
    namespace offsetfinder64{
        class insn{
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
                sub,
                br,
                ldr,
                cbnz,
                movk,
                orr,
                tbz,
                ldxr,
                ldrb,
                str,
                stp,
                movz,
                bcond,
                b,
                nop,
                and_
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
            
        private:
            uint32_t _opcode;
            uint64_t _pc;
            
        public:
            insn(uint32_t opcode, uint64_t pc);
            insn(loc_t pc, type t, subtype subt, int64_t imm, uint8_t rd, uint8_t rn, uint8_t rt, uint8_t other);
            
        public: //static type determinition
            static bool is_adrp(uint32_t i);
            static bool is_adr(uint32_t i);
            static bool is_add(uint32_t i);
            static bool is_sub(uint32_t i);
            static bool is_bl(uint32_t i);
            static bool is_cbz(uint32_t i);
            static bool is_ret(uint32_t i);
            static bool is_tbnz(uint32_t i);
            static bool is_br(uint32_t i);
            static bool is_ldr(uint32_t i);
            static bool is_cbnz(uint32_t i);
            static bool is_movk(uint32_t i);
            static bool is_orr(uint32_t i);
            static bool is_and(uint32_t i);
            static bool is_tbz(uint32_t i);
            static bool is_ldxr(uint32_t i);
            static bool is_ldrb(uint32_t i);
            static bool is_str(uint32_t i);
            static bool is_stp(uint32_t i);
            static bool is_movz(uint32_t i);
            static bool is_bcond(uint32_t i);
            static bool is_b(uint32_t i);
            static bool is_nop(uint32_t i);
            
        public:
            uint32_t opcode();
            type type();
            subtype subtype();
            supertype supertype();
            int64_t imm();
            uint8_t rd();
            uint8_t rn();
            uint8_t rt();
            uint8_t other();
        
        public: //cast operators
            operator enum type();
            operator loc_t();
        };
    };
};


#endif /* insn_hpp */
