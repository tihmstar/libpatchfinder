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
                and_,
                csel,
                mov,
                mrs,
                subs,
                cmp = subs,
                ccmp
            };
            enum subtype{
                st_general,
                st_register,
                st_register_extended,
                st_immediate,
                st_literal
            };
            enum supertype{
                sut_general,
                sut_branch_imm,
                sut_memory //load or store
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
            enum systemreg : uint64_t{
                tpidr_el1 = 0x4684
            };
            
        private:
            uint32_t _opcode;
            uint64_t _pc;
            type _type;
            
        public:
            insn(uint32_t opcode, uint64_t pc);
            
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
            static bool is_mov(uint32_t i);
            static bool is_bcond(uint32_t i);
            static bool is_b(uint32_t i);
            static bool is_nop(uint32_t i);
            static bool is_csel(uint32_t i);
            static bool is_mrs(uint32_t i);
            static bool is_subs(uint32_t i);
            static bool is_ccmp(uint32_t i);

        public:
            uint32_t opcode();
            uint64_t pc();
            
            type type();
            subtype subtype();
            supertype supertype();
            int64_t imm();
            uint8_t rd();
            uint8_t rn();
            uint8_t rt();
            uint8_t rt2();
            uint8_t rm();
            cond condition();
            uint64_t special();
            
        public: //cast operators
            operator enum type();
            operator loc_t();
            
              
        public: //constructor functions
            static insn new_general_adr(loc_t pc, int64_t imm, uint8_t rd);

            static insn new_register_mov(loc_t pc, int64_t imm, uint8_t rd, uint8_t rn, uint8_t rm);
            static insn new_register_ccmp(loc_t pc, cond condition, uint8_t flags, uint8_t rn, uint8_t rm);

            static insn new_immediatel_bl(loc_t pc, int64_t imm);
            static insn new_immediatel_b(loc_t pc, int64_t imm);
            static insn new_immediatel_movz(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm);
            static insn new_immediatel_movk(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm);
        };
    };
};





#endif /* insn_hpp */
