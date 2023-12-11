//
//  ibootpatchfinder64_iOS15.cpp
//  libpatchfinder
//
//  Created by tihmstar on 01.10.21.
//

#include "ibootpatchfinder64_iOS15.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS15::get_sigcheck_img4_patch(){
    UNCACHEPATCHES;
    loc_t findpos = 0;
    vmem iter = _vmem->getIter();
    
    /* We are looking for this:
     0x00000001800312e4         ldr        x8, [x19, #0x10]
     0x00000001800312e8         cmp        x8, #0x4
     0x00000001800312ec         b.eq       loc_180031388

     0x00000001800312f0         cmp        x8, #0x2
     0x00000001800312f4         b.eq       loc_180031344

     0x00000001800312f8         cmp        x8, #0x1
     0x00000001800312fc         b.ne       loc_180031a88
     */
    
    while (!findpos) {
        if (++iter != insn::ldr || iter().imm() != 0x10) continue;

        if (++iter != insn::cmp || iter().imm() != 4) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        if (++iter != insn::cmp || iter().imm() != 2) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        if (++iter != insn::cmp || iter().imm() != 1) continue;
        if ((++iter).supertype() != insn::sut_branch_imm) continue;

        
        findpos = iter;
    }
    debug("findpos=0x%016llx",findpos);

    while (true) {
        while (++iter != insn::ldp);
        if (++iter != insn::ldp) continue;
        if (++iter != insn::ldp) continue;
        if (++iter != insn::ldp) continue;
        ++iter;
        break;
    }
    
    loc_t funcend = iter;
    debug("funcend=0x%016llx",funcend);
    
    while ((--iter != insn::mov || iter().rd() != 0))
        ;
    loc_t overwrite = iter;
    debug("overwrite=0x%016llx",overwrite);
    /*
        looking for:
     000000087000f7e4 mov x0, x20
     */

    pushINSN(insn::new_immediate_movz(overwrite, 0, 0, 0));
    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder64_iOS15::get_always_production_patch(){
    UNCACHEPATCHES;

    for (uint64_t demoteReg : {(uint64_t)0x3F500000UL,(uint64_t)0x481BC000UL,(uint64_t)0x20E02A000UL,(uint64_t)0x2102BC000UL,(uint64_t)0x2352BC000UL}) {
        loc_t demoteRef = -4;
        while ((demoteRef = find_literal_ref(demoteReg,0,demoteRef+4))) {
            vmem iter = _vmem->getIter(demoteRef);
            uint8_t ldrdst = -1;
            loc_t ldrpos = 0;
            
            iter+=2;
            if (iter() == insn::and_) {
                if ((uint32_t)iter().imm() != 1) continue;
            }else if (iter() == insn::lsl){
                if ((uint32_t)iter().imm() != 8) continue;
                reterror("UNIMPLEMENTED");
            }else{
                continue;
            }
            iter = ldrpos = demoteRef+4;
            retassure(iter() == insn::ldr, "should be ldr here!");
            ldrdst = iter().rt();
            debug("demoteReg=0x%016llx",demoteReg);
            debug("demoteRef=0x%016llx",demoteRef);
            loc_t demoteBof = 0;
            {
                uint64_t curReg = 0;
                while (--iter != insn::movk)
                    ;
                curReg |= iter().imm();
                if (curReg == demoteReg) goto doneFindDemoteBof;
                retassure(--iter == insn::movk || iter() == insn::movz, "unexpected insn");
                curReg |= iter().imm();
                if (curReg == demoteReg) goto doneFindDemoteBof;
                if (--iter != insn::movz){
                    loc_t bdst = iter.pc()+4;
                    loc_t start = bdst;
                    while (true) {
                        start = find_branch_ref(bdst, -0x200, 0, start-4);
                        iter = start-4;
                        if ((curReg | iter().imm()) == demoteReg) break;
                    }
                }
                retassure(iter() == insn::movz, "unexpected insn");
                curReg |= iter().imm();
            doneFindDemoteBof:;
                retassure(curReg == demoteReg, "Failed to find demoteBof");
                demoteBof = iter;
            }
            debug("demoteBof=0x%016llx",demoteBof);

            /*
             You would not believe your eyes
             if ten million fireflies
             Lit up the world as I fell asleep
             */
            loc_t ref = find_literal_ref(0x20000200);
            debug("ref=0x%016llx",ref);
            assure(ref);
            loc_t refbof = find_bof(ref);
            debug("refbof=0x%016llx",refbof);
            assure(refbof);
            iter = refbof;
            while (true) {
                while (++iter != insn::bl);
                assure(iter.pc() < ref);
                loc_t dst = iter().imm();
                if (demoteBof == dst) {
                    //direct call
                    break;
                }else{
                    vmem iter2(iter,dst);
                    if (iter2() == insn::b) {
                        //indirect call through unconditional branch
                        dst = iter2().imm();
                        if (demoteBof == dst) {
                            break;
                        }
                    }
                    //indirect call through proxy function. sigh
                    int insncnt = 0;
                    while (++iter2 != insn::ret) retassure(++insncnt < 5, "not a proxy function");
                    
                    //find bl
                    while (--iter2 != insn::bl) retassure(--insncnt >0, "no bl in proxy func");
                    
                    //are we there yet?
                    dst = iter2().imm();
                    
                    vmem iter3 = _vmem->getIter(dst);
                    for (int i=0; i<6; i++) {
                        ++iter3;
                    retry:
                        if (iter3() == insn::b) {
                            if (iter3().imm() == iter3.pc()) break;
                            iter3 = iter3().imm();
                            goto retry;
                        }
                        if (iter3.pc() == demoteRef) goto found;
                    }
                    continue;
                    
                found:
                    //yes! but we need to remove the proxy for our detection to work
                    pushINSN(insn::new_immediate_bl(iter, dst));
                    break;
                }
            }
            
            {
                uint32_t shellcode_insn_cnt = 7; //commitment
                loc_t shellcode = findnops(shellcode_insn_cnt + 2*2/*8 byte ptr*/);
                debug("shellcode=0x%016llx",shellcode);
                
                uint32_t retInsn = 6; //commitment

            #define cPC (shellcode+(insnNum++)*4)
                int insnNum = 0;
                
                pushINSN(insn::new_literal_ldr(cPC, shellcode+shellcode_insn_cnt*4, ldrdst));
                pushINSN(insn::new_register_cmp(cPC, 0, 30, ldrdst, -1));
                pushINSN(insn::new_literal_ldr(cPC, shellcode+shellcode_insn_cnt*4+8, ldrdst)); //get the truth
                pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0, ldrdst, ldrdst));
                pushINSN(insn::new_immediate_bcond(cPC, shellcode+(retInsn)*4, insn::EQ));
                pushINSN(insn::new_immediate_movz(cPC, 1, ldrdst, 0)); //always production
                assure(insnNum == retInsn);
                pushINSN(insn::new_immediate_b(cPC, ldrpos+4));
                assure(insnNum == shellcode_insn_cnt);
            #undef cPC
                uint64_t v = iter.pc()+4;
                patches.push_back({shellcode+4*shellcode_insn_cnt,&v,sizeof(v)});
                patches.push_back({shellcode+4*shellcode_insn_cnt+8,&demoteReg,sizeof(demoteReg)});

                pushINSN(insn::new_immediate_b(demoteBof, shellcode));
            }

            RETCACHEPATCHES;
        }
    }
    reterror("Failed to find patches");
}
