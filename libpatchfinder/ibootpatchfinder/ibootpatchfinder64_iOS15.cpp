//
//  ibootpatchfinder64_iOS15.cpp
//  libpatchfinder
//
//  Created by tihmstar on 01.10.21.
//
#include <libgeneral/macros.h>

#include "ibootpatchfinder64_iOS15.hpp"
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

ibootpatchfinder64_base::loc_t ibootpatchfinder64_iOS15::find_malloc(){
    UNCACHELOC;
    
    auto iter = _vmem->getIter();
    while (true) {
        auto isn = ++iter;
        if (isn == insn::movz && isn.subtype() == insn::st_immediate && isn.rd() == 0 && isn.imm() == 0x200) {
            auto isn2 = ++iter;
            if (isn2 == insn::movz && isn2.subtype() == insn::st_immediate && isn2.rd() == 1 && isn2.imm() == 0) {
                auto isn3 = ++iter;
                if (isn3 == insn::b && isn3.supertype() == libinsn::arm64::insn::sut_branch_imm) {
                    loc_t pos = isn2;
                    RETCACHELOC(pos);
                }
                if (isn3 == insn::movz && isn3.subtype() == insn::st_immediate && isn3.rd() == 2 && isn3.imm() == 0) {
                    auto isn4 = ++iter;
                    if (isn4 == insn::b && isn4.supertype() == libinsn::arm64::insn::sut_branch_imm) {
                        loc_t pos = isn2;
                        RETCACHELOC(pos);
                    }
                }
            }
            iter = isn;
        }
    }

    reterror("Failed to find malloc function");
}


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

std::vector<patch> ibootpatchfinder64_iOS15::get_debug_enabled_patch(){
    UNCACHEPATCHES;
    
    loc_t debug_enabled = -1;
    while (true) {
        debug_enabled = findstr("debug-enabled", true, debug_enabled+1);
        assure(debug_enabled);
        if ((_vmem->deref(debug_enabled-1) & 0xFF) == 0) break;
        //iOS 18 introduces "dev-unset-debug-enabled" which appears before the actual "debug-enabled". We need to skip that
    }
    debug("debug_enabled=0x%016llx\n",debug_enabled);
    
    loc_t xref = find_literal_ref(debug_enabled);
    assure(xref);
    debug("xref=0x%016llx\n",xref);
    
    vmem iter = _vmem->getIter(xref);
    
    while (++iter != insn::bl)
        ;
    while (++iter != insn::bl)
        ;
    
    {
        /*
            Hello Firebloom?
            iPhone11,2 iOS 15.1 iBSS
            iPhone11,2 iOS 18.7.9 iBSS
         */
        auto iter2 = iter;
        for (int i=0; i<5; i++) {
            iter2 = iter().imm();
            int isncnt = 0;
            while (++iter2 != insn::ret) {
                isncnt++;
            }
            if (isncnt < 5) {
                /*
                    This isn't a real function but some outline woodoo
                 */
                loc_t woodoo = iter;
                debug("skipping outline woodoo function at 0x%llx",woodoo);
                while (++iter != insn::bl)
                    ;
                continue;
            }
            goto found_real_func;
        }
        reterror("Failed to find a real function");
        found_real_func:;
    }
    
    pushINSN(insn::new_immediate_movz(iter, 1, 0, 0 ));
    
    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder64_iOS15::get_skip_set_bpr_patch(){
    UNCACHEPATCHES;
    
    try {
        /*
            iOS 14 method seems to have worked find for older devices i guess?
            It only started failing on A12 (as far as i have noticed)
         */
        return ibootpatchfinder64_iOS14::get_skip_set_bpr_patch();
    } catch (...) {
        debug("iOS 14 method failed, trying iOS 16 method");
    }
    
    /*
        Below this line is iOS 16 patchfinder copy and pasted
     */
    
    
    /*
     In 16.1 20B5027f we're back to this again -_-"
0x00000001800cf2e8         mov        x8, #0x30
0x00000001800cf2ec         movk       x8, #0x102d, lsl #16
0x00000001800cf2f0         movk       x8, #0x2, lsl #32
0x00000001800cf2f4         ldr        w9, [x8]
0x00000001800cf2f8         ret
     
0x00000001800cf120         mov        x0, lr
0x00000001800cf124         bl         0x00000001800cf2e8
0x00000001800cf128         mov        lr, x0
0x00000001800cf12c         orr        w9, w9, #0x1
0x00000001800cf130         b          call_to_store
     */
    
    std::set<uint64_t> bpr_regs = {0x2102d0030/*t8010*/, 0x2352d0030/*t8015*/, 0x23d2d0030/*t8030,t8020,t8006*/, 0x23d2dc030/*t8110*/};
    
    vmem iter = _vmem->getIter();
    try {
        while (true) {
        loop_start:
            while (++iter != insn::movz || iter().subtype() != insn::st_immediate)
                ;
            vmem iter2 = iter;
            uint8_t rd = iter().rd();
            loc_t tgtval = iter2().imm();
            
            loc_t didBranchTo = 0;
            
            for (int i=0; i<4; i++) {
                if (++iter2 != insn::movk || iter2().rd() != rd){
                    if (iter2() == insn::bl) {
                        iter2 = didBranchTo = iter2().imm();
                        continue;
                    }
                    break;
                }
                tgtval += iter2().imm();
            }
            
            if (bpr_regs.find(tgtval) == bpr_regs.end()) continue;

            if (iter2() != insn::ldr || iter2().rn() != rd) continue; //this should be fatal!
            uint8_t rt = iter2().rt();
            
            try{
                loc_t callref = -4;
                while ((callref = find_call_ref(iter,false,callref+4))) {
                    debug("callref=0x%llx",callref);
                    
                    iter2 = callref;
                    for (int i=0; i<4; i++) {
                        if (++iter2 == insn::orr && iter2().rn() == rt && iter2().imm() == 1) {
                            pushINSN(insn::new_register_mov(iter2, 0, iter2().rd(), iter2().rn()));
                            goto loop_start;
                        }
                    }
                }
            }catch(...){
                //
            }
        }
    } catch (...) {
        //
    }
    retassure(patches.size(), "Failed to find a single patch");
    RETCACHEPATCHES;
}
