//
//  ibootpatchfinder64_iOS13.cpp
//  libpatchfinder
//
//  Created by tihmstar on 13.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include "ibootpatchfinder64_iOS13.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS13::get_force_septype_local_patch(){
    std::vector<patch> patches;

    loc_t rsepref = find_literal_ref('rsep');
    debug("rsepref=0x%016llx",rsepref);
    
    loc_t bof = find_bof(rsepref);
    debug("bof=0x%016llx",bof);

    loc_t bref = -4;
    while (true) {
        try {
            bref = find_call_ref(bof,0,bref+4);
        } catch (...) {
            if (patches.size()) {
                //failed to find ref, but we already have at least one patch. Should be good
                break;
            }else{
                //failed to find bref, but we didn't find the correct patch yet
                throw;
            }
        }
        debug("bref=0x%016llx",bref);
        vmem iter = _vmem->getIter(bref);

        if (--iter != insn::movz || iter().rd() != 2){
            //setting third arg
            error("unexpected insn before call");
            continue;
        }
        
        if (iter().imm() == 0) {
            debug("arg already good");
            continue;
        }
        
        {
            insn pinsn = insn::new_immediate_movz(iter.pc(), 0, iter().rd(), 0);
            uint32_t opcode = pinsn.opcode();
            patches.push_back({pinsn.pc(),&opcode,sizeof(opcode)});
        }
    }
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS13::replace_cmd_with_memcpy(const char *cmd_handler_str){
    std::vector<patch> patches;
    retassure(cmd_handler_str, "unexpected NULL cmd_handler_str");
    
    loc_t handler_str_loc = findstr(cmd_handler_str, true);
    debug("handler_str_loc=0x%016llx\n",handler_str_loc);

    loc_t tableref = memmem(&handler_str_loc, sizeof(handler_str_loc));
    debug("tableref=0x%016llx\n",tableref);

    loc_t scratchbuf = _vmem->memstr("failed to execute upgrade command from new");
    debug("scratchbuf=0x%016llx\n",scratchbuf);
    
    uint32_t shellcode_insn_cnt = 10; //commitment
    loc_t shellcode = findnops(shellcode_insn_cnt);
    debug("shellcode=0x%016llx\n",shellcode);

    int insnRet = 9; //commitment
    int insnLoopRef = 5; //commitment

    
#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;

    pushINSN(insn::new_immediate_cmp(cPC, 4, 0));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+insnRet*4, insn::cond::NE));
    /*
        iPhone 5s iOS 12 still uses 0x30+0x28*x formula
     */
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*2, 1, 2));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*0, 1, 0));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*1, 1, 1));
    assure(insnLoopRef == insnNum);

    {
        /*
         patch:
          ldrb       w3, [x1], #0x1
          strb       w3, [x0], #0x1
          subs       x2, x2, #0x1
          b.ne       cmd_bgcolor+84
         */
        constexpr const char patch[] = "\x23\x14\x40\x38"
                                       "\x03\x14\x00\x38"
                                       "\x42\x04\x00\xF1"
                                       "\xA1\xFF\xFF\x54";
        patches.push_back({cPC,patch,sizeof(patch)-1}); //my memcpy
        cPC;
        cPC;
        cPC;
    }
    
    assure(insnNum == insnRet);
    pushINSN(insn::new_general_ret(cPC));
    assure(insnNum == shellcode_insn_cnt);
#undef cPC
    
    patches.push_back({scratchbuf,"memcpy",sizeof("memcpy")}); //overwrite name
    patches.push_back({tableref,&scratchbuf,8}); //overwrite pointer to name
    patches.push_back({tableref+8,&shellcode,8}); //overwrite function pointer
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS13::get_always_production_patch(){
    std::vector<patch> patches;
    
    for (uint64_t demoteReg : {(uint64_t)0x3F500000UL,(uint64_t)0x481BC000UL,(uint64_t)0x20E02A000UL,(uint64_t)0x2102BC000UL,(uint64_t)0x2352BC000UL}) {
        loc_t demoteRef = -4;
        while ((demoteRef = find_literal_ref(demoteReg,0,demoteRef+4))) {
            vmem iter = _vmem->getIter(demoteRef);
            bool isVariant2 = false;
            
            iter+=2;
            if (iter() == insn::and_) {
                if ((uint32_t)iter().imm() != 1) continue;
                isVariant2 = false;
//                pushINSN(insn::new_immediate_movz(iter, 1, 0, 0));//movz x0, 1
            }else if (iter() == insn::lsl){
                if ((uint32_t)iter().imm() != 8) continue;
                isVariant2 = true;
//                pushINSN(insn::new_immediate_movz(iter, 0x100, iter().rd(), 0));//movz x0, 1
            }else{
                continue;
            }
            debug("demoteRef=0x%016llx\n",iter.pc());
            
            
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
                if (demoteRef > dst && demoteRef - dst <= 4*6) {
                    //direct call
                    break;
                }else{
                    vmem iter2(iter,dst);
                    if (iter2() == insn::b) {
                        //indirect call through unconditional branch
                        dst = iter2().imm();
                        if (demoteRef > dst && demoteRef - dst <= 4*6) {
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

            char patch[] = "\xA1\x00\x00\x58\xDF\x03\x01\xEB\x40\x00\x00\x54\x20\x00\x80\xD2\xC0\x03\x5F\xD6";
            if (isVariant2) {
                patch[sizeof(patch)-1-7] = 0x20;
            }
            auto zerospace = findnops(sizeof(patch)-1 + sizeof(uint64_t),true,0x00000000);
            pushINSN(insn::new_immediate_b(demoteRef+4, zerospace));
            patches.push_back({zerospace,patch,sizeof(patch)-1});
            uint64_t v = iter.pc()+4;
            patches.push_back({zerospace+sizeof(patch)-1,&v,sizeof(v)});

            return patches;
        }
    }
    
    
    return patches;
}

uint32_t ibootpatchfinder64_iOS13::get_el1_pagesize(){
    vmem iter = _vmem->getIter();

    while (++iter != insn::msr || iter().special() != insn::tcr_el1);
    
    loc_t write_tcr_el1 = iter;
    debug("write_tcr_el1=0x%016llx",write_tcr_el1);

    loc_t ref_write_tcr_el1 = find_call_ref(write_tcr_el1);
    debug("ref_write_tcr_el1=0x%016llx",ref_write_tcr_el1);
    
    iter = ref_write_tcr_el1;
    --iter;
    
    assure(iter() == insn::bl);
    
    loc_t get_tcr_el1 = iter().imm();
    debug("get_tcr_el1=0x%016llx",get_tcr_el1);
    
    iter = get_tcr_el1;
    
    while (++iter != insn::ret);
    loc_t get_tcr_el1_eof = iter;
    debug("get_tcr_el1_eof=0x%016llx",get_tcr_el1_eof);
    
    uint64_t tcr_el1_val = find_register_value(get_tcr_el1_eof,0,get_tcr_el1);
    debug("tcr_el1_val=0x%016llx",tcr_el1_val);

    uint8_t TG0 = (tcr_el1_val >> 14) & 0b11;
    
    switch (TG0) {
        case 0b00:
            return 0x1000;
        case 0b01:
            return 0x10000;
        case 0b10:
            return 0x4000;
        default:
            reterror("invalid TG0=%d",TG0);
    }
}


std::vector<patch> ibootpatchfinder64_iOS13::get_rw_and_x_mappings_patch_el1(){
    std::vector<patch> patches;

    uint32_t pagesize = get_el1_pagesize();
    
    vmem iter = _vmem->getIter();

    while (++iter != insn::msr || iter().special() != insn::ttbr0_el1);
    
    loc_t write_ttbr0_el1 = iter;
    debug("write_ttbr0_el1=0x%016llx",write_ttbr0_el1);
    
    while (++iter != insn::ret);
    loc_t write_ttbr0_el1_eof = iter;
    debug("write_ttbr0_el1_eof=0x%016llx",write_ttbr0_el1_eof);

    /*
     create iboot_base_block_entry (rw)
     */
    uint64_t iboot_base_block_entry = find_base();

    //mask off unneeded bits
    iboot_base_block_entry = pte_vma_to_index(pagesize,2,iboot_base_block_entry);
    iboot_base_block_entry = pte_index_to_vma(pagesize, 2, iboot_base_block_entry);
    
    //set pte bits
    iboot_base_block_entry |= 0x445;
    
    /*
     create loadaddr_block_entry (rx)
     */
    loc_t loadaddr_str = findstr("loadaddr", true);
    debug("loadaddr_str=0x%016llx",loadaddr_str);
    loc_t loadaddr = 0;
    while (!loadaddr) {
        loc_t loadaddr_ref = find_literal_ref(loadaddr_str);
        debug("loadaddr_ref=0x%016llx",loadaddr_ref);
        vmem iter = _vmem->getIter(loadaddr_ref);

        while (++iter != insn::bl);
        loc_t loadaddr_ref_firstbl = iter;
        debug("loadaddr_ref_firstbl=0x%016llx",loadaddr_ref_firstbl);

        loadaddr = find_register_value(loadaddr_ref_firstbl, 1, loadaddr_ref);
    }
    
    debug("loadaddr=0x%016llx",loadaddr);

    //mask off unneeded bits
    uint64_t loadaddr_block_entry = pte_vma_to_index(pagesize,2,loadaddr);
    loadaddr_block_entry = pte_index_to_vma(pagesize, 2, loadaddr_block_entry);

    //set pte bits
    loadaddr_block_entry |= 0x4c5;
    
    uint32_t orig_write_ttbr0_el1_insn_cnt = (uint32_t)((write_ttbr0_el1_eof-write_ttbr0_el1+4)/4);
    bool needs_alignment = ! (orig_write_ttbr0_el1_insn_cnt&1);
    

    /*
     create patch
              ldr        x1, =0x180000445
              nop
              ldr        x2, =0x8000004c5
              stp        x1, x2, [x0, #0x8]
              dmb        sy
        ///orig
              msr        ttbr0_el1, x0
              isb
              ret
        ///orig end
              dq         0x0000000180000445
              dq         0x00000008000004c5
    */
    uint8_t cinsn = 0;
    {
        //ldr        x1, =0x180000445
        insn pins = insn::new_literal_ldr(0, (5+orig_write_ttbr0_el1_insn_cnt)*4, 1);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)(cinsn++*4),&opcode, sizeof(opcode)});
    }
    {
        //nop
        insn pins = insn::new_general_nop(0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)(cinsn++*4),&opcode, sizeof(opcode)});
    }
    {
        //ldr        x2, =0x8000004c5
        insn pins = insn::new_literal_ldr(0, (5+orig_write_ttbr0_el1_insn_cnt)*4, 2);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)(cinsn++*4),&opcode, sizeof(opcode)});
    }
    {
        //stp        x1, x2, [x0, #0x8]
        insn pins = insn::new_general_stp_offset(0, 8, 1, 2, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)(cinsn++*4),&opcode, sizeof(opcode)});
    }
    //dmb        sy
    patches.push_back({(loc_t)(cinsn++*4),"\xBF\x3F\x03\xD5",4});
    
    uint32_t *orig_opcodes = (uint32_t*)memoryForLoc(write_ttbr0_el1);
    patches.push_back({(loc_t)(cinsn*4),orig_opcodes,4*orig_write_ttbr0_el1_insn_cnt});cinsn+=orig_write_ttbr0_el1_insn_cnt;
    
    patches.push_back({(loc_t)(cinsn*4),&iboot_base_block_entry,sizeof(iboot_base_block_entry)}); cinsn+=sizeof(iboot_base_block_entry)/4;
    patches.push_back({(loc_t)(cinsn*4),&loadaddr_block_entry,sizeof(loadaddr_block_entry)}); cinsn+=sizeof(loadaddr_block_entry)/4;

    uint32_t fullpatch_size = 0;
    for (auto p: patches){
        fullpatch_size += p.getPatchSize();
    }
    
    /*
     now find an empty spot for to place the payload
     */
    loc_t nopspace = findnops(fullpatch_size/4 + 1, true); //alloc 1 more nop than we need
    debug("nopspace=0x%016llx",nopspace);
    
    /*
     ldp needs to load from 8 byte aligned address
     if needs_alignment is false, we start at 8 byte aligned address and the data is placed at 8 byte aligned
     if needs_alignmend is true, then we need to start at 8byte aligned + 4 for the data to be 8 byte aligned
     */
    if (((nopspace & 0x4) && !needs_alignment /* we don't need alignment, but we start at an +4 address*/ )
        || (((nopspace & 0x4) == 0) && needs_alignment) /* we are at 8 byte aligned, but we need fixup*/) {
        nopspace+=4;
    }
    
    //now fixup payload addresses
    for (auto &p: patches){
        p._location += nopspace;
    }
    
    /*
     finally rewrite write_ttbr0 to jump to payload
     */
    for (loc_t iloc = write_ttbr0_el1; iloc<write_ttbr0_el1_eof; iloc+=4) {
        insn pins = insn::new_general_nop(iloc);
        uint32_t opcode = pins.opcode();
        patches.push_back({pins,&opcode,sizeof(opcode)});
    }
    
    {
        //make last orig insn of write_ttbr0 jump to payload
        insn pins = insn::new_immediate_b(write_ttbr0_el1_eof, nopspace);
        uint32_t opcode = pins.opcode();
        patches.push_back({pins,&opcode,sizeof(opcode)});
    }
    
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_iOS13::get_ra1nra1n_patch(){
    std::vector<patch> patches;
    
    /*
     uint32_t* tramp = find_next_insn(boot_image, 0x80000, 0xd2800012, 0xFFFFFFFF);
     if (tramp) {
         for (int i = 0; i < 5; i++) {
             tramp[i] = tramp_hook[i];
         }
     }
     
     patch ->
     
     mov x8, x29
     mov x9, x29
     mov x27, #0x800000000
     movk x27, #0x1800, lsl#16
     mov x29, x27
     
     */
    

    loc_t findloc = memmem("\x12\x00\x80\xd2", 4);
    debug("findloc=0x%016llx\n",findloc);

    auto iter = _vmem->getIter(findloc);
    while (++iter != insn::mov && iter().rd() != 30){
        retassure(iter() != insn::ret, "got unexpected ret!");
    }
    uint8_t srcreg = iter().rm();
    
    findloc-=4;
    pushINSN(insn::new_register_mov(findloc+=4, 0, 8, srcreg));
    pushINSN(insn::new_register_mov(findloc+=4, 0, 9, srcreg));
    pushINSN(insn::new_immediate_movz(findloc+=4, 0x8, 27, 32));
    pushINSN(insn::new_immediate_movk(findloc+=4, 0x1800, 27, 16));
    pushINSN(insn::new_register_mov(findloc+=4, 0, 29, 27));

    
    loc_t findloc2 = memmem("\x23\x74\x0b\xd5", 4);
    debug("findloc2=0x%016llx\n",findloc2);

    loc_t bzero = find_bof(findloc2);
    debug("bzero=0x%016llx\n",bzero);
    
    uint32_t shellcode_insn_cnt = 10; //commitment
    loc_t shellcode = findnops((shellcode_insn_cnt/2)+1, true, 0x00000000);
    debug("shellcode=0x%016llx",shellcode);
    
    pushINSN(insn::new_immediate_b(bzero, shellcode));
    
#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    uint32_t shellend = 8;

    pushINSN(insn::new_immediate_movz(cPC, 0x8, 3, 32));
    pushINSN(insn::new_immediate_movk(cPC, 0x1800, 3, 16));
    pushINSN(insn::new_register_cmp(cPC, 0, 0, 3, -1));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+shellend*4, insn::HI));
    pushINSN(insn::new_register_add(cPC, 0, 1, 0, 2));
    pushINSN(insn::new_register_cmp(cPC, 0, 2, 3, -1));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+shellend*4, insn::CC));
    pushINSN(insn::new_general_br(cPC, 30));
    assure(shellend == insnNum);
    uint32_t backUpProloge = (uint32_t)deref(bzero);
    patches.push_back({shellcode+insnNum*4, &backUpProloge, 4});insnNum++;
    pushINSN(insn::new_immediate_b(cPC, (int64_t)bzero+4));
    assure(insnNum == shellcode_insn_cnt);
#undef cPC
    
    return patches;
}
