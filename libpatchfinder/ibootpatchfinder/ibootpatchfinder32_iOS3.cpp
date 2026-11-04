//
//  ibootpatchfinder32_iOS3.cpp
//  libpatchfinder
//
//  Created by erd on 16.09.24.
//
#include <libgeneral/macros.h>

#include "ibootpatchfinder32_iOS3.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

#define DEFAULT_BOOTARGS_STR "rd=md0 nand-enable-reformat=1 -progress"
#define CERT_STR "Reliance on this certificate"


std::vector<patch> ibootpatchfinder32_iOS3::get_boot_arg_patch(const char *bootargs){
    std::vector<patch> patches;

    loc_t default_boot_args_str_loc = findstr(DEFAULT_BOOTARGS_STR, false);
    debug("default_boot_args_str_loc=0x%08x",default_boot_args_str_loc);
    
    loc_t default_boot_args_data_xref = memmem(&default_boot_args_str_loc, sizeof(default_boot_args_str_loc));
    debug("default_boot_args_data_xref=0x%08x",default_boot_args_data_xref);

    loc_t default_boot_args_xref = find_literal_ref_thumb(default_boot_args_str_loc);
    debug("default_boot_args_xref=0x%08x",default_boot_args_xref);

    
    if (strlen(bootargs) > strlen(DEFAULT_BOOTARGS_STR)) {
        loc_t cert_str_loc = 0;
        debug("Relocating boot-args string...");

        /* Find the "Reliance on this cert..." string. */
        retassure(cert_str_loc = findstr(CERT_STR,false), "Unable to find \"%s\" string!", CERT_STR);

        debug("\"%s\" string found at 0x%08x", CERT_STR, cert_str_loc);

        /* Point the boot-args xref to the "Reliance on this cert..." string. */
        debug("Pointing default boot-args xref to 0x%08x...", cert_str_loc);

        default_boot_args_str_loc = cert_str_loc;
        
        patches.push_back({default_boot_args_data_xref, &default_boot_args_str_loc, sizeof(default_boot_args_str_loc)});
    }
    
    debug("Applying custom boot-args \"%s\"\n", bootargs);
    patches.push_back({default_boot_args_str_loc, bootargs, strlen(bootargs)+1});
    
    {
        bool methodArmv6 = false;
        vmem_thumb iter = _vmemThumb->getIter(default_boot_args_xref);
        
        uint8_t xref_dst_reg = iter().rt();

        {
            if (++iter != arm32::it) {
                if (iter() == arm32::b) iter = iter().imm();
                for (int i=0; i<0x30; i++) {
                    if (iter() == arm32::b) iter = iter().imm();
                    if (++iter == arm32::it) break;
                }
                if (iter() != arm32::it){
                    methodArmv6 = true;
                    debug("Could not find 'it' insn, switching to armv6 method");
                }
            }else{
                //this is expected
            }
        }
        if (!methodArmv6) {
            pushINSN(thumb::new_T2_register_mov(iter.pc(), 0, 0));

            retassure(++iter == arm32::mov, "next insn not mov");
            
            if (iter().rd() == xref_dst_reg) {
                //this overwrites our reg, just nop it
                pushINSN(thumb::new_T2_register_mov(iter.pc(), 0, 0));
            }else{
                //our register always overwrites the other option now.
                //this is correct, no need to do anything in this case
            
                /* iPad1,1 iOS 4.3.5
                 0x8400c7c8         ite        ne
                 0x8400c7ca         movne      r4, r3
                 0x8400c7cc         moveq      r4, r2
                 */
                uint8_t rn = iter().rd();
                if (++iter == arm32::mov) {
                    if (iter().rd() == rn){
                        pushINSN(thumb::new_T2_register_mov(iter, rn, xref_dst_reg));
                    }
                }
            }
        }else{
            iter = default_boot_args_xref;
            if (--iter == arm32::bcond){
                pushINSN(thumb::new_T2_register_mov(iter.pc(), 0, 0));
            } else if (--iter == arm32::bcond){
                pushINSN(thumb::new_T2_register_mov(iter.pc(), 0, 0));
                pushINSN(thumb::new_T2_register_mov(iter.pc()+2, 0, 0));
            }else{
                bool foundPatch = false;
                for (int i=0; i<2; i++){
                    try{
                        loc_t bref = find_branch_ref_thumb(default_boot_args_xref-i*2, -0x10);
                        debug("bref=0x%08x",bref);
                        pushINSN(thumb::new_T2_immediate_b(bref,default_boot_args_xref-i*2));
                        foundPatch = true;
                        break;
                    }catch(...){
                        //
                    }
                }
                retassure(foundPatch, "Failed to find patch!");
            }
        }
    }
    
    return patches;
}

std::vector<patch> ibootpatchfinder32_iOS3::get_honor_nvram_boot_arg_patch(){
    UNCACHEPATCHES;
    /*
     iPhone1,1 iOS 3.0
     */
    loc_t default_boot_args_str_loc = findstr(DEFAULT_BOOTARGS_STR, false);
    debug("default_boot_args_str_loc=0x%08x",default_boot_args_str_loc);
    
    loc_t default_boot_args_data_xref = memmem(&default_boot_args_str_loc, sizeof(default_boot_args_str_loc));
    debug("default_boot_args_data_xref=0x%08x",default_boot_args_data_xref);
    
    loc_t default_boot_args_xref = find_literal_ref_thumb(default_boot_args_str_loc);
    debug("default_boot_args_xref=0x%08x",default_boot_args_xref);
    
    loc_t env_get = find_env_get();
    debug("env_get=0x%08x",env_get);
    
    loc_t bref = 0;
    loc_t bdst_skip = 0;
    uint8_t xref_dst_reg = -1;
    loc_t xref_imm = 0;
    vmem_thumb iter = _vmemThumb->getIter(default_boot_args_xref);
    xref_imm = iter().imm();
    {
        bool methodArmv6 = false;
        
        xref_dst_reg = iter().rt();
        
        {
            if (++iter != arm32::it) {
                if (iter() == arm32::b) iter = iter().imm();
                for (int i=0; i<0x30; i++) {
                    if (iter() == arm32::b) iter = iter().imm();
                    if (++iter == arm32::it) break;
                }
                if (iter() != arm32::it){
                    methodArmv6 = true;
                    debug("Could not find 'it' insn, switching to armv6 method");
                }
            }else{
                //this is expected
            }
        }
        if (!methodArmv6) {
            /*
                iPhone2,1 iOS 3.1
             */
            loc_t blloc = iter;
            pushINSN(thumb::new_T1_immediate_bl(iter, env_get));
            iter = iter.pc()+4;
            retassure(iter() == arm32::mov, "unexpected insn");
            pushINSN(thumb::new_T2_register_mov(iter, iter().rd(), 0));
            iter = default_boot_args_xref;
            while ((++iter).pc() < blloc) {
                uint8_t rd = -1;
                uint8_t rt = -1;
                try {rd = iter().rd();} catch (...) {}
                try {if (iter() != arm32::str) rt = iter().rt();} catch (...) {}

                if (rd == 0 || rt == 0){
                    pushINSN(thumb::new_T1_general_nop(iter));
                    if (iter().insnsize() == 4){
                        pushINSN(thumb::new_T1_general_nop(iter.pc()+2));
                    }
                }
            }
        }else{
            iter = default_boot_args_xref;
            bdst_skip = iter.pc() + iter().insnsize();
            if (--iter == arm32::bcond){
                pushINSN(thumb::new_T2_register_mov(iter.pc(), 0, 0));
            } else if (--iter == arm32::bcond){
                pushINSN(thumb::new_T2_register_mov(iter.pc(), 0, 0));
                pushINSN(thumb::new_T2_register_mov(iter.pc()+2, 0, 0));
            }else{
                for (int i=0; i<2; i++){
                    try{
                        bref = find_branch_ref_thumb(default_boot_args_xref-i*2, -0x80);
                        break;
                    }catch(...){
                        //
                    }
                }
            }
            retassure(bref, "Failed to find bref");
            debug("bref=0x%08x",bref);
            debug("xref_dst_reg=%d",xref_dst_reg);
            debug("bdst_skip=0x%08x",bdst_skip);
            debug("xref_imm=0x%08x",xref_imm);
            
            iter = bref;
            
            retassure(iter().imm()-iter < 4*6 && iter().condition() == cond::NE, "unexpected layout");
            pushINSN(thumb::new_T2_register_mov(iter, 0, 0));
            retassure(++iter == arm32::ldr && iter().subtype() == arm32::st_literal, "unexpected layout");
            uint8_t ldrReg = iter().rt();
            debug("ldrReg=%d",ldrReg);
            bool isStrVariant = false;
            ++iter;
            {
                uint8_t rd = iter().rd();
                uint8_t rm = -1;
                uint8_t rn = -1;
                int32_t imm = -1;
                /*
                 iPhone1,1 iOS 3.0
                 ldr    r0, =0x1801fff0
                 mov    fp, r0
                 adds   r5, r0, #0x0
                 */
                try {rm = iter().rm();} catch(...){isStrVariant = true;} //mov
                /*
                 iPhone1,1 iOS 3.1
                 ldr    r0, =0x1801f9f0
                 adds   r6, r0, #0x0
                 str    r0, [sp, #0x4]
                 */
                try {rn = iter().rn();} catch(...){} //adds
                try {imm = iter().imm();} catch(...){} //adds
                retassure((rm == ldrReg && rd != xref_dst_reg) || (rd == xref_dst_reg && rn == ldrReg && imm == 0), "unexpected layout");
            }
            ++iter;
            {
                uint8_t rd = -1;
                uint8_t rt = -1;
                try {rd = iter().rd();} catch(...){retassure(isStrVariant, "sanity check fail");} //adds
                try {rt = iter().rt();} catch(...){} //str
                retassure(rd == xref_dst_reg || rt == ldrReg, "unexpected layout");
            }
            
            loc_t shellcode = iter;
            if ((xref_imm-shellcode) & 3){
                pushINSN(thumb::new_T2_register_mov(shellcode, 0, 0));
                shellcode+=2;
            }
            
            debug("shellcode=0x%08x",shellcode);
            iter = bref;
            while (++iter != arm32::b)
                ;
            loc_t post_shellcode = iter().imm();
            debug("post_shellcode=0x%08x",post_shellcode);
            
            if (isStrVariant) {
                iter = shellcode;
                retassure(iter().insnsize() == 2, "bad insnsize");
                uint16_t opcode = (uint16_t)iter().opcode();
                --iter;
                retassure(iter().insnsize() == 2, "bad insnsize");
                patches.push_back({
                    iter,
                    &opcode,
                    sizeof(opcode),
                });
            }
            
            pushINSN(thumb::new_T1_literal_ldr(shellcode, xref_imm, 0));
            shellcode+=2;
            pushINSN(thumb::new_T1_immediate_bl(shellcode, env_get));
            shellcode+=4;
            pushINSN(thumb::new_T2_register_mov(shellcode, xref_dst_reg, 0));
            shellcode+=2;
            while (shellcode < post_shellcode) {
                pushINSN(thumb::new_T2_register_mov(shellcode, 0, 0));
                shellcode+=2;
            }
            retassure(shellcode == post_shellcode, "shellcode overflow!");
        }
    }
    {
        //old bootargs are not the "boot-args" string arg for getenv
        char argstr[] = "boot-args";
        patches.push_back({default_boot_args_str_loc, argstr, sizeof(argstr)});
    }

    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder32_iOS3::get_no_img3_dumplist_patch(){
    UNCACHEPATCHES;
    
    loc_t str = (loc_t)findstr("image %p", false);
    debug("str=0x%08x",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%08x",ref);
    
    auto iter = _vmemThumb->getIter(ref);

    loc_t bof = find_bof(ref);
    debug("bof=0x%08x",bof);
    
    pushINSN(thumb::new_T1_immediate_movs(bof, 0, 0));
    pushINSN(thumb::new_T1_general_bx(bof+2, 14));

    RETCACHEPATCHES;
}
