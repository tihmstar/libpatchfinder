//
//  ibootpatchfinder64_base.cpp
//  libpatchfinder
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>

#include "ibootpatchfinder64_base.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all64.h"
#include <string.h>


using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;


#define IBOOT_VERS_STR_OFFSET 0x280
#define iBOOT_BASE_OFFSET 0x318
#define KERNELCACHE_PREP_STRING "__PAGEZERO"
#define ENTERING_RECOVERY_CONSOLE "Entering recovery mode, starting command prompt"
#define DEFAULT_BOOTARGS_STR "rd=md0 nand-enable-reformat=1 -progress"
#define DEFAULT_BOOTARGS_STR_13 "rd=md0 -progress -restore"
#define CERT_STR "Apple Inc.1"

ibootpatchfinder64_base::ibootpatchfinder64_base(const char * filename) :
    ibootpatchfinder64(true)
{
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    })
    struct stat fs = {};
    
    assure((fd = open(filename, O_RDONLY)) != -1);
    assure(!fstat(fd, &fs));
    assure((_buf = (uint8_t*)malloc(_bufSize = fs.st_size)));
    assure(read(fd,(void*)_buf,_bufSize)==_bufSize);
    
    init();
}

ibootpatchfinder64_base::ibootpatchfinder64_base(const void *buffer, size_t bufSize, bool takeOwnership)
:    ibootpatchfinder64(takeOwnership)
{
    _bufSize = bufSize;
    _buf = (uint8_t*)buffer;
    init();
}

void ibootpatchfinder64_base::init(){
    assure(_bufSize > 0x1000);
    
    assure(!strncmp((char*)&_buf[IBOOT_VERS_STR_OFFSET], "iBoot", sizeof("iBoot")-1));
    retassure(*(uint32_t*)&_buf[0] == 0x90000000
              || (((uint32_t*)_buf)[0] == 0x14000001 && ((uint32_t*)_buf)[4] == 0x90000000)
              || (((uint32_t*)_buf)[0] == 0xD53C1102 && ((uint32_t*)_buf)[3] == 0xD51C1102)
              , "invalid magic");
    
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[iBOOT_BASE_OFFSET];
    debug("iBoot base at=0x%016llx\n", _base);
    safeDelete(_vmem);
    _vmem = new vmem({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    retassure(_vers = atoi((char*)&_buf[IBOOT_VERS_STR_OFFSET+6]), "No iBoot version found!\n");
    debug("iBoot-%d inputted\n", _vers);
}

ibootpatchfinder64_base::~ibootpatchfinder64_base(){
    //
}

#pragma mark public
bool ibootpatchfinder64_base::has_kernel_load(){
    try {
        return (bool) (_vmem->memstr(KERNELCACHE_PREP_STRING) != 0);
    } catch (...) {
        return 0;
    }
}

bool ibootpatchfinder64_base::has_recovery_console(){
    try {
        return (bool) (_vmem->memstr(ENTERING_RECOVERY_CONSOLE) != 0);
    } catch (...) {
        return 0;
    }
}

std::vector<patch> ibootpatchfinder64_base::get_always_production_patch(){
    std::vector<patch> patches;
    for (uint64_t demoteReg : {(uint64_t)0x3F500000UL,(uint64_t)0x481BC000UL,(uint64_t)0x20E02A000UL,(uint64_t)0x2102BC000UL}) {
        loc_t demoteRef = find_literal_ref(demoteReg);
        if (demoteRef) {
            vmem iter = _vmem->getIter(demoteRef);

            while (++iter != insn::and_);
            assure((uint32_t)iter().imm() == 1);
            demoteRef = iter;
            debug("demoteRef=0x%016llx\n",demoteRef);
//            pushINSN(insn::new_immediate_movz(demoteRef, 1, 0, 0));//movz x0, 1
            
            
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
                    if (demoteRef > dst && demoteRef - dst <= 4*6) {
                        //yes! but we need to remove the proxy for our detection to work
                        pushINSN(insn::new_immediate_bl(iter, dst));
                        break;
                    }
                }
            }

            char patch[] = "\xA1\x00\x00\x58\xDF\x03\x01\xEB\x40\x00\x00\x54\x20\x00\x80\xD2\xC0\x03\x5F\xD6";
            auto zerospace = findnops(sizeof(patch)-1 + sizeof(uint64_t),true,0x00000000);
            pushINSN(insn::new_immediate_b(demoteRef+4, zerospace));
            patches.push_back({zerospace,patch,sizeof(patch)-1});
            uint64_t v = iter.pc()+4;
            patches.push_back({zerospace+sizeof(patch)-1,&v,sizeof(v)});

            break;
        }
    }
    
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_sigcheck_img4_patch(){
    std::vector<patch> patches;
    vmem iter = _vmem->getIter();
    
continue_search_for_stores:
    while (++iter != insn::strb);
    vmem iter2 = _vmem->getIter(iter);
    for (int i=0; i<6; i++) {
        if (++iter2 != insn::strb) {
            goto continue_search_for_stores;
        }
    }
    
    loc_t stores=iter;
    debug("store=0x%016llx",stores);
    
    //find lowest value
    uint64_t lowestOffset = -1;//max offset
    iter2 = stores-4;
    for (int i=0; i<7; i++) {
        uint64_t imm = (++iter2).imm();
        if (imm < lowestOffset) {
            lowestOffset = imm;
        }
    }
    debug("lowestOffset=0x%016llx",lowestOffset);
    
    pushINSN(insn::new_immediate_movz(stores, 1, 1, 0));
    pushINSN(insn::new_immediate_strb_unsigned(stores+4*1, lowestOffset+1, iter().rn(), 1));
    pushINSN(insn::new_immediate_strb_unsigned(stores+4*2, lowestOffset+3, iter().rn(), 1));
    pushINSN(insn::new_immediate_strb_unsigned(stores+4*3, lowestOffset+4, iter().rn(), 1));
    pushINSN(insn::new_general_nop(stores+4*4));
    pushINSN(insn::new_general_nop(stores+4*5));
    pushINSN(insn::new_general_nop(stores+4*6));
    
    iter = stores+4*7;
    
    if (iter() != insn::b) ++iter; //may be along the lines of: mov x11, x25 / ldr x10, [sp, #0x80]

    if (iter() == insn::b) {
        loc_t overwritebranch = iter;
        debug("overwritebranch=0x%016llx",overwritebranch);

        loc_t storesref = 0;
        try {
            storesref = find_branch_ref(stores, -0x300);
            debug("storesref=0x%016llx",storesref);
        } catch (...) {
            storesref = overwritebranch;
            debug("Failed to find storesref. storesref=overwritebranch=0x%016llx",storesref);
        }
        
        pushINSN(insn::new_immediate_b(overwritebranch, storesref+4));
    }else{
        reterror("unimplemented sigpatch case :(");
    }
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_boot_arg_patch(const char *bootargs){
    std::vector<patch> patches;
    loc_t default_boot_args_str_loc = 0;
    loc_t default_boot_args_xref = 0;

    try{
        default_boot_args_str_loc = _vmem->memstr(DEFAULT_BOOTARGS_STR);
    }catch(...){
        debug("DEFAULT_BOOTARGS_STR not found, trying fallback to DEFAULT_BOOTARGS_STR_13\n");
        default_boot_args_str_loc = _vmem->memstr(DEFAULT_BOOTARGS_STR_13);
    }

    assure(default_boot_args_str_loc);
    debug("default_boot_args_str_loc=0x%016llx\n",default_boot_args_str_loc);
   
    assure(default_boot_args_xref = find_literal_ref(default_boot_args_str_loc));
    debug("default_boot_args_xref=0x%016llx\n",default_boot_args_xref);

    if (strlen(bootargs) > strlen(DEFAULT_BOOTARGS_STR)) {
        loc_t cert_str_loc = 0;
        debug("Relocating boot-args string...\n");

        /* Find the "Reliance on this cert..." string. */
        retassure(cert_str_loc = _vmem->memstr(CERT_STR), "Unable to find \"%s\" string!\n", CERT_STR);

        debug("\"%s\" string found at 0x%016llx\n", CERT_STR, cert_str_loc);

        /* Point the boot-args xref to the "Reliance on this cert..." string. */
        debug("Pointing default boot-args xref to 0x%016llx...\n", cert_str_loc);

        default_boot_args_str_loc = cert_str_loc;
        
        vmem iter = _vmem->getIter(default_boot_args_xref);
        
        if (iter() == insn::adr) {
            pushINSN(insn::new_general_adr(default_boot_args_xref, (int64_t)default_boot_args_str_loc, iter().rd()));
        }else if (iter() == insn::add && iter-1 == insn::adrp){
            pushINSN(insn::new_general_adrp(iter.pc()-4, default_boot_args_str_loc & ~0xfff, iter().rd()));
            pushINSN(insn::new_immediate_add(iter.pc(), default_boot_args_str_loc & 0xfff, iter().rd(), iter().rd()));
        }else{
            reterror("unexpected insns");
        }
    }
    
    debug("Applying custom boot-args \"%s\"\n", bootargs);
    patches.push_back({default_boot_args_str_loc, bootargs, strlen(bootargs)+1});
    
    vmem iter = _vmem->getIter(default_boot_args_xref);
    uint8_t xrefRD = iter().rd();
    debug("xrefRD=%d\n",xrefRD);

    
    while (++iter != insn::csel);
    
    insn csel = iter();
    debug("csel=0x%016llx\n", (loc_t)csel.pc());

    assure(xrefRD == csel.rn() || xrefRD == csel.rm());
    
    debug("cselrd=%d\n",csel.rd());
        
    
    {
        insn pins = insn::new_register_mov(iter, 0, csel.rd(), xrefRD);
        debug("(0x%016llx)patching: \"mov x%d, x%d\"\n",(loc_t)pins.pc(),pins.rd(),pins.rm());
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }

    
    while ((--iter).supertype() != insn::sut_branch_imm || iter() == insn::bl)
        ;
    
    debug("branch loc=0x%016llx\n",(loc_t)iter);
    
    iter = (loc_t)iter().imm();

    debug("branch dst=0x%016llx\n",(loc_t)iter);
    
    if (iter() != insn::adr) {
        while (++iter != insn::adr);
    }
    
    {
        insn pins = insn::new_general_adr(iter, (int64_t)default_boot_args_str_loc, iter().rd());
        debug("(0x%016llx)patching: \"adr x%d, 0x%llx\"\n",(loc_t)pins.pc(),pins.rd(),pins.imm());
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }

    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_debug_enabled_patch(){
    std::vector<patch> patches;
    
    loc_t debug_enabled = findstr("debug-enabled", true);
    debug("debug_enabled=0x%016llx\n",debug_enabled);
    
    loc_t xref = find_literal_ref(debug_enabled);
    debug("xref=0x%016llx\n",xref);
    
    vmem iter = _vmem->getIter(xref);
    
    while (++iter != insn::bl);
    while (++iter != insn::bl);
    
    patches.push_back({iter,"\x20\x00\x80\xD2" /* mov x0,1 */,4});
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr){
    std::vector<patch> patches;
    std::string handler_str{"A"};
    handler_str+= cmd_handler_str;
    ((char*)handler_str.c_str())[0] = '\0';
    
    loc_t handler_str_loc = memmem(handler_str.c_str(), handler_str.size());
    debug("handler_str_loc=0x%016llx\n",handler_str_loc);
    
    handler_str_loc++;
    
    loc_t tableref = memmem(&handler_str_loc, sizeof(handler_str_loc));
    debug("tableref=0x%016llx\n",tableref);
    
    patches.push_back({tableref+8,&ptr,8});
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_cmd_handler_callfunc_patch(const char *cmd_handler_str){
    std::vector<patch> patches;
    retassure(cmd_handler_str, "null pointer provided");
    std::string handler_str = cmd_handler_str;

    loc_t handler_str_loc = memmem(handler_str.c_str(), handler_str.size());
    debug("handler_str_loc=0x%016llx",handler_str_loc);
    
    loc_t tableref = memmem(&handler_str_loc, sizeof(handler_str_loc));
    debug("tableref=0x%016llx",tableref);
    tableref+=8;
    
    loc_t logstr = findstr("%llx:%d\n", true);
    debug("logstr=0x%016llx",logstr);

    loc_t logstr_ref = find_literal_ref(logstr);
    debug("logstr_ref=0x%016llx",logstr_ref);
    
    vmem iter = _vmem->getIter(logstr_ref);
    while (++iter != insn::bl)
        ;
    
    loc_t func_printf = iter().imm();
    debug("func_printf=0x%016llx",func_printf);

    uint32_t shellcode_insn_cnt = 27; //commitment
    loc_t shellcode = findnops(shellcode_insn_cnt);
    debug("shellcode=0x%016llx",shellcode);
    
    uint32_t retInsn = 26; //commitment
    uint32_t afterBRInsn = 10; //commitment

#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    
    pushINSN(insn::new_immediate_sub(cPC, 0x20, 31, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x00, 8, 9, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x10, 29, 30, 31));
    pushINSN(insn::new_register_mov(cPC, 0, 8, 1));
    pushINSN(insn::new_immediate_movz(cPC, 10, 3, 0));
    pushINSN(insn::new_register_add(cPC, 0, 3, 0, 0, true));
    pushINSN(insn::new_general_adr(cPC, shellcode+retInsn*4, 9));
    pushINSN(insn::new_general_adr(cPC, shellcode+afterBRInsn*4, 3));
    pushINSN(insn::new_register_add(cPC, 2, 3, 0, 3));
    pushINSN(insn::new_general_br(cPC, 3));

    assure(insnNum == afterBRInsn);
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*8, 8, 7));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*7, 8, 6));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*6, 8, 5));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*5, 8, 4));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*4, 8, 3));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*3, 8, 2));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*2, 8, 1));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*1, 8, 0));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x28+0x20*0, 8, 9));
    pushINSN(insn::new_general_blr(cPC, 9));
    pushINSN(insn::new_general_ldp_offset(cPC, 0x00, 8, 9, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x00, 0, 0, 31));
    pushINSN(insn::new_general_adr(cPC, logstr, 0));
    pushINSN(insn::new_immediate_bl(cPC, func_printf));
    pushINSN(insn::new_general_ldp_offset(cPC, 0x10, 29, 30, 31));
    pushINSN(insn::new_immediate_add(cPC, 0x20, 31, 31));

    assure(insnNum == retInsn);
    pushINSN(insn::new_general_ret(cPC));
    
    assure(insnNum == shellcode_insn_cnt);
#undef cPC
    
    patches.push_back({tableref,&shellcode,sizeof(shellcode)});
    
    return patches;
}


std::vector<patch> ibootpatchfinder64_base::replace_cmd_with_memcpy(const char *cmd_handler_str){
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
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x30+0x28*2, 1, 2));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x30+0x28*0, 1, 0));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0x30+0x28*1, 1, 1));
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


std::vector<patch> ibootpatchfinder64_base::get_ra1nra1n_patch(){
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
    /*
        0x7000 iOS 12 buffers the ramdisk at 0x818000000. If we write ra1nra1n there, the ramdisk gets corrupted
     */
    pushINSN(insn::new_immediate_movz(findloc+=4, 0x8, 27, 32));
    pushINSN(insn::new_immediate_movk(findloc+=4, 0x2000, 27, 16));
    pushINSN(insn::new_register_mov(findloc+=4, 0, 29, 27));

    
    /*
        Disable bzero above 0x818000000
     */
    
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


std::vector<patch> ibootpatchfinder64_base::get_unlock_nvram_patch(){
    std::vector<patch> patches;

    loc_t debug_uarts_str = findstr("debug-uarts", true);
    debug("debug_uarts_str=0x%016llx\n",debug_uarts_str);

    loc_t debug_uarts_ref = memmem(&debug_uarts_str, sizeof(debug_uarts_str));
    debug("debug_uarts_ref=0x%016llx\n",debug_uarts_ref);

    loc_t setenv_whitelist = debug_uarts_ref;
    
    while (deref(setenv_whitelist-=8));
    setenv_whitelist+=8;
    debug("setenv_whitelist=0x%016llx\n",setenv_whitelist);

    loc_t blacklist1_func = find_literal_ref(setenv_whitelist);
    debug("blacklist1_func=0x%016llx\n",blacklist1_func);
    
    loc_t blacklist1_func_top = find_bof(blacklist1_func);
    debug("blacklist1_func_top=0x%016llx\n",blacklist1_func_top);

    patches.push_back({blacklist1_func_top,"\x00\x00\x80\xD2"/* movz x0, #0x0*/"\xC0\x03\x5F\xD6"/*ret*/,8});
    
    loc_t env_whitelist = setenv_whitelist;
    while (deref(env_whitelist+=8));
    env_whitelist+=8;
    debug("env_whitelist=0x%016llx\n",env_whitelist);

    loc_t blacklist2_func = find_literal_ref(env_whitelist);
    debug("blacklist2_func=0x%016llx\n",blacklist2_func);

    loc_t blacklist2_func_top = find_bof(blacklist2_func);
    debug("blacklist2_func_top=0x%016llx\n",blacklist2_func_top);
    
    patches.push_back({blacklist2_func_top,"\x00\x00\x80\xD2"/* movz x0, #0x0*/"\xC0\x03\x5F\xD6"/*ret*/,8});

    
    loc_t com_apple_system = findstr("com.apple.System.", true);
    debug("com_apple_system=0x%016llx\n",com_apple_system);

    loc_t com_apple_system_xref = find_literal_ref(com_apple_system);
    debug("com_apple_system_xref=0x%016llx\n",com_apple_system_xref);

    loc_t func3top = find_bof(com_apple_system_xref);
    debug("func3top=0x%016llx\n",func3top);

    patches.push_back({func3top,"\x00\x00\x80\xD2"/* movz x0, #0x0*/"\xC0\x03\x5F\xD6"/*ret*/,8});

    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_nvram_nosave_patch(){
    std::vector<patch> patches;

    loc_t saveenv_str = findstr("saveenv", true);
    debug("saveenv_str=0x%016llx\n",saveenv_str);

    loc_t saveenv_ref = memmem(&saveenv_str, sizeof(saveenv_str));
    debug("saveenv_ref=0x%016llx\n",saveenv_ref);

    loc_t saveenv_cmd_func_pos = deref(saveenv_ref+8);
    debug("saveenv_cmd_func_pos=0x%016llx\n",saveenv_cmd_func_pos);

    vmem saveenv_func = _vmem->getIter(saveenv_cmd_func_pos);
    
    assure(saveenv_func() == insn::b);
    
    loc_t nvram_save_func = saveenv_func().imm();
    debug("nvram_save_func=0x%016llx\n",nvram_save_func);
    
    patches.push_back({nvram_save_func,"\xC0\x03\x5F\xD6"/*ret*/,4});
    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_nvram_noremove_patch(){
    std::vector<patch> patches;

    auto nosave_patches = get_nvram_nosave_patch();
    loc_t nvram_save_func = nosave_patches.at(0)._location;
    debug("nvram_save_func=0x%016llx\n",nvram_save_func);

    loc_t bootcommand_str = findstr("boot-command", true);
    debug("bootcommand_str=0x%016llx\n",bootcommand_str);
    
    loc_t remove_env_func = 0;
    
    for (int i=0;; i++) {
        loc_t bootcommand_ref = find_literal_ref(bootcommand_str,i);
        debug("[%d] bootcommand_ref=0x%016llx\n",i,bootcommand_ref);
        vmem iter = _vmem->getIter(bootcommand_ref);
        
        for (int z=0; z<4; z++) {
            while (++iter != insn::bl);
            
            if (z == 0) { //this is the func where "boot-command" is passed as an argument
                remove_env_func = iter().imm();
                continue;
            }
            
            if (iter().imm() == nvram_save_func) { //after we unset an environment var, we usually do save_nvram within the next 3 functions
                goto found;
            }
        }
    }
    reterror("failed to find remove_env_func!"); //NOTREACHED
found:
    debug("remove_env_func=0x%016llx\n",remove_env_func);

    patches.push_back({remove_env_func,"\xC0\x03\x5F\xD6"/*ret*/,4});
    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_freshnonce_patch(){
    std::vector<patch> patches;

    loc_t noncevar_str = findstr("com.apple.System.boot-nonce", true);
    debug("noncevar_str=0x%016llx\n",noncevar_str);

    loc_t noncevar_ref = find_literal_ref(noncevar_str);
    debug("noncevar_ref=0x%016llx\n",noncevar_ref);

    loc_t noncefun1 = find_bof(noncevar_ref);
    debug("noncefun1=0x%016llx\n",noncefun1);

    loc_t noncefun1_blref = find_call_ref(noncefun1);
    debug("noncefun1_blref=0x%016llx\n",noncefun1_blref);

    loc_t noncefun2 = find_bof(noncefun1_blref);
    debug("noncefun2=0x%016llx\n",noncefun2);

    loc_t noncefun2_blref = find_call_ref(noncefun2);
    debug("noncefun2_blref=0x%016llx\n",noncefun2_blref);

    vmem iter = _vmem->getIter(noncefun2_blref);
    
    assure((--iter).supertype() == insn::sut_branch_imm);

    loc_t branchloc = iter;
    debug("branchloc=0x%016llx\n",branchloc);

    patches.push_back({branchloc,"\x1F\x20\x03\xD5"/*nop*/,4});
    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_large_picture_patch(){
    std::vector<patch> patches;

    loc_t picture_too_large_str = findstr("picture too large", false);
    debug("picture_too_large_str=0x%016llx\n",picture_too_large_str);
    
    loc_t picture_too_large_ref = find_literal_ref(picture_too_large_str);
    debug("picture_too_large_ref=0x%016llx\n",picture_too_large_ref);

    vmem iter = _vmem->getIter(picture_too_large_ref);

    while (--iter != insn::bcond || iter().condition() != insn::LS);

    pushINSN(insn::new_immediate_b(iter, iter().imm()));
    
    return patches;
}

std::vector<patch> ibootpatchfinder64_base::get_atv4k_enable_uart_patch(){
    UNCACHEPATCHES;
    
    int shellcode_insn_cnt = 11; //commitment
    
    loc_t shellcode = findnops(shellcode_insn_cnt);
    
#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    pushINSN(insn::new_immediate_movz(cPC, 0x2a0, 0, 0));
    pushINSN(insn::new_immediate_movk(cPC, 0xf10, 0, 16));
    pushINSN(insn::new_immediate_movk(cPC, 0x2  , 0, 32));

    pushINSN(insn::new_immediate_movz(cPC, 0x23a0, 1, 0));
    pushINSN(insn::new_immediate_movk(cPC, 0x87,   1, 16));
    pushINSN(insn::new_immediate_str_unsigned(cPC, 4, 0, 1, true));
    
    pushINSN(insn::new_immediate_movz(cPC, 0x63a0, 1, 0));
    pushINSN(insn::new_immediate_movk(cPC, 0x7,   1, 16));
    pushINSN(insn::new_immediate_str_unsigned(cPC, 0, 0, 1, true));

    
    pushINSN(insn::new_immediate_movz(cPC, 3, 0, 0));
    pushINSN(insn::new_general_ret(cPC));
    assure(insnNum == shellcode_insn_cnt);
#undef cPC
    
    loc_t str = findstr("debug-uarts", true);
    debug("str=0x%016llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    retassure((iter() == insn::adr || iter == insn::adrp) && iter().rd() == 0, "unexpected ref");
    
    while (++iter != insn::movz)
        retassure(iter() != insn::bl, "unexpected bl");
    
    retassure(iter().rd() == 1 && iter().imm() == 0, "unexpected mov insn");

    while (++iter != insn::bl)
        ;
    
    pushINSN(insn::new_immediate_bl(iter, shellcode));

    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder64_base::get_tz0_lock_patch(){
    UNCACHEPATCHES;
    
    /* Looking for: (iOS 9.1)
        orr        w10, wzr, #0x1
        str        w10, [x9]
        ldr        w11, [x9]
        tbz        w11, 0x0, ...
     */
    
    vmem iter = _vmem->getIter();

    try {
        while (true) {
            loc_t strloc = 0;
            loc_t ldrloc = 0;
            while (++iter != insn::orr);
            if (iter().rn() != 31 || iter().imm() != 1) continue;
            uint8_t orrrd = iter().rd();
            if (++iter != insn::str || iter().rt() != orrrd) continue;
            uint8_t strrn = iter().rn();
            strloc = iter;
            if (++iter != insn::ldr || iter().rn() != strrn) continue;
            uint8_t ldrrt = iter().rt();
            ldrloc = iter;
            if (++iter != insn::tbz && iter() != insn::tbnz) continue;
            if (iter().rt() != ldrrt) continue;
            
            pushINSN(insn::new_general_nop(strloc));
            pushINSN(insn::new_register_mov(ldrloc, 0, ldrrt, orrrd));
            
            {
                if (++iter != insn::str || iter().rt() != orrrd || iter().imm() != 4) continue;
                uint8_t strrn = iter().rn();
                strloc = iter;
                if (++iter != insn::ldr || iter().rn() != strrn || iter().imm() != 4) continue;
                uint8_t ldrrt = iter().rt();
                ldrloc = iter;
                if (++iter != insn::tbz && iter() != insn::tbnz) continue;
                if (iter().rt() != ldrrt) continue;
                
                pushINSN(insn::new_general_nop(strloc));
                pushINSN(insn::new_register_mov(ldrloc, 0, ldrrt, orrrd));
            }
        }
    } catch (...) {
        //will fail eventually. this is fine
    }
    
    retassure(patches.size(), "Failed to find patches");
    RETCACHEPATCHES;
}

std::vector<patch> ibootpatchfinder64_base::get_no_force_dfu_patch(){
    UNCACHEPATCHES;

    loc_t tref = -4;
    while ((tref = find_literal_ref(100*1000,0,tref+4))) {
        vmem iter = _vmem->getIter(tref);
        loc_t bdst = 0;
        {
            bool has_sub = false;
            for (int i=0; i<5; i++){
                auto insn = ++iter;
                if (insn == insn::b) break;
                else if (insn == insn::sub) has_sub = true;
                else if (has_sub && (insn == insn::cbz || insn == insn::cbnz)){
                    bdst = insn.imm();
                    goto good_spot;
                }
            }
            continue;
        good_spot:;
        }
        debug("tref=0x%016llx",tref);
        debug("bdst=0x%016llx",bdst);

        iter = bdst;
            
        {
            for (int i = 0; i< 5; i++){
                if (++iter == insn::bl) goto have_bl;
            }
            continue;
        have_bl:;
        }
        
        auto insn = ++iter;
        if (insn == insn::cbnz){
            pushINSN(insn::new_immediate_b(insn, insn.imm()));
            break;
        }else if (insn == insn::cbz){
            pushINSN(insn::new_general_nop(insn));
            break;
        }else{
            reterror("unexpected insn");
        }
    }

    retassure(patches.size(), "Failed to find patches");
    RETCACHEPATCHES;
}
