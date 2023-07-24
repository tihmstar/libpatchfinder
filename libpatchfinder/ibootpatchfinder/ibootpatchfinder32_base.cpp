//
//  ibootpatchfinder32_base.cpp
//  libpatchfinder
//
//  Created by tihmstar on 07.07.21.
//

#include <libgeneral/macros.h>

#include "ibootpatchfinder32_base.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

//#ifdef XCODE
//#define WITH_WTFPWNDFU
//#endif

#define IBOOT_VERS_STR_OFFSET 0x280
#define IBOOT32_RESET_VECTOR_BYTES 0xEA00000E
#define ENTERING_RECOVERY_CONSOLE "Entering recovery mode, starting command prompt"
#define KERNELCACHE_PREP_STRING "__PAGEZERO"
#define DEFAULT_BOOTARGS_STR "rd=md0 nand-enable-reformat=1 -progress"
#define CERT_STR "Reliance on this certificate"

ibootpatchfinder32_base::ibootpatchfinder32_base(const char * filename) :
    ibootpatchfinder32(true)
{
    struct stat fs = {0};
    int fd = 0;
    bool didConstructSuccessfully = false;
    cleanup([&]{
        if (fd>0) close(fd);
        if (!didConstructSuccessfully) {
            safeFreeConst(_buf);
        }
    })
    
    assure((fd = open(filename, O_RDONLY)) != -1);
    assure(!fstat(fd, &fs));
    assure((_buf = (uint8_t*)malloc( _bufSize = fs.st_size)));
    assure(read(fd,(void*)_buf,_bufSize)==_bufSize);
    
    assure(_bufSize > 0x1000);
    
    assure(!strncmp((char*)&_buf[IBOOT_VERS_STR_OFFSET], "iBoot", sizeof("iBoot")-1));
    retassure(*(uint32_t*)&_buf[0] == IBOOT32_RESET_VECTOR_BYTES, "invalid magic");

    _entrypoint = _base = (loc_t)((*(uint32_t*)&_buf[0x20]) & ~0xFFF);
    debug("iBoot base at=0x%08x", _base);
    _vmemThumb = new vmem_thumb({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    _vmemArm = new vmem_arm({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    retassure(_vers = atoi((char*)&_buf[IBOOT_VERS_STR_OFFSET+6]), "No iBoot version found!\n");
    debug("iBoot-%d inputted", _vers);
    
    didConstructSuccessfully = true;
}

ibootpatchfinder32_base::ibootpatchfinder32_base(const void *buffer, size_t bufSize, bool takeOwnership)
:    ibootpatchfinder32(takeOwnership)
{
    _bufSize = bufSize;
    _buf = (uint8_t*)buffer;
    assure(_bufSize > 0x1000);
    
    retassure(*(uint32_t*)&_buf[0] == IBOOT32_RESET_VECTOR_BYTES, "invalid magic");

    _entrypoint = _base = (loc_t)((*(uint32_t*)&_buf[0x20]) & ~0xFFF);
    debug("iBoot base at=0x%08x", _base);
    _vmemThumb = new vmem_thumb({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    _vmemArm = new vmem_arm({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});

    if (!strncmp((char*)&_buf[IBOOT_VERS_STR_OFFSET], "iBoot", sizeof("iBoot")-1)){
        retassure(_vers = atoi((char*)&_buf[IBOOT_VERS_STR_OFFSET+6]), "No iBoot version found!\n");
    }else{
        //iOS 1 iBoot??
        loc_t ibootstrloc = memmem("iBoot-", sizeof("iBoot-")-1);
        retassure(ibootstrloc, "No iBoot version found!\n");
        const char *ibootstr = (char*)memoryForLoc(ibootstrloc);
        retassure(_vers = atoi(ibootstr+6), "No iBoot version found!\n");
    }
    debug("iBoot-%d inputted", _vers);
}

ibootpatchfinder32_base::~ibootpatchfinder32_base(){
    //
}

bool ibootpatchfinder32_base::has_kernel_load(){
    try {
        return (bool) (memstr(KERNELCACHE_PREP_STRING) != 0);
    } catch (...) {
        return 0;
    }
}

bool ibootpatchfinder32_base::has_recovery_console(){
    try {
        return (bool) (memstr(ENTERING_RECOVERY_CONSOLE) != 0);
    } catch (...) {
        return 0;
    }
}

std::vector<patch> ibootpatchfinder32_base::get_wtf_pwndfu_patch(){
#ifndef WITH_WTFPWNDFU
    reterror("Compiled without wtf pwndfu support!");
#else
    UNCACHEPATCHES;
    
#include "usb_0xA1_2_armv6.bin.h" //const unsigned char usb_0xA1_2_armv6[];
    
    loc_t str = findstr("Apple Mobile Device (DFU Mode)", true);
    debug("str=0x%08x",str);
    
    loc_t ref = find_literal_ref_thumb(str);
    debug("ref=0x%08x",ref);
    
    loc_t callfunc = find_call_ref_thumb(ref);
    debug("callfunc=0x%08x",callfunc);
    
    loc_t usb_init = find_bof_thumb(callfunc);
    debug("usb_init=0x%08x",usb_init);
    
    loc_t tgt = find_call_ref_thumb(usb_init);
    debug("tgt=0x%08x",tgt);
    
    loc_t dfuGetImage = find_bof_thumb(tgt);
    debug("dfuGetImage=0x%08x",dfuGetImage);

    loc_t ref_dfuGetImage = find_call_ref_thumb(dfuGetImage);
    debug("ref_dfuGetImage=0x%08x",ref_dfuGetImage);
    
    uint32_t loadaddr = find_register_value_thumb(ref_dfuGetImage, 0, ref_dfuGetImage-0x10);
    debug("loadaddr=0x%08x",loadaddr);
    
    vmem_thumb iter = _vmemThumb->getIter(tgt);
    
    while (++iter != arm32::ldr || iter().rt() != 3) assure(iter() != arm32::pop);
    
    loc_t handle_dfu_request_loc = iter().imm();
    debug("handle_dfu_request_loc=0x%08x",handle_dfu_request_loc);

    loc_t handle_dfu_request = deref(handle_dfu_request_loc) & ~ 1;
    debug("handle_dfu_request=0x%08x",handle_dfu_request);
    
    iter = handle_dfu_request;
    
    while (++iter != arm32::bl)
        ;
    
    loc_t handle_dev_2_host_request = iter().imm();
    debug("handle_dev_2_host_request=0x%08x",handle_dev_2_host_request);

    iter = handle_dev_2_host_request;
    
    uint8_t selector_register = -1;
    while ((++iter).supertype() != arm32::sut_branch_imm)
        ;

    loc_t switch_table = iter.pc() + iter().insnsize();
    debug("switch_table=0x%08x",switch_table);

    {
        --iter;
        retassure(iter() == arm32::add && iter().rd() == 0, "sanity check failed!");
        selector_register = iter().rn();
        debug("selector_register=0x%02x",selector_register);
    }
    
    uint8_t max_switch = deref(switch_table);
    retassure(max_switch = 6, "sanity check failed!");
    
    uint8_t get_state_jump_num = deref(switch_table+5);
    debug("get_state_jump_num=0x%02x",get_state_jump_num);
    patches.push_back({switch_table +2, &get_state_jump_num, 1});

    loc_t breq_get_state = switch_table+2*get_state_jump_num;
    debug("breq_get_state=0x%02x",breq_get_state);
    
    iter = breq_get_state;
    
    retassure(iter() == arm32::ldr && iter().subtype() == arm32::st_literal, "sanity check failed");
    
    loc_t state_ptr_loc = iter().imm();
    state_ptr_loc = deref(state_ptr_loc);
    debug("state_ptr_loc=0x%02x",state_ptr_loc);

    while (++iter != arm32::ldr || iter().subtype() != arm32::st_immediate)
        ;
    retassure(iter().imm() == 0, "sanity check failed!");
    loc_t ldr_loc = iter;
    debug("ldr_loc=0x%02x",ldr_loc);

    uint8_t tgt_ptr_reg = iter().rn();
    debug("tgt_ptr_reg=0x%02x",tgt_ptr_reg);
    
    int payloadInsnCnt = sizeof(usb_0xA1_2_armv6)/4;
    if (sizeof(usb_0xA1_2_armv6) & 3) payloadInsnCnt++;
    loc_t shellcode_usb = findnops(payloadInsnCnt, true, 0x00000000);
    debug("shellcode_usb=0x%016llx",shellcode_usb);
    patches.push_back({shellcode_usb,&usb_0xA1_2_armv6,sizeof(usb_0xA1_2_armv6)});

    
    uint32_t shellcode_insn_cnt = 18; //commitment
    loc_t shellcode = findnops((shellcode_insn_cnt/2)+1, true, 0x00000000);
    debug("shellcode=0x%016llx",shellcode);
    
#define cPC (shellcode+(insnNum)*2)
#define pushINSNCPC(_pinsn) do {auto _pinsnn = _pinsn; pushINSN(_pinsnn); insnNum += (_pinsnn.insnsize()>>1);} while (0);

    int insnNum = 0;
    
    uint32_t bloc_dfu_uplod = 10; //commitment
    uint32_t funcend = 14; //commitment

    
    pushINSNCPC(thumb::new_T2_register_mov(cPC, 0, 0));
    pushINSNCPC(thumb::new_T1_immediate_cmp(cPC, 1, selector_register));
    pushINSNCPC(thumb::new_T1_immediate_bcond(cPC, shellcode+bloc_dfu_uplod*2, cond::EQ));
    /*
        CASE DFU_GETSTATE
     */
    pushINSNCPC(thumb::new_T1_immediate_ldr(cPC, 0, tgt_ptr_reg, tgt_ptr_reg));
    pushINSNCPC(thumb::new_T1_literal_ldr(cPC, shellcode+funcend*2, selector_register));
    pushINSNCPC(thumb::new_T1_immediate_ldr(cPC, 0, selector_register, selector_register));
    pushINSNCPC(thumb::new_T1_immediate_ldr(cPC, 0, selector_register, selector_register));
    pushINSNCPC(thumb::new_T1_immediate_str(cPC, 0, tgt_ptr_reg, selector_register));
    pushINSNCPC(thumb::new_T1_immediate_movs(cPC, 1, 0));
    pushINSNCPC(thumb::new_T1_general_bx(cPC, 14));
    assure(insnNum == bloc_dfu_uplod);
    /*
        CASE DFU_UPLOAD
     */
    pushINSNCPC(thumb::new_T1_literal_ldr(cPC, shellcode+funcend*2+4, 0));
    pushINSNCPC(thumb::new_T1_immediate_ldr(cPC, 0, tgt_ptr_reg, 1));
    pushINSNCPC(thumb::new_T2_immediate_b(cPC, shellcode_usb));

    pushINSNCPC(thumb::new_T2_register_mov(cPC, 0, 0));
    assure(insnNum == funcend && (funcend & 1) == 0);
    //function end, data section
    patches.push_back({shellcode+funcend*2, &state_ptr_loc, 4});insnNum+=2;
    patches.push_back({shellcode+funcend*2 + 4, &loadaddr, 4});insnNum+=2;
    assure(insnNum == shellcode_insn_cnt);
#undef pushINSNCPC
#undef cPC

    
    {
        //both GET_STATE and DFU_UPLOAD call now into shellcode
        iter = breq_get_state;
        while (++iter != arm32::b)
            ;
        loc_t b_loc = iter;
        debug("b_loc=0x%016llx",b_loc);
        pushINSN(thumb::new_T1_immediate_bl(breq_get_state, shellcode));
        for (loc_t liter = breq_get_state+4; liter < b_loc; liter += 2){
            pushINSN(thumb::new_T2_register_mov(liter,0,0));
        }
    }

    
    {
        //change USB string
        loc_t usb_str = findstr("CPID:%04X CPRV:%02X CPFM:%02X SCEP:%02X BDID:%02X ECID:%016llX IBFL:%02X", true);
        debug("usb_str=0x%08x",usb_str);
        
        loc_t usb_str_ref = memmem(&usb_str,sizeof(loc_t));
        debug("usb_str_ref=0x%08x",usb_str_ref);
        
        char newstr[] = "CPID:%04X CPRV:%02X CPFM:%02X SCEP:%02X BDID:%02X ECID:%016llX IBFL:%02X PWND:[WTF]";
        size_t newstr_nopsize = sizeof(newstr)/4;
        if (sizeof(newstr) & 3) newstr_nopsize++;
        
        loc_t newstr_loc = findnops(newstr_nopsize,true,0x00000000);
        debug("newstr_loc=0x%08x",newstr_loc);

        patches.push_back({newstr_loc,newstr,sizeof(newstr)});
        patches.push_back({usb_str_ref,&newstr_loc,sizeof(newstr_loc)});
    }
    
    RETCACHEPATCHES;
#endif
}

std::vector<patch> ibootpatchfinder32_base::get_sigcheck_img3_patch(){
    std::vector<patch> patches;
    
    //iOS 4.1 //pre-APTicket era
    
    loc_t cert_ref = find_literal_ref_thumb('CERT');
    debug("cert_ref=0x%08x",cert_ref);
    
    loc_t bof = find_bof_thumb(cert_ref);
    debug("bof=0x%08x",bof);
    
    loc_t bref = find_call_ref_thumb(bof);
    debug("bref=0x%08x",bref);
    
    
    loc_t data_ref = find_literal_ref_thumb('DATA');
    debug("data_ref=0x%08x",data_ref);
    
    loc_t dbref = 0;
    for (int i=0; i<0x30; i++){
        try {
            dbref = find_branch_ref_thumb(data_ref-i*2, -0x100);
            data_ref -= i*2;
            debug("Got bref from 0x%08x to data_ref at 0x%08x",dbref,data_ref);
            break;
        } catch (...) {
            continue;
        }
    }
    
    pushINSN(thumb::new_T1_immediate_movs(bref, 0, 0));
    pushINSN(thumb::new_T1_immediate_movs(bref+2, 0, 0));
    
    vmem_thumb iter = _vmemThumb->getIter(data_ref);
    for (int i=0; i<2; i++){
        auto isn = --iter;
        if (isn == arm32::str && isn.rn() == 13){
            uint8_t rt = iter().rt();
            if ((--iter == arm32::mov || --iter == arm32::mov) && iter().rd() == rt){
                debug("Fixing data_ref");
                data_ref = iter;
                pushINSN(thumb::new_T1_immediate_movs(iter, 0, rt));
                if (iter().insnsize() != 2) {
                    pushINSN(thumb::new_T1_immediate_movs(iter.pc()+2, 0, rt));
                }
            }
            break;
        }else if (isn == mov && isn.subtype() == subtype::st_immediate && isn.imm() == 1){
            debug("Fixing codesign resval");
            pushINSN(thumb::new_T1_immediate_movs(iter, 0, isn.rd()));
            if (iter().insnsize() != 2) {
                pushINSN(thumb::new_T1_immediate_movs(iter.pc()+2, 0, isn.rd()));
            }
            data_ref = iter;
            break;
        }
    }
    
    pushINSN(thumb::new_T2_immediate_b(dbref+2, data_ref));
    pushINSN(thumb::new_T2_immediate_b(dbref+4, data_ref));
    
    return patches;
}

std::vector<patch> ibootpatchfinder32_base::get_sigcheck_img4_patch(){
    std::vector<patch> patches;
    loc_t img4str = findstr("IMG4", true);
    debug("img4str=0x%08x",img4str);
    loc_t img4strref = -2;
    loc_t f1top = 0;
    loc_t f1topref = 0;
    
retry_find_ref:
    img4strref = find_literal_ref_thumb(img4str, 0, img4strref+2);
    debug("img4strref=0x%08x",img4strref);
    try{

        f1top = find_bof_thumb(img4strref);
        debug("f1top=0x%08x",f1top);

        f1topref = find_call_ref_thumb(f1top,1);
        debug("f1topref=0x%08x",f1topref);
    } catch (...){
        try {
            loc_t val = deref(img4strref);
            deref(val);
            warning("Failed to find f1topref, but 'img4strref' can be derefed. Is this a bad find? retrying...");
            goto retry_find_ref;
        } catch (...) {
            //
        }
        throw;
    }

    loc_t f2top = find_bof_thumb(f1topref);
    debug("f2top=0x%08x",f2top);

    
    vmem_thumb iter = _vmemThumb->getIter(f2top);

    loc_t val_r2 = 0;
    loc_t val_r3 = 0;
    
    while (true) {
        auto insn = ++iter;
        if (insn == arm32::ldr && insn.subtype() == st_literal) {
            if (insn.rt() == 2) {
                val_r2 = insn.imm();
            }else if (insn.rt() == 3) {
                val_r3 = insn.imm();
            }
        } else if (insn == arm32::bl){
            if (val_r2 && val_r3) {
                break;
            }
        }
    }

    loc_t callback_ptr = deref(val_r2);
    debug("callback_ptr=0x%08x",callback_ptr);

    loc_t callback = deref(callback_ptr) & ~1;
    debug("callback=0x%08x",callback);
    
    iter = callback;
    
    retassure(iter() == arm32::push, "unexpected instruction. Expecting push");

    while (++iter != arm32::pop || !iter().reglist().pc);

    loc_t pop_pc = iter;
    debug("pop_pc=0x%08x",pop_pc);

    while (--iter != arm32::mov) retassure(iter() != arm32::it, "found 'it' too early")
        ;
    
    loc_t movpos = iter;
    uint8_t movfromreg = iter().rm();
    debug("movpos=0x%08x",movpos);
    debug("movfromreg=%d",movfromreg);

    while (--iter != arm32::it)
        ;
    
    loc_t itpos = iter;
    debug("itpos=0x%08x",itpos);

    pushINSN(thumb::new_T1_immediate_movs(itpos, 0, movfromreg));

    return patches;
}


std::vector<patch> ibootpatchfinder32_base::get_boot_arg_patch(const char *bootargs){
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
                for (int i=0; i<0x30; i++) {
                    if (++iter == arm32::it) break;
                }
                if (iter() != arm32::it){
                    methodArmv6 = true;
                    debug("Could not found 'it' insn, switching to armv6 method");
                }
            }else{
                //this is expected
            }
        }
        if (!methodArmv6) {
            pushINSN(thumb::new_T1_general_nop(iter));

            retassure(++iter == arm32::mov, "next insn not mov");
            
            if (iter().rd() == xref_dst_reg) {
                //this overwrites our reg, just nop it
                pushINSN(thumb::new_T1_general_nop(iter));
            }else{
                //our register always overwrites the other option now.
                //this is correct, no need to do anything in this case
            }
        }else{
            iter = default_boot_args_xref;
            if (--iter == arm32::bcond){
                pushINSN(thumb::new_T1_general_nop(iter.pc()));
            } else if (--iter == arm32::bcond){
                pushINSN(thumb::new_T1_general_nop(iter.pc()));
                pushINSN(thumb::new_T1_general_nop(iter.pc()+2));
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

std::vector<patch> ibootpatchfinder32_base::get_debug_enabled_patch(){
    std::vector<patch> patches;

    loc_t debug_enabled = findstr("debug-enabled", true);
    debug("debug_enabled=0x%08x",debug_enabled);
    retassure(debug_enabled, "Failed to find str");

    loc_t xref = find_literal_ref_thumb(debug_enabled);
    debug("xref=0x%08x",xref);
    retassure(xref,"Failed to find ref");

    vmem_thumb iter = _vmemThumb->getIter(xref);
    
    while (++iter != arm32::bl);
    while (++iter != arm32::bl);
    
    loc_t ploc = iter;
    debug("ploc=0x%08x",ploc);
    
    pushINSN(thumb::new_T1_immediate_movs(ploc, 1, 0));
    pushINSN(thumb::new_T1_immediate_movs(ploc+2, 1, 0));

    return patches;
}


std::vector<patch> ibootpatchfinder32_base::get_cmd_handler_patch(const char *cmd_handler_str, loc64_t ptr){
    std::vector<patch> patches;
    std::string handler_str{"A"};
    handler_str+= cmd_handler_str;
    ((char*)handler_str.c_str())[0] = '\0';
    
    loc_t handler_str_loc = memmem(handler_str.c_str(), handler_str.size());
    debug("handler_str_loc=0x%08x",handler_str_loc);
    
    handler_str_loc++;
    
    loc_t tableref = memmem(&handler_str_loc, sizeof(handler_str_loc));
    debug("tableref=0x%08x",tableref);
    
    patches.push_back({tableref+sizeof(loc_t),&ptr,sizeof(loc_t)});
    
    return patches;
}

ibootpatchfinder::loc64_t ibootpatchfinder32_base::find_iBoot_logstr(uint64_t loghex, int skip, uint64_t shortdec){
    loc_t foundpos = 0;
    do{
        loc_t upper = find_literal_ref_thumb(loghex >> 32);
        loc_t lower = find_literal_ref_thumb(loghex & 0xffffffff,0,upper);

        uint64_t diff = abs((long)(lower-lower));
        retassure(diff <=0x8, "upper and lower too far apart");
        foundpos = upper;
    }while(skip--);
    
    return foundpos;
}
