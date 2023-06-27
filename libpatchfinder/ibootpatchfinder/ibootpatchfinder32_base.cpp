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
    _vmem = new vmem_thumb({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
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
    _vmem = new vmem_thumb({{_buf,_bufSize,_base, (vmprot)(kVMPROTREAD | kVMPROTWRITE | kVMPROTEXEC)}});
    
    if (!strncmp((char*)&_buf[IBOOT_VERS_STR_OFFSET], "iBoot", sizeof("iBoot")-1)){
        retassure(_vers = atoi((char*)&_buf[IBOOT_VERS_STR_OFFSET+6]), "No iBoot version found!\n");
    }else{
        //iOS 1 iBoot??
        loc_t ibootstrloc = _vmem->memmem("iBoot-", sizeof("iBoot-")-1);
        retassure(ibootstrloc, "No iBoot version found!\n");
        const char *ibootstr = (char*)_vmem->memoryForLoc(ibootstrloc);
        retassure(_vers = atoi(ibootstr+6), "No iBoot version found!\n");
    }
    debug("iBoot-%d inputted", _vers);
}

ibootpatchfinder32_base::~ibootpatchfinder32_base(){
    //
}

bool ibootpatchfinder32_base::has_kernel_load(){
    try {
        return (bool) (_vmem->memstr(KERNELCACHE_PREP_STRING) != 0);
    } catch (...) {
        return 0;
    }
}

bool ibootpatchfinder32_base::has_recovery_console(){
    try {
        return (bool) (_vmem->memstr(ENTERING_RECOVERY_CONSOLE) != 0);
    } catch (...) {
        return 0;
    }
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
    
    pushINSN(thumb::new_T2_immediate_b(dbref+2, data_ref));
    pushINSN(thumb::new_T2_immediate_b(dbref+4, data_ref));
    
    
    loc_t kbag = find_literal_ref_thumb('KBAG');
    debug("kbag=0x%08x",kbag);
    
    vmem_thumb iter = _vmem->getIter(kbag);
    while ((++iter).supertype() != arm32::sut_branch_imm || iter() == arm32::bl)
        ;
    iter = iter().imm();
    while ((++iter).supertype() != arm32::sut_branch_imm || iter() == arm32::bl)
        ;
    pushINSN(thumb::new_T1_general_nop(iter));
    
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
            loc_t val = _vmem->deref(img4strref);
            _vmem->deref(val);
            warning("Failed to find f1topref, but 'img4strref' can be derefed. Is this a bad find? retrying...");
            goto retry_find_ref;
        } catch (...) {
            //
        }
        throw;
    }

    loc_t f2top = find_bof_thumb(f1topref);
    debug("f2top=0x%08x",f2top);

    
    vmem_thumb iter = _vmem->getIter(f2top);

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

    loc_t callback_ptr = _vmem->deref(val_r2);
    debug("callback_ptr=0x%08x",callback_ptr);

    loc_t callback = _vmem->deref(callback_ptr) & ~1;
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
    
    loc_t default_boot_args_data_xref = _vmem->memmem(&default_boot_args_str_loc, sizeof(default_boot_args_str_loc));
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

    vmem_thumb iter = _vmem->getIter(default_boot_args_xref);
    
    uint8_t xref_dst_reg = iter().rt();

    {
        if (++iter != arm32::it) {
            for (int i=0; i<0x30; i++) {
                if (++iter == arm32::it) break;
            }
            retassure(iter() == arm32::it, "it not found");
        }else{
            //this is expected
        }
    }
    
    pushINSN(thumb::new_T1_general_nop(iter));

    retassure(++iter == arm32::mov, "next insn not mov");
    
    if (iter().rd() == xref_dst_reg) {
        //this overwrites our reg, just nop it
        pushINSN(thumb::new_T1_general_nop(iter));
    }else{
        //our register always overwrites the other option now.
        //this is correct, no need to do anything in this case
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

    libinsn::vmem<arm32::thumb> iter = _vmem->getIter(xref);
    
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
    
    loc_t handler_str_loc = _vmem->memmem(handler_str.c_str(), handler_str.size());
    debug("handler_str_loc=0x%08x",handler_str_loc);
    
    handler_str_loc++;
    
    loc_t tableref = _vmem->memmem(&handler_str_loc, sizeof(handler_str_loc));
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
