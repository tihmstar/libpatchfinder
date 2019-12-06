//
//  ibootpatchfinder64.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "ibootpatchfinder64.hpp"
#include "all_liboffsetfinder.hpp"
#include <libgeneral/macros.h>
#include "OFexception.hpp"

using namespace std;
using namespace tihmstar::offsetfinder64;

#define IBOOT_VERS_STR_OFFSET 0x280
#define iBOOT_BASE_OFFSET 0x318
#define KERNELCACHE_PREP_STRING "__PAGEZERO"
#define ENTERING_RECOVERY_CONSOLE "Entering recovery mode, starting command prompt"
#define DEBUG_ENABLED_DTRE_VAR_STR "debug-enabled"
#define DEFAULT_BOOTARGS_STR "rd=md0 nand-enable-reformat=1 -progress"
#define DEFAULT_BOOTARGS_STR_13 "rd=md0 -progress -restore"
#define CERT_STR "Apple Inc.1"

ibootpatchfinder64::ibootpatchfinder64(const char * filename) :
    patchfinder64(true),
    _vers(0) //is filled during construction
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
    retassure(*(uint32_t*)&_buf[0] == 0x90000000, "invalid magic");
    
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[iBOOT_BASE_OFFSET];
    
    _vmem = new vmem({{_buf,_bufSize,_base, vsegment::vmprot::kVMPROTREAD | vsegment::vmprot::kVMPROTWRITE | vsegment::vmprot::kVMPROTEXEC}});
    
    retassure(_vers = atoi((char*)&_buf[IBOOT_VERS_STR_OFFSET+6]), "No iBoot version found!\n");
    
    debug("iBoot-%d inputted\n", _vers);
    
    didConstructSuccessfully = true;
}

ibootpatchfinder64::ibootpatchfinder64(const void *buffer, size_t bufSize) :
    patchfinder64(false),
    _vers(0) //is filled during construction
{
    _bufSize = bufSize;
    _buf = (uint8_t*)buffer;
    assure(_bufSize > 0x1000);
    
    assure(!strncmp((char*)&_buf[IBOOT_VERS_STR_OFFSET], "iBoot", sizeof("iBoot")-1));
    retassure(*(uint32_t*)&_buf[0] == 0x90000000, "invalid magic");
    
    _entrypoint = _base = (loc_t)*(uint64_t*)&_buf[iBOOT_BASE_OFFSET];
    
    _vmem = new vmem({{_buf,_bufSize,_base, vsegment::vmprot::kVMPROTREAD | vsegment::vmprot::kVMPROTWRITE | vsegment::vmprot::kVMPROTEXEC}});
    
    retassure(_vers = atoi((char*)&_buf[IBOOT_VERS_STR_OFFSET+6]), "No iBoot version found!\n");
    
    debug("iBoot-%d inputted\n", _vers);
}


bool ibootpatchfinder64::has_kernel_load() noexcept{
    try {
        return (bool) (_vmem->memstr(KERNELCACHE_PREP_STRING) != 0);
    } catch (...) {
        return 0;
    }
}

bool ibootpatchfinder64::has_recovery_console() noexcept{
    try {
        return (bool) (_vmem->memstr(ENTERING_RECOVERY_CONSOLE) != 0);
    } catch (...) {
        return 0;
    }
}

std::vector<patch> ibootpatchfinder64::get_sigcheck_patch(){
    std::vector<patch> patches;
    loc_t img4str = findstr("IMG4", true);
    debug("img4str=%p\n",img4str);

    loc_t img4strref = find_literal_ref(img4str);
    debug("img4strref=%p\n",img4strref);

    loc_t f1top = find_bof(img4strref);
    debug("f1top=%p\n",f1top);

    loc_t f1topref = find_call_ref(f1top,1);
    debug("f1topref=%p\n",f1topref);

    loc_t f2top = find_bof(f1topref);
    debug("f2top=%p\n",f2top);

    vmem iter(*_vmem,f2top);

    loc_t adr_x3 = 0;
    loc_t adr_x2 = 0;

    while (true) {
        if (++iter == insn::adr && iter().rd() == 2){
            adr_x2 = iter;
        }else if (iter() == insn::adr && iter().rd() == 3){
            adr_x3 = iter;
        }else if (iter() == insn::bl){
            if (adr_x2 && adr_x3) {
                break;
            }else{
                adr_x2 = 0;
                adr_x3 = 0;
            }
        }
    }
    
    assure(adr_x2);
    iter = adr_x2;
    
    loc_t callback = (loc_t)_vmem->deref((loc_t)iter().imm());
    debug("callback=%p\n",callback);

    iter = callback;
    
    while (++iter != insn::ret);
    
    loc_t ret = iter;
    debug("ret=%p\n",ret);

    const char p[] ="\x00\x00\x80\xD2" /*mov x0,0*/ "\xC0\x03\x5F\xD6" /*ret*/;
    patches.push_back({ret,p,sizeof(p)-1});
    
    return patches;
}

std::vector<patch> ibootpatchfinder64::get_boot_arg_patch(const char *bootargs){
    std::vector<patch> patches;
    loc_t default_boot_args_str_loc = 0;
    loc_t default_boot_args_xref = 0;

    default_boot_args_str_loc = _vmem->memstr(DEFAULT_BOOTARGS_STR);
    if(!default_boot_args_str_loc){
        debug("DEFAULT_BOOTARGS_STR not found, trying fallback to DEFAULT_BOOTARGS_STR_13\n");
        default_boot_args_str_loc = _vmem->memstr(DEFAULT_BOOTARGS_STR_13);
    }
    assure(default_boot_args_str_loc);
    debug("default_boot_args_str_loc=%p\n",default_boot_args_str_loc);
   
    assure(default_boot_args_xref = find_literal_ref(default_boot_args_str_loc));
    debug("default_boot_args_xref=%p\n",default_boot_args_xref);

    if (strlen(bootargs) > strlen(DEFAULT_BOOTARGS_STR)) {
        loc_t cert_str_loc = 0;
        debug("Relocating boot-args string...\n");

        /* Find the "Reliance on this cert..." string. */
        retassure(cert_str_loc = _vmem->memstr(CERT_STR), "Unable to find \"%s\" string!\n", CERT_STR);

        debug("\"%s\" string found at %p\n", CERT_STR, cert_str_loc);

        /* Point the boot-args xref to the "Reliance on this cert..." string. */
        debug("Pointing default boot-args xref to %p...\n", cert_str_loc);

        default_boot_args_str_loc = cert_str_loc;

        insn pins(default_boot_args_xref, insn::adr, insn::st_general, (int64_t)default_boot_args_str_loc, 9, 0, 0, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    
    debug("Applying custom boot-args \"%s\"\n", bootargs);
    patches.push_back({default_boot_args_str_loc, bootargs, strlen(bootargs)+1});
    
    vmem iter(*_vmem,default_boot_args_xref);
    uint8_t xrefRD = iter().rd();
    debug("xrefRD=%d\n",xrefRD);

    
    while (++iter != insn::csel);
    
    insn csel = iter();
    debug("csel=%p\n", (loc_t)csel.pc());

    assure(xrefRD == csel.rn() || xrefRD == csel.other());
    
    debug("cselrd=%d\n",csel.rd());
    
    insn pmov(iter(), insn::mov, insn::st_register, 0, csel.rd(), -1, 0, xrefRD);
    
    debug("(%p)patching: \"mov x%d, x%d\"\n",(loc_t)pmov.pc(),pmov.rd(),pmov.other());
    uint32_t opcode = pmov.opcode();
    patches.push_back({(loc_t)pmov.pc(), &opcode, 4});

    
    while ((--iter).supertype() != insn::sut_branch_imm || iter() == insn::bl);
    
    debug("branch loc=%p\n",(loc_t)iter);
    
    iter = (loc_t)iter().imm();

    debug("branch dst=%p\n",(loc_t)iter);
    
    if (iter() != insn::adr) {
        while (++iter != insn::adr);
    }

    insn pins(iter, insn::adr, insn::st_general, (int64_t)default_boot_args_str_loc, iter().rd(), 0, 0, 0);
    opcode = pins.opcode();
    patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    debug("(%p)patching: \"adr x%d, 0x%llx\"\n",(loc_t)pins.pc(),pins.rd(),pins.imm());

    return patches;
}

std::vector<patch> ibootpatchfinder64::get_debug_enabled_patch(){
    std::vector<patch> patches;
    
    loc_t debug_enabled = findstr("debug-enabled", true);
    debug("debug_enabled=%p\n",debug_enabled);
    
    loc_t xref = find_literal_ref(debug_enabled);
    debug("xref=%p\n",xref);
    
    vmem iter(*_vmem,xref);
    
    while (++iter != insn::bl);
    while (++iter != insn::bl);
    
    patches.push_back({iter,"\x20\x00\x80\xD2" /* mov x0,1 */,4});
    
    return patches;
}

std::vector<patch> ibootpatchfinder64::get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr){
    std::vector<patch> patches;
    std::string handler_str{"A"};
    handler_str+= cmd_handler_str;
    ((char*)handler_str.c_str())[0] = '\0';
    
    loc_t handler_str_loc = _vmem->memmem(handler_str.c_str(), handler_str.size());
    debug("handler_str_loc=%p\n",handler_str_loc);
    
    handler_str_loc++;
    
    loc_t tableref = _vmem->memmem(&handler_str_loc, sizeof(handler_str_loc));
    debug("tableref=%p\n",tableref);
    
    patches.push_back({tableref+8,&ptr,8});
    
    return patches;
}

std::vector<patch> ibootpatchfinder64::get_unlock_nvram_patch(){
    std::vector<patch> patches;

    loc_t debug_uarts_str = findstr("debug-uarts", true);
    debug("debug_uarts_str=%p\n",debug_uarts_str);

    loc_t debug_uarts_ref = _vmem->memmem(&debug_uarts_str, sizeof(debug_uarts_str));
    debug("debug_uarts_ref=%p\n",debug_uarts_ref);

    loc_t setenv_whitelist = debug_uarts_ref;
    
    while (_vmem->deref(setenv_whitelist-=8));
    setenv_whitelist+=8;
    debug("setenv_whitelist=%p\n",setenv_whitelist);

    loc_t blacklist1_func = find_literal_ref(setenv_whitelist);
    debug("blacklist1_func=%p\n",blacklist1_func);
    
    loc_t blacklist1_func_top = find_bof(blacklist1_func);
    debug("blacklist1_func_top=%p\n",blacklist1_func_top);

    patches.push_back({blacklist1_func_top,"\x00\x00\x80\xD2"/* movz x0, #0x0*/"\xC0\x03\x5F\xD6"/*ret*/,8});
    
    loc_t env_whitelist = setenv_whitelist;
    while (_vmem->deref(env_whitelist+=8));
    env_whitelist+=8;
    debug("env_whitelist=%p\n",env_whitelist);

    loc_t blacklist2_func = find_literal_ref(env_whitelist);
    debug("blacklist2_func=%p\n",blacklist2_func);

    loc_t blacklist2_func_top = find_bof(blacklist2_func);
    debug("blacklist2_func_top=%p\n",blacklist2_func_top);
    
    patches.push_back({blacklist2_func_top,"\x00\x00\x80\xD2"/* movz x0, #0x0*/"\xC0\x03\x5F\xD6"/*ret*/,8});

    
    loc_t com_apple_system = findstr("com.apple.System.", true);
    debug("com_apple_system=%p\n",com_apple_system);

    loc_t com_apple_system_xref = find_literal_ref(com_apple_system);
    debug("com_apple_system_xref=%p\n",com_apple_system_xref);

    loc_t func3top = find_bof(com_apple_system_xref);
    debug("func3top=%p\n",func3top);

    patches.push_back({func3top,"\x00\x00\x80\xD2"/* movz x0, #0x0*/"\xC0\x03\x5F\xD6"/*ret*/,8});

    return patches;
}

std::vector<patch> ibootpatchfinder64::get_nvram_nosave_patch(){
    std::vector<patch> patches;

    loc_t saveenv_str = findstr("saveenv", true);
    debug("saveenv_str=%p\n",saveenv_str);

    loc_t saveenv_ref = _vmem->memmem(&saveenv_str, sizeof(saveenv_str));
    debug("saveenv_ref=%p\n",saveenv_ref);

    loc_t saveenv_cmd_func_pos = _vmem->deref(saveenv_ref+8);
    debug("saveenv_cmd_func_pos=%p\n",saveenv_cmd_func_pos);

    vmem saveenv_func(*_vmem,saveenv_cmd_func_pos);
    
    assure(saveenv_func() == insn::b);
    
    loc_t nvram_save_func = saveenv_func().imm();
    debug("nvram_save_func=%p\n",nvram_save_func);
    
    patches.push_back({nvram_save_func,"\xC0\x03\x5F\xD6"/*ret*/,4});
    return patches;
}

std::vector<patch> ibootpatchfinder64::get_nvram_noremove_patch(){
    std::vector<patch> patches;

    auto nosave_patches = get_nvram_nosave_patch();
    loc_t nvram_save_func = nosave_patches.at(0)._location;
    debug("nvram_save_func=%p\n",nvram_save_func);

    loc_t bootcommand_str = findstr("boot-command", true);
    debug("bootcommand_str=%p\n",bootcommand_str);
    
    loc_t remove_env_func = 0;
    
    for (int i=0;; i++) {
        loc_t bootcommand_ref = find_literal_ref(bootcommand_str,i);
        debug("[%d] bootcommand_ref=%p\n",i,bootcommand_ref);
        vmem iter(*_vmem,bootcommand_ref);
        
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
    debug("remove_env_func=%p\n",remove_env_func);

    patches.push_back({remove_env_func,"\xC0\x03\x5F\xD6"/*ret*/,4});
    return patches;
}

std::vector<patch> ibootpatchfinder64::get_freshnonce_patch(){
    std::vector<patch> patches;

    loc_t noncevar_str = findstr("com.apple.System.boot-nonce", true);
    debug("noncevar_str=%p\n",noncevar_str);

    loc_t noncevar_ref = find_literal_ref(noncevar_str);
    debug("noncevar_ref=%p\n",noncevar_ref);

    loc_t noncefun1 = find_bof(noncevar_ref);
    debug("noncefun1=%p\n",noncefun1);

    loc_t noncefun1_blref = find_call_ref(noncefun1);
    debug("noncefun1_blref=%p\n",noncefun1_blref);

    loc_t noncefun2 = find_bof(noncefun1_blref);
    debug("noncefun2=%p\n",noncefun2);

    loc_t noncefun2_blref = find_call_ref(noncefun2);
    debug("noncefun2_blref=%p\n",noncefun2_blref);

    vmem iter(*_vmem,noncefun2_blref);
    
    assure((--iter).supertype() == insn::sut_branch_imm);

    loc_t branchloc = iter;
    debug("branchloc=%p\n",branchloc);

    patches.push_back({branchloc,"\x1F\x20\x03\xD5"/*nop*/,4});
    return patches;
}

std::vector<patch> ibootpatchfinder64::get_readback_loadaddr_patch(){
    std::vector<patch> patches;

    loc_t cmd_results_str = findstr("cmd-results", true);
    debug("cmd_results_str=%p\n",cmd_results_str);

    loc_t cmd_results_ref = find_literal_ref(cmd_results_str);
    debug("cmd_results_ref=%p\n",cmd_results_ref);

    loc_t loadaddr_str = findstr("loadaddr", true);
    debug("loadaddr_str=%p\n",loadaddr_str);

    loc_t file_size_str = findstr("filesize", true);
    debug("file_size_str=%p\n",file_size_str);
    
    
    loc_t file_size_ref = find_literal_ref(file_size_str);
    debug("file_size_ref=%p\n",file_size_ref);
    
    vmem iter(*_vmem,file_size_ref);

    while (++iter != insn::bl);
    
    loc_t getenv_int_func = iter().imm();
    debug("getenv_int_func=%p\n",getenv_int_func);


    debug("Pointing cmd_results_ref to %p...\n", loadaddr_str);
    {
        insn pins(cmd_results_ref, insn::adr, insn::st_general, (int64_t)loadaddr_str, 0, 0, 0, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }

    iter = cmd_results_ref;

    while (++iter != insn::bl);

    {
        debug("replacing getenv func with getenvint func at=%p\n",(loc_t)iter);
        insn pins(iter, insn::bl, insn::st_general, (int64_t)getenv_int_func, 0, 0, 0, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }

    ++iter;
    ++iter;

    debug("Loading file_size_str to x0\n");
    loc_t loadArgLoc = iter;
    debug("loadArgLoc=%p\n",loadArgLoc);
    {
        insn pins(loadArgLoc, insn::adr, insn::st_general, (int64_t)file_size_str, 0, 0, 0, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }

    debug("Calling getenv\n");
    ++iter;
    loc_t callGentenvLoc = iter;
    debug("callGentenvLoc=%p\n",callGentenvLoc);
    {
        insn pins(callGentenvLoc, insn::bl, insn::st_general, (int64_t)getenv_int_func, 0, 0, 0, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    
    while (++iter != insn::bl);
    
    loc_t strlenloc = iter;
    debug("strlenloc=%p\n",strlenloc);
    patches.push_back({strlenloc,"\xE1\x03\x00\xAA"/*mov x1, x0*/"\x1F\x20\x03\xD5"/*nop*/,8});
    return patches;
}


std::vector<patch> ibootpatchfinder64::get_memload_patch(){
    std::vector<patch> patches;
    
    loc_t loadaddr_str = findstr("loadaddr", true);
    debug("loadaddr_str=%p\n",loadaddr_str);

    loc_t memboot_str = findstr("memboot", true);
    debug("memboot_str=%p\n",memboot_str);

    debug("renaming memboot to memload\n");
    patches.push_back({memboot_str,"memload",strlen("memload")});

    loc_t memboot_table_ptr = _vmem->memmem(&memboot_str, sizeof(memboot_str));
    debug("memboot_table_ptr=%p\n",memboot_table_ptr);

    memboot_table_ptr+=8;
    
    loc_t memboot_fuc = _vmem->deref(memboot_table_ptr);
    debug("memboot_fuc=%p\n",memboot_fuc);

    vmem iter(*_vmem,memboot_fuc);

    while (++iter != insn::bl);
    
    loc_t firstBL = iter;
    debug("firstBL=%p\n",firstBL);
    
    loc_t getenv_func = iter().imm();
    debug("getenv_func=%p\n",getenv_func);

    while (++iter != insn::cbz);

    loc_t fistCBZ = iter;
    debug("fistCBZ=%p\n",fistCBZ);
    
    loc_t cbzdst = iter().imm();
    debug("cbzdst=%p\n",cbzdst);

    
    loc_t err_loading_ramdisk_str = findstr("error loading ramdisk\n", true);
    debug("err_loading_ramdisk_str=%p\n",err_loading_ramdisk_str);

    loc_t err_loading_ramdisk_ref = find_literal_ref(err_loading_ramdisk_str);
    debug("err_loading_ramdisk_ref=%p\n",err_loading_ramdisk_ref);

    
    loc_t bsrc = find_branch_ref(err_loading_ramdisk_ref, -0x200);
    debug("bsrc=%p\n",bsrc);

    iter = bsrc;
    
    while (--iter != insn::bl);
    
    loc_t load_ramdisk_func = iter().imm();
    debug("load_ramdisk_func=%p\n",load_ramdisk_func);

    iter = load_ramdisk_func;
    do{
        while (++iter != insn::bl);
    }while (find_register_value(iter,3) != 'rdsk');
    
    loc_t loadimg_func = iter().imm();
    debug("loadimg_func=%p\n",loadimg_func);

    
    iter = firstBL;
    ++iter;
    
    uint8_t backupreg = iter().rd();
    debug("filesize reg=%u\n",backupreg);
    ++iter;
    
    {
        debug("arg0 = loadaddr\n");
        insn pins(iter, insn::adr, insn::st_immediate, (int64_t)loadaddr_str, 0, 0, 0, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    ++iter;
    {
        debug("call getenv(loadaddr)\n");
        insn pins(iter, insn::bl, insn::st_general, (int64_t)getenv_func, 0, 0, 0, 0);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    ++iter;
    {
        debug("x1 = filesize_val\n");
        insn pins(iter, insn::mov, insn::st_register, 0, 1, -1, 0, backupreg);
        uint32_t opcode = pins.opcode();
        patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    ++iter;
    debug("x2 = 'ibot'\n");
    {
       debug("  x2 = '  ot'\n");
       insn pins(iter, insn::movz, insn::st_immediate, 'ibot' & 0xffff, 2, 0, 0, 0);
       uint32_t opcode = pins.opcode();
       patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    ++iter;
    {
       debug("  x2 |= 'ib  '\n");
       insn pins(iter, insn::movk, insn::st_immediate, ('ibot'>>16) & 0xffff, 2, 0, 0, 1);
       uint32_t opcode = pins.opcode();
       patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    ++iter;
    {
       debug("x3 = 0\n");
       insn pins(iter, insn::movz, insn::st_immediate, 0, 3, 0, 0, 0);
       uint32_t opcode = pins.opcode();
       patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
    ++iter;
    {
       debug("call load image\n");
       insn pins(iter, insn::bl, insn::st_immediate, loadimg_func, 0, 0, 0, 0);
       uint32_t opcode = pins.opcode();
       patches.push_back({(loc_t)pins.pc(), &opcode, 4});
    }
//    ++iter;
//    {
//       debug("jump exit\n");
//       insn pins(iter, insn::b, insn::st_immediate, cbzdst, 0, 0, 0, 0);
//       uint32_t opcode = pins.opcode();
//       patches.push_back({(loc_t)pins.pc(), &opcode, 4});
//    }
    return patches;
}
