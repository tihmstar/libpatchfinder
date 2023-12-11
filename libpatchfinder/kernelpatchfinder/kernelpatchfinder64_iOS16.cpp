//
//  kernelpatchfinder64_iOS16.cpp
//  libpatchfinder
//
//  Created by tihmstar on 08.06.22.
//

#include "kernelpatchfinder64_iOS16.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"
#include "sbops64.h"
#include <string.h>

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

#pragma mark Info finders
patchfinder64::offset_t kernelpatchfinder64_iOS16::find_kernel_el(){
    UNCACHELOC;
    
    vmem iter = _vmem->getIter(find_entry());
    assure(iter() == insn::b);
    iter = iter().imm();
    
    iter = iter.pc() + 0x10;
    
    if (iter() == insn::mrs && iter().special() == insn::currentel)
        RETCACHELOC(2);
    RETCACHELOC(1);
}

#pragma mark Offset finders
patchfinder64::offset_t kernelpatchfinder64_iOS16::find_struct_kqworkloop_offset_kqwl_owner(){
    UNCACHELOC;
    
    loc_t str = findstr("kq(%p) invalid refcount %d", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    while (--iter != insn::movz)
        ;
    
    loc_t bref = find_branch_ref(iter, -0x130);
    debug("bref=0x%016llx",bref);

    iter = bref;
    while (++iter != insn::bl)
        ;
    
    loc_t kqworkloop_dealloc = iter().imm();
    --iter;
    assure(iter() == insn::movz && iter().rd() == 1 && iter().imm() == 0);
    debug("kqworkloop_dealloc=0x%016llx",kqworkloop_dealloc);

    iter = kqworkloop_dealloc;
    while (++iter != insn::ldr)
        ;
    assert(iter().rn() == 0);
    RETCACHELOC(iter().imm());
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_struct_task_offset_thread_count(){
    UNCACHELOC;
    
    loc_t str = findstr("Panicked task %p: %d threads: ", true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    {
        int distance = 0;
        while (--iter != insn::stp)
            distance++;
        retassure(distance < 5, "we went too far!");
    }

    uint8_t countreg = iter().rt2();

    while (--iter != insn::ldr || iter().rt() != countreg)
        ;
    RETCACHELOC(iter().imm());
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_struct_thread_offset_thread_id(){
    UNCACHELOC;
    
    loc_t str = findstr("mach_exception_raise_identity_protected() must be code64 ", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    while (--iter != insn::bl)
        ;
    ++iter;
    
    loc_t bref = find_branch_ref(iter, -0x600);
    debug("bref=0x%016llx",bref);

    iter = bref;
    
    while (++iter != insn::ldr)
        ;
    
    RETCACHELOC(iter().imm());
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_struct__vm_map_offset_vmu1_lowest_unnestable_start(){
    UNCACHELOC;
    
    loc_t str = findstr("vm_map_clip_unnest(", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);

    vmem iter = _vmem->getIter(bof);

    while (++iter != insn::ldp)
        retassure(iter() != insn::bl, "sanity check failed");

    uint8_t tgtreg = iter().rt();
    
    loc_t lastLdrLoc = 0;
    
    while (++iter != insn::bl) {
        if (iter() == insn::ldr && iter().rn() == tgtreg) lastLdrLoc = iter;
    }
    debug("lastLdrLoc=0x%016llx",lastLdrLoc);
    iter = lastLdrLoc;
    RETCACHELOC(iter().imm());
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_ACT_CONTEXT(){
    UNCACHELOC;
    
    vmem iter = _vmem->getIter();
    
    while (true) {
        while (++iter != insn::mrs || iter().special() != insn::tpidr_el1 || iter().rt() != 0)
            ;
        if (++iter != insn::mrs || iter().special() != insn::sp_el0) continue;
        if (++iter != insn::add || iter().rd() != 0) continue;
        RETCACHELOC(iter().imm());
    }

    reterror("failed to find offset");
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_ACT_CPUDATAP(){
    UNCACHELOC;
    /*
     check_exception_stack:
     92 D0 38 D5    mrs    x18, TPIDR_EL1
                    cbz    x18, Lvalid_exception_stack
                    ldr    x18, [x18, ACT_CPUDATAP]
                    cbz    x18, .
     */
    
    loc_t tgt = memmem("\x92\xD0\x38\xD5", 4);
    debug("tgt=0x%016llx",tgt);
    
    vmem iter = _vmem->getIter(tgt);
    assure(++iter == insn::cbz);
    assure(++iter == insn::ldr);
    uint64_t retval = iter().imm();
    assure(++iter == insn::cbz && iter().imm() == iter.pc());

    RETCACHELOC(retval);
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_TH_KSTACKPTR(){
    UNCACHELOC;
    /*
                    ldr    x0, [x22, TH_KSTACKPTR]
                    mov    sp, x0
     BF 20 03 D5    sevl
     */
    
    loc_t tgt = memmem("\xBF\x20\x03\xD5", 4);
    debug("tgt=0x%016llx",tgt);
    
    vmem iter = _vmem->getIter(tgt);
    assure((--iter == insn::mov || (iter() == insn::add && iter().imm() == 0)) && iter().rn() == 0 && iter().rd() == 31);
    assure(--iter == insn::ldr && iter().rt() == 0);
    RETCACHELOC(iter().imm());
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_struct_thread_offset_map(){
    UNCACHELOC;
    
    loc_t str = findstr("swap_task_map ", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);

    vmem iter = _vmem->getIter(bof);
    
    uint16_t pachash = getPointerAuthStringDiscriminator("task.map");

    while (true) {
    continue_loop:
        while (++iter != insn::movk || iter().imm() != ((uint64_t)pachash<<48))
            ;
        loc_t hit = iter;
        debug("hit=0x%016llx",hit);
        vmem iter2 = iter;
        while (++iter2 != insn::str || iter2().rt() != iter().rd()){
            if (iter2() == insn::ret) goto continue_loop;
        }
        loc_t hot = iter2;
        debug("hot=0x%016llx",hot);
        
        if (iter2().subtype() != insn::st_immediate || iter2().imm() < 0x100)
            continue;
        
        RETCACHELOC(iter2().imm());
    }
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_elementsize_for_zone(const char *zonedesc){
    loc_t str = -1;
    while (true) {
        str = findstr(zonedesc, true, str+1);
        if (deref(str-1) & 0xff) continue;
        break;
    }
    debug("str=0x%016llx",str);
    str -= find_base();
    debug("needle=0x%016llx",str);
    
    loc_t ref = memmem(&str, 6);
    debug("ref=0x%016llx",ref);
        
    return deref(ref+8);
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_sizeof_struct_proc(){
    UNCACHELOC;
    
    loc_t str = findstr("io_telemetry_limit", true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl)
        ;
    while (++iter != insn::ldr)
        ;
    
    loc_t val = find_register_value(iter, iter().rn());
    val += iter().imm();
    
    uint64_t retval = deref(val);
    
    RETCACHELOC(retval);
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_sizeof_struct_task(){
    UNCACHELOC;
    
    loc_t str = findstr("io_telemetry_limit", true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl)
        ;
    
    while (++iter != insn::add || iter().subtype() != insn::st_immediate)
        ;
    
    RETCACHELOC(iter().imm());
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_sizeof_struct_thread(){
    UNCACHELOC;
    
    loc_t str = findstr("foreground process without thread", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);

    vmem iter = _vmem->getIter(bof);
    
    while (true) {
        while (++iter != insn::bl)
            ;
        uint64_t x1 = find_register_value(iter, 1);
        if (x1 != 3) continue;
        
        loc_t candidate = iter;
        debug("candidate=0x%016llx",candidate);
        break;
    }
    
    while (--iter != insn::sub || iter().rd() != 0)
        ;
    
    RETCACHELOC(iter().imm());
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_sizeof_struct_uthread(){
    UNCACHELOC;
    
    loc_t str = findstr("threads", true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);

    while (++iter != insn::bl)
        ;

    uint64_t retval = find_register_value(iter, 1);

    retval -= find_sizeof_struct_thread();
    
    RETCACHELOC(retval);
}

patchfinder64::offset_t kernelpatchfinder64_iOS16::find_sizeof_struct__vm_map(){
    UNCACHELOC;
    
    loc_t str = findstr("maps", true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);

    while (++iter != insn::bl)
        ;

    uint64_t retval = find_register_value(iter, 1);
    
    RETCACHELOC(retval);
}

#pragma mark Location finders
patchfinder64::loc_t kernelpatchfinder64_iOS16::find_boot_args_commandline_offset(){
    UNCACHELOC;
    
    std::string s = "-x";
    s.insert(s.begin(), 0);
    loc_t str = findstr(s, true);
    debug("str=0x%016llx",str);
    assure(str);
    
    loc_t ref = find_literal_ref(str+1);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    while (++iter != insn::bl)
        ;
    
    loc_t PE_parse_boot_argn = iter().imm();
    debug("PE_parse_boot_argn=0x%016llx",PE_parse_boot_argn);
    
    while (--iter != insn::add || iter().rd() != 0)
        ;
    offset_t bootargOffset = iter().imm();
    RETCACHELOC(bootargOffset);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_sbops(){
    UNCACHELOC;
    try {
        RETCACHELOC(kernelpatchfinder64_iOS15::find_sbops());
    } catch (...) {
        //
    }
    patchfinder64::loc_t str = findstr("Seatbelt sandbox policy", false);
    retassure(str, "Failed to find str");
    debug("str=0x%16llx",str);
    str -= _base;
    patchfinder64::loc_t ref = 0;
    retassure(ref = memmem(&str, 4), "Failed to find ref");
    debug("ref=0x%16llx",ref);

    loc_t retval = (patchfinder64::loc_t)deref(ref+0x18);
    RETCACHELOC(retval);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_cdevsw(){
    UNCACHELOC;
    loc_t str = findstr("perfmon: %s: cdevsw_add failed:", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    while (--iter != insn::bl)
        ;
    ++iter;
    
    loc_t bref = find_branch_ref(iter, -0x400);
    debug("bref=0x%016llx",bref);
    
    iter = bref;
    
    while (--iter != insn::bl)
        ;
    
    loc_t cdevsw_add = iter().imm();
    debug("cdevsw_add=0x%016llx",cdevsw_add);
    
    iter = cdevsw_add;
    
    while (++iter != insn::bl)
        ;
    
    while (true) {
        loc_t dst = 0;
        while (++iter != insn::adr && iter() != insn::adrp)
            ;
        dst = iter().imm();
        if (iter() == insn::adrp) {
            uint8_t rd = iter().rd();
            while (++iter != insn::add || (iter().rn() != rd))
                ;
            dst += iter().imm();
        }
        debug("candidate=0x%016llx",dst);
        if (deref(dst + 7*8) == 0 && deref(dst + 13*8) == 3) {
            RETCACHELOC(dst);
        }
    }
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_gPhysBase(){
    UNCACHELOC;
    loc_t str = findstr("illegal PA: ", false);
    while (deref(--str) & 0xff)
        ;
    str++;
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bref = 0;
    
    for (int i=0; i<0x20; i++) {
        try {
            if ((bref = find_branch_ref(ref-i*4, -0x200))) break;
        } catch (...) {
            //
        }
    }
    retassure(bref, "Failed to find bref");
    debug("bref=0x%016llx",bref);
    
    vmem iter = _vmem->getIter(bref);
    loc_t lastLdrOffset = 0;
    for (int i=0; i<0x10; i++) {
        insn isn = --iter;
        if (isn == insn::ldr){
            lastLdrOffset = isn.imm();
        }else if (isn == insn::adrp){
            loc_t dst = isn.imm() + lastLdrOffset;
            debug("candidate=0x%016llx",dst);
            if (deref(dst + 0x00) == 0 &&
                deref(dst + 0x08) == 0 &&
                deref(dst + 0x10) != 0 &&
                deref(dst + 0x18) != 0) {
                RETCACHELOC(dst);
            }
        }
    }
    reterror("Failed to find gPhysBase");
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_gVirtBase(){
    UNCACHELOC;
    loc_t str = findstr("illegal PA: ", false);
    while (deref(--str) & 0xff)
        ;
    str++;
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bref = 0;
    for (int i=0; i<0x20; i++) {
        try {
            if ((bref = find_branch_ref(ref-i*4, -0x200))) break;
        } catch (...) {
            //
        }
    }
    retassure(bref, "Failed to find bref");
    debug("bref=0x%016llx",bref);

    vmem iter = _vmem->getIter(bref);
    loc_t dst = 0;

    assure(++iter == insn::adrp);
    dst = iter().imm();

    assure(++iter == insn::ldr);
    dst += iter().imm();

    RETCACHELOC(dst);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_perfmon_devices(){
    UNCACHELOC;
    loc_t str = findstr("perfmon: no source for major device:", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bref = 0;
    for (int i=0; i<0x20; i++) {
        try {
            if ((bref = find_branch_ref(ref-i*4, -0x200))) break;
        } catch (...) {
            //
        }
    }
    retassure(bref, "Failed to find bref");
    debug("bref=0x%016llx",bref);

    vmem iter = _vmem->getIter(bref);
    loc_t dst = 0;

    while(++iter != insn::adrp)
        assure(iter() != insn::ret);
    dst = iter().imm();

    assure(++iter == insn::add);
    dst += iter().imm();

    RETCACHELOC(dst);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_ptov_table(){
    UNCACHELOC;
    loc_t str = findstr("illegal PA: ", false);
    while (deref(--str) & 0xff)
        ;
    str++;
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);

    vmem iter = _vmem->getIter(bof);
    while ((++iter).supertype() != insn::sut_branch_imm)
        ;
    
    loc_t dst = 0;
    while(++iter != insn::adrp)
        assure(iter() != insn::ret);
    dst = iter().imm();

    assure(++iter == insn::ldr);
    dst += iter().imm();

    RETCACHELOC(dst);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_vm_first_phys_ppnum(){
    UNCACHELOC;
    loc_t str = findstr("no remap page found", false);
    while (deref(--str) & 0xff)
        ;
    str++;
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    while (--iter != insn::adrp || iter().rd() != 8)
        ;
    
    loc_t bdst = iter;
    debug("bdst=0x%016llx",bdst);
    
    loc_t bref = find_branch_ref(bdst, -0x1000, 1);
    debug("bref=0x%016llx",bref);
    
    iter = bref;
    assure(iter().supertype() == insn::sut_branch_imm);
    
    while (++iter != insn::bcond)
        ;
    assure(iter().condition() == insn::EQ);
    loc_t t1 = iter;
    debug("t1=0x%016llx",t1);

    iter = iter().imm();
    
    while (++iter != insn::bcond)
        ;
    assure(iter().condition() == insn::HI);
    iter = iter().imm();
    
    loc_t target_block = iter;
    debug("target_block=0x%016llx",target_block);
    
    loc_t dst = 0;
    while(++iter != insn::adrp)
        assure(iter() != insn::ret);
    dst = iter().imm();

    assure(++iter == insn::ldr);
    dst += iter().imm();

    RETCACHELOC(dst);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_vm_pages(){
    UNCACHELOC;
    loc_t str = findstr("vm pages array", true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    while ((++iter).supertype() != insn::sut_branch_imm)
        ;
    
    loc_t block = find_register_value(iter, 4);
    debug("block=0x%016llx",block);
    
    loc_t bfunc = (deref(block +0x10) & 0xffffffff) + find_base();
    debug("bfunc=0x%016llx",bfunc);
    
    iter = bfunc;
    
    while ((++iter).supertype() != insn::sut_branch_imm || iter() == insn::bl)
        ;
    
    while (--iter != insn::ldr)
        ;
    uint64_t res = find_register_value(iter.pc()+4, iter().rt());
    
    RETCACHELOC(res);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_vm_page_array_beginning_addr(){
    UNCACHELOC;
    loc_t str = findstr("page_frame_init", true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl)
        ;
    
    loc_t dst = 0;
    while(++iter != insn::adrp)
        assure(iter() != insn::ret);
    dst = iter().imm();

    assure(++iter == insn::str);
    dst += iter().imm();

    RETCACHELOC(dst);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_vm_page_array_ending_addr(){
    UNCACHELOC;
    loc_t str = findstr("page_frame_init", true);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl)
        ;
    
    loc_t dst = 0;
    while(++iter != insn::adrp)
        assure(iter() != insn::ret);
    while(++iter != insn::adrp)
        assure(iter() != insn::ret);
    dst = iter().imm();

    assure(++iter == insn::str);
    dst += iter().imm();

    RETCACHELOC(dst);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_function_vn_kqfilter(){
    UNCACHELOC;
    
    loc_t open1 = find_bof_with_sting_ref("/Applications/Camera.app/", true);
    debug("open1=0x%016llx",open1);
    
    vmem iter = _vmem->getIter(open1);
    
    uint64_t pachash = getPointerAuthStringDiscriminator("fileglob.fg_ops");
    
    while (++iter != insn::movk || iter().imm() != pachash << 48)
        ;
    
    loc_t hit = iter;
    debug("hit=0x%016llx",hit);
    
    while (++iter != insn::pacda)
        ;
    
    loc_t vnops = find_register_value(iter, iter().rd());
    debug("vnops=0x%016llx",vnops);
    
    loc_t vn_kqfilter = deref(vnops + 6*8);
    vn_kqfilter = (vn_kqfilter & 0xffffffff) + find_base();
    debug("vn_kqfilter=0x%016llx",vn_kqfilter);

    RETCACHELOC(vn_kqfilter);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_cpu_ttep(){
    UNCACHELOC;
    vmem iter = _vmem->getIter();
    while (true) {
        while (++iter != insn::msr || iter().special() != insn::ttbr1_el1)
            ;
        uint8_t reg = iter().rt();
        if (--iter != insn::ldr || iter().rt() != reg){
            ++iter;
            continue;
        }
        
        RETCACHELOC(find_register_value(iter, reg, iter.pc()-0x20));
    }
    reterror("Failed to find loc");
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_exception_return(){
    UNCACHELOC;
    /*
     exception_return:
     DF 4F 03 D5    msr DAIFSet, #DAIFSC_ALL
     exception_return_unint:
     83 D0 38 D5    mrs x3, TPIDR_EL1
     */
    loc_t tgt = memmem("\xDF\x4F\x03\xD5\x83\xD0\x38\xD5", 8);
    debug("tgt=0x%016llx",tgt);
    assure(tgt);
    RETCACHELOC(tgt);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_exception_return_after_check(){
    UNCACHELOC;
    loc_t er = find_exception_return();
    vmem iter = _vmem->getIter(er);
    while (++iter != insn::mov || iter().rd() != 30)
        ;
    RETCACHELOC(iter);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_exception_return_after_check_no_restore(){
    UNCACHELOC;
    loc_t erac = find_exception_return_after_check();
    vmem iter = _vmem->getIter(erac);
    while (++iter != insn::msr)
        ;
    RETCACHELOC(iter);
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_gxf_ppl_enter(){
    UNCACHELOC;
    
    loc_t ppl_bootstrap_dispatch = find_ppl_bootstrap_dispatch();
    loc_t bref = find_branch_ref(ppl_bootstrap_dispatch, -0x400);
    debug("bref=0x%016llx",bref);
    
    RETCACHELOC(find_bof(bref));
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_kalloc_data_external(){
    UNCACHELOC;
    loc_t str = findstr("AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bref = find_block_branch_ref(ref, -0x100);
    debug("bref=0x%016llx",bref);

    vmem iter = _vmem->getIter(bref);
    while (--iter != insn::bl)
        ;
    RETCACHELOC(iter().imm());
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_kernel_pmap(){
    UNCACHELOC;
    loc_t str = findstr("kaddr not in kernel", false);
    while (deref(str) & 0xff) str--;
    str++;
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);

    uint64_t hash = getPointerAuthStringDiscriminator("_vm_map.pmap");
    hash<<=48;
    
    vmem iter = _vmem->getIter(bof);
    
    while (++iter != insn::movk || iter().imm() != hash)
        ;
    
    loc_t hit = iter;
    debug("hit=0x%016llx",hit);
    while (++iter != insn::autda)
        ;
    uint8_t reg = iter().rd();

    bool hasAdr = false;
    
    while (!hasAdr) {
        while (++iter != insn::cmp || (iter().rn() != reg && iter().rm() != reg))
            if (iter() == insn::adrp || iter() == insn::adr)
                hasAdr = true;
    }

    loc_t tgtcmp = iter;
    debug("tgtcmp=0x%016llx",tgtcmp);

    if (iter().rn() == reg) {
        RETCACHELOC(find_register_value(iter, iter().rm(), iter.pc()-0x20));
    }else{
        RETCACHELOC(find_register_value(iter, iter().rn(), iter.pc()-0x20));
    }
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_ml_sign_thread_state(){
    UNCACHELOC;
    /*
     E1 03 16 AA    mov x1, x22
     E2 03 17 2A    mov w2, w23
     E3 03 14 AA    mov x3, x20
     E4 03 10 AA    mov x4, x16
     E5 03 11 AA    mov x5, x17
     13 42 38 D5    mrs x19, SPSel
     BF 41 00 D5    msr SPSel, #1
        bl  _ml_sign_thread_state
        msr SPSel, x19
        mov lr, x20
        mov x1, x21
     */
    char needle[] = "\xE1\x03\x16\xAA\xE2\x03\x17\x2A\xE3\x03\x14\xAA\xE4\x03\x10\xAA\xE5\x03\x11\xAA\x13\x42\x38\xD5\xBF\x41\x00\xD5";
    loc_t tgt = memmem(needle,sizeof(needle)-1);
    debug("tgt=0x%016llx",tgt);
    assure(tgt);
    
    vmem iter = _vmem->getIter(tgt);
    while (++iter != insn::bl)
        ;
    RETCACHELOC(iter().imm());
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_pmap_create_options(){
    UNCACHELOC;
    
    loc_t ref = find_literal_ref(0xfeedfacefeedfad3);
    debug("ref=0x%016llx",ref);

    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl) {
        if (iter() == insn::b) iter = iter().imm()-4;
    }
    
    RETCACHELOC(iter().imm());
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_pmap_enter_options_addr(){
    UNCACHELOC;

    loc_t str = findstr("VM page %p should not have an error", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);
    
    vmem iter = _vmem->getIter(bof);
    
    while (++iter != insn::ret)
        ;
    
    loc_t ret = iter;
    debug("ret=0x%016llx",ret);
    
    while (true) {
        while (--iter != insn::bl)
            assure(iter > bof);

        loc_t retval = iter().imm();
        bool has_x5_0 = false;
        
        while (true) {
            insn isn = --iter;
            if (isn == insn::movz && isn.rd() == 5 && isn.imm() == 0){
                has_x5_0 = true;
                break;
            } else if (isn != insn::mov){
                ++iter;
                break;
            }
        }
        if (!has_x5_0) continue;
        RETCACHELOC(retval);
    }
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_stub_for_pplcall(uint8_t pplcall){
    loc_t gxf_ppl_enter = find_gxf_ppl_enter();
    vmem iter = _vmem->getIter();
    while (true) {
        iter = find_branch_ref(gxf_ppl_enter, 0, 0, iter.pc()+8);
        if (--iter == insn::movz && iter().imm() == pplcall)
            return iter;
    }
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_pmap_nest(){
    UNCACHELOC;

    loc_t func = find_stub_for_pplcall(0x11);
    debug("func=0x%016llx",func);
    
    loc_t ref = find_call_ref(func);
    debug("ref=0x%016llx",ref);

    RETCACHELOC(find_bof(ref));
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_pmap_remove_options(){
    UNCACHELOC;

    loc_t func = find_stub_for_pplcall(0x17);
    debug("func=0x%016llx",func);
    
    loc_t ref = find_call_ref(func);
    debug("ref=0x%016llx",ref);

    RETCACHELOC(find_bof(ref));
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_ppl_bootstrap_dispatch(){
    UNCACHELOC;
    /*
     LEXT(ppl_bootstrap_dispatch)
                    cmp    x15, PMAP_COUNT
                    b.hs   Lppl_fail_bootstrap_dispatch
                    adrp   x9, EXT(ppl_handler_table)@page
                    add    x9, x9, EXT(ppl_handler_table)@pageoff
                    add    x9, x9, x15, lsl #3
     2A 01 40 F9    ldr    x10, [x9]
     #ifdef HAS_APPLE_PAC
     49 09 3F D7    blraa        x10, x9
     #else
                    blr        x10
     #endif
     */
    loc_t tgt = -1;
    while (true) {
        tgt = memmem("\x2A\x01\x40\xF9\x49\x09\x3F\xD7", 8, tgt+1);
        debug("tgt=0x%016llx",tgt);
        assure(tgt);
        vmem iter = _vmem->getIter(tgt);
        for (int i=0; i<10; i++) {
            if (--iter == insn::cmp){
                assure(iter().rn() == 15);
                RETCACHELOC(iter);
            }
        }
    }
    reterror("Failed to find loc");
}

patchfinder64::loc_t kernelpatchfinder64_iOS16::find_ppl_handler_table(){
    UNCACHELOC;
    
    loc_t func = find_ppl_bootstrap_dispatch();
    loc_t retval = 0;
    vmem iter = _vmem->getIter(func);
    
    while (++iter != insn::adrp)
        if (iter() == insn::adr) RETCACHELOC(iter().imm());
    
    retval = iter().imm();
    if (++iter == insn::add) {
        retval += iter().imm();
    }
    
    RETCACHELOC(retval);
}

#pragma mark Patch finders
std::vector<patch> kernelpatchfinder64_iOS16::get_trustcache_true_patch(){
    UNCACHEPATCHES;

    vmem iter = _vmem->getIter();
    loc_t orr1pos = 0;
    while (!orr1pos) {
    retry_loop:
        while (++iter != insn::adrp && (iter() != insn::adr))
               ;
        vmem iter2 = iter;
        int foundBlrs = 0;
        for (int i=0; i<20; i++) {
            auto curinsn = ++iter2;
            if (curinsn == insn::blr || curinsn == insn::blraa) foundBlrs++;
            else if (curinsn == insn::orr){
                if (foundBlrs == 2 && curinsn.rd() == 0 && curinsn.imm() == 1) {
                    orr1pos = iter2;
                    for (int j=0; j<15; j++) {
                        if (++iter2 == insn::ret) goto found_func;
                    }
                    orr1pos = 0;
                    goto retry_loop;
                found_func:;
                    break;
                }
            }
        }
    }
    debug("orr1pos=0x%016llx",orr1pos);
    ++iter;
    loc_t bof = find_bof(orr1pos);
    debug("bof=0x%016llx",bof);

    pushINSN(insn::new_immediate_movz(bof, 1, 0, 0));
    pushINSN(insn::new_general_ret(bof+4));

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_codesignature_patches(){
    UNCACHEPATCHES;

    //add disabling launch constraints
    loc_t str = findstr("amfi_enforce_launch_constraints", true);
    debug("str=0x%16llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%16llx",ref);
    
    vmem iter = _vmem->getIter(ref);
    
    while (++iter != insn::bl)
        ;
    ++iter;
    retassure(iter() == insn::mov && iter().rm() == 0, "unexpected insn");
    uint8_t rd = iter().rd();
    
    while (++iter != insn::cbz || iter().rt() != rd) {
        retassure(iter() != insn::ret, "unexpected end of function");
    }
    loc_t badloc = iter().imm();
    debug("badloc=0x%16llx",badloc);

    loc_t goodloc = badloc-4;
    iter = goodloc;
    retassure(iter() == insn::str, "unexpected insn, expected str");
    
    uint8_t srcreg = iter().rn();
    
    loc_t is_launch_constraints_enforced = find_register_value(goodloc, srcreg, goodloc-0x10);
    is_launch_constraints_enforced += iter().imm();
    debug("is_launch_constraints_enforced=0x%16llx",is_launch_constraints_enforced);
    {
        uint32_t zero = 0;
        patches.push_back({is_launch_constraints_enforced,&zero,sizeof(zero)});
    }
    
    {
        //Hello iOS 16.4!
        loc_t query_trust_cache = find_sym("_query_trust_cache");
        if (!query_trust_cache) {
            warning("Failed to get query_trust_cache symbol, ignoring...");
        }else{
            debug("query_trust_cache=0x%016llx",query_trust_cache);
            loc_t stub_ptr = memmem(&query_trust_cache, sizeof(query_trust_cache));
            debug("stub_ptr=0x%016llx",stub_ptr);
            
            loc_t stub_query_trust_cache = find_literal_ref(stub_ptr);
            assure(stub_query_trust_cache);
            stub_query_trust_cache -=4;
            debug("stub_query_trust_cache=0x%016llx",stub_query_trust_cache);
            
            try {
                loc_t trustcache_check_call = find_call_ref(stub_query_trust_cache,1);
                debug("trustcache_check_call=0x%016llx",trustcache_check_call);
                
                loc_t trustcache_check = find_bof(trustcache_check_call);
                debug("trustcache_check=0x%016llx",trustcache_check);
                pushINSN(insn::new_immediate_movz(trustcache_check+4*0, 1, 0, 0));
                pushINSN(insn::new_immediate_cbz(trustcache_check+4*1, trustcache_check+4*3, 2));
                pushINSN(insn::new_immediate_str_unsigned(trustcache_check+4*2, 0, 2, 0));
                pushINSN(insn::new_general_ret(trustcache_check+4*3));
            } catch (...) {
                warning("Failed to get iOS 16.4 trustcache_check patch, ignoring...");
            }
        }
    }
    
    //add usual patches
    addPatches(get_trustcache_true_patch());
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_force_boot_ramdisk_patch(){
    UNCACHEPATCHES;

    {
        //no rootfs auth patch
        loc_t str = findstr("rootvp not authenticated after mounting", false);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);

        vmem iter = _vmem->getIter(ref);
        
        while (--iter != insn::cbnz)
            ;
        
        loc_t btgt = iter+1;
        debug("btgt=0x%16llx",btgt);
        
        for (int i=0; i<10; i++) {
            while (--iter != insn::bl)
                ;
            loc_t x1val = find_register_value(iter, 1,iter.pc()-0x20);
            if (!x1val) continue;
            try {
                if (strcmp((const char*)_vmem->memoryForLoc(x1val), "rd") == 0) goto found_patch;
            } catch (...) {
                //
            }
        }
        reterror("Failed to find function");
    found_patch:
        pushINSN(insn::new_immediate_b(iter, btgt));
    }
    
    {
        //IOFindBSDRoot patch
        loc_t str = findstr("!BSD\n", true);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);
        
        vmem iter = _vmem->getIter(ref);


        while (true) {
            while (++iter != insn::bl)
                ;
            loc_t x1val = find_register_value(iter, 1,iter.pc()-0x20);
            if (!x1val) continue;
            try {
                if (strcmp((const char*)_vmem->memoryForLoc(x1val), "rd") != 0) continue;
            } catch (...) {
                continue;
            }
            
            ++iter;
            retassure(iter() == insn::cbnz, "unexpected insn");
            loc_t bdst = iter().imm();
            loc_t shellcodeEnd = iter;
            debug("shellcodeEnd=0x%16llx",shellcodeEnd);
            while (--iter != insn::mov || iter().rd() != 2)
                ;
            ++iter;
            loc_t shellcodeBegin = iter;
            debug("shellcodeBegin=0x%16llx",shellcodeBegin);
            retassure((shellcodeEnd-shellcodeBegin)/4 >= 3, "not enough room for shellcode");
            pushINSN(insn::new_immediate_movz(shellcodeBegin+0x00, 0x646d, 0, 0));
            pushINSN(insn::new_immediate_movk(shellcodeBegin+0x04, 0x30, 0, 16));
            pushINSN(insn::new_immediate_str_unsigned(shellcodeBegin+0x08, 0, 2, 0));
            pushINSN(insn::new_immediate_b(shellcodeBegin+0x0c, bdst));
            break;
        }
    }
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_read_bpr_patch_with_params(int syscall, loc_t bpr_reg_addr, loc_t ml_io_map, loc_t kernel_map, loc_t kmem_free){
    UNCACHEPATCHES;

    loc_t bss_space = find_bss_space(16,false);
    if (bss_space & 7) {
        bss_space +=8;
        bss_space &= ~7;
    }
    debug("bss_space=0x%016llx",bss_space);

    loc_t table = find_table_entry_for_syscall(syscall);
    debug("table=0x%016llx",table);

    uint32_t shellcode_insn_cnt = 25; //commitment
    loc_t shellcode = 0;
    try {
        shellcode = findnops(shellcode_insn_cnt);
    } catch (...) {
        shellcode = findnops(shellcode_insn_cnt, true, 0x00000000);
    }
    debug("shellcode=0x%016llx",shellcode);
    
    uint32_t afterMapInsn = 12; //commitment
    uint32_t addrpos = 23; //commitment
    uint32_t ml_map_io_stubInsn = 22; //commitment

#define cPC (shellcode+(insnNum++)*4)
    int insnNum = 0;
    
    pushINSN(insn::new_immediate_sub(cPC, 0x10, 31, 31));
    pushINSN(insn::new_general_stp_offset(cPC, 0x00, 29, 30, 31));
    try {
        pushINSN(insn::new_general_adr(cPC, bss_space, 0));
        pushINSN(insn::new_register_mov(cPC, 0, 29, 0));
    } catch (...) {
        --insnNum;//was incremented before without using the instruction space by adr
        pushINSN(insn::new_general_adrp(cPC, (bss_space & ~0xfff), 0));
        pushINSN(insn::new_immediate_add(cPC, bss_space & 0xfff, 0, 29));
    }
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0, 29, 0));
    pushINSN(insn::new_immediate_cmp(cPC, 0, 0));
    pushINSN(insn::new_immediate_bcond(cPC, shellcode+afterMapInsn*4, insn::cond::NE));
    
    pushINSN(insn::new_literal_ldr(cPC, shellcode+addrpos*4, 0));
    pushINSN(insn::new_immediate_movz(cPC, 0x4000, 1, 0));
    {
        uint32_t opcode = 0x9272C400; //and x0, x0, #0xffffffffffffc000
        patches.push_back({cPC, &opcode,sizeof(opcode)});
    }
    pushINSN(insn::new_immediate_bl(cPC, shellcode+ml_map_io_stubInsn*4));
    pushINSN(insn::new_immediate_str_unsigned(cPC, 0, 29, 0));
    assure(insnNum == afterMapInsn);
    pushINSN(insn::new_literal_ldr(cPC, shellcode+addrpos*4, 1));
    {
        uint32_t opcode = 0x92403421; //x1, x1, #0x3fff
        patches.push_back({cPC, &opcode,sizeof(opcode)});
    }
    pushINSN(insn::new_register_add(cPC, 0, 1, 0, 1));
    pushINSN(insn::new_immediate_ldr_unsigned(cPC, 0, 1, 29, true));
    pushINSN(insn::new_immediate_movz(cPC, 0x4141, 0, 16));
    {
        uint32_t opcode = 0x92403FBD; //and fp, fp, #0xffff
        patches.push_back({cPC, &opcode,sizeof(opcode)});
    }
    pushINSN(insn::new_register_add(cPC, 0, 0, 29, 0));
    pushINSN(insn::new_general_ldp_offset(cPC, 0, 29, 30, 31));
    pushINSN(insn::new_immediate_add(cPC, 0x10, 31, 31));
    pushINSN(insn::new_general_ret(cPC));
    assure(insnNum == ml_map_io_stubInsn);
    pushINSN(insn::new_immediate_b(cPC, ml_io_map));
    assure(insnNum == addrpos);
    patches.push_back({cPC,&bpr_reg_addr,sizeof(bpr_reg_addr)}); cPC;
    assure(insnNum == shellcode_insn_cnt);
#undef cPC
    
    //hello linkerinfo in pointers
    uint64_t funcptr = deref(table) & 0xffffffff00000000;
    funcptr |= (shellcode & 0xffffffff);
    patches.push_back({table,&funcptr,sizeof(funcptr)});
    
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_mount_patch(){
    UNCACHEPATCHES;
    addPatches(kernelpatchfinder64_iOS15::get_mount_patch());
    
    loc_t str = findstr("Updating mount to read/write mode is not allowed", false);
    if (str) {
        debug("Found 'Updating mount to read/write mode is not allowed' str, adding additional apfs update rw patch");
        while (deref(str) & 0xff) str--;
        str++;
        debug("str=0x%016llx",str);
        
        loc_t ref = find_literal_ref(str);
        debug("ref=0x%016llx",ref);

        vmem iter = _vmem->getIter(ref);
        
        while (--iter != insn::ldr){
            auto isn = iter();
            if (isn.supertype() == insn::sut_branch_imm && isn != insn::bl){
                /*
                 If we reached a non-conditional jump (which isn't bl),
                 then the code below can only be reached by jumping there
                 */
                ++iter;
                break;
            }
        }
        
        loc_t jmpsrc = find_branch_ref(iter, -0x500);
        debug("jmpsrc=0x%016llx",jmpsrc);

        pushINSN(insn::new_general_nop(jmpsrc));
    }
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_apfs_skip_authenticate_root_hash_patch(){
    UNCACHEPATCHES;
    
    loc_t str = findstr("\"could not authenticate personalized root hash!", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t bof = find_bof(ref);
    debug("bof=0x%016llx",bof);
    
    pushINSN(insn::new_immediate_movz(bof, 0, 0, 0));
    pushINSN(insn::new_general_ret(bof+4));

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_sandbox_patch(){
    UNCACHEPATCHES;
    try {
        return kernelpatchfinder64_iOS15::get_sandbox_patch();
    } catch (...) {
        //
    }

    patchfinder64::loc_t sbops = find_sbops();
    //pointer now contain linker information :o
    sbops = (sbops & 0xFFFFFFFF) + _base;
    
    debug("sbobs=0x%016llx",sbops);
    
    vmem iter = _vmem->getIter();
        
    do{
        ++iter;
        while (++iter != insn::ret);
    }while (--iter != insn::movz || iter().rd() != 0 || iter().imm() != 0);
        
    patchfinder64::loc_t ret0gadget = iter;
    debug("ret0gadget=0x%016llx",ret0gadget);
        
#define PATCH_OP(loc) \
    if (uint64_t origval = deref(loc)) { \
        patchfinder64::loc_t tmp = ((ret0gadget-_base) & 0xFFFFFFFF) | (origval & 0xFFFFFFFF00000000); \
        patches.push_back({loc,&tmp,sizeof(tmp)}); \
    }
    
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_mount_check_mount));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_mount_check_remount));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_mount_check_umount));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_write));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_rename));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_fsgetpath));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_getattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_proc_check_get_cs_info));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_proc_check_set_cs_info));
    
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_file_check_mmap));

    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_access));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_chdir));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_chroot));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_create));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_deleteextattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_exchangedata));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_exec));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_getattrlist));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_getextattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_ioctl));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_kqfilter));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_label_update));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_link));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_listextattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_lookup));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_open));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_read));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_readdir));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_readlink));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_rename_from));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_rename_to));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_revoke));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_select));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setattrlist));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setextattr));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setflags));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setmode));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setowner));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_setutimes));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_stat));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_truncate));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_unlink));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_vnode_check_write));

    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_mount_check_stat));

    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_create));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_open));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_post));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_unlink));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_check_wait));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_label_associate));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_label_destroy));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixsem_label_init));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_create));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_mmap));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_open));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_stat));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_truncate));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_check_unlink));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_label_associate));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_label_destroy));
    PATCH_OP(sbops+offsetof(struct mac_policy_ops,mpo_posixshm_label_init));
#undef PATCH_OP

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS16::get_task_conversion_eval_patch(){
    UNCACHEPATCHES;
    
    loc_t str = findstr("Just like pineapple on pizza, this task/thread port doesn't belong here.", false);
    debug("str=0x%016llx",str);
    
    loc_t ref = find_literal_ref(str);
    debug("ref=0x%016llx",ref);
    
    loc_t task_conversion_eval_internal = find_bof(ref);
    debug("task_conversion_eval_internal=0x%016llx",task_conversion_eval_internal);

    loc_t ktask = find_kerneltask();
    debug("ktask=0x%016llx",ktask);
    
    loc_t tref = find_literal_ref(ktask,0,task_conversion_eval_internal);
    debug("tref=0x%016llx",tref);

    vmem iter = _vmem->getIter(tref);
    
    uint8_t ktask_reg = iter().rt();
    
    for (int i=0; i<10; i++) {
        auto isn = ++iter;
        
        if (isn == insn::cmp) {
            uint8_t reg1 = isn.rm();
            uint8_t reg2 = isn.rn();
            
            uint8_t greg = reg1 + reg2;
            
            if (greg == ktask_reg || greg == 1){
                /*
                    check if we are comparing "ktask_reg with X0" or "X1 with X0"
                    check if next branch goes to epilogue
                    then replace with "cmp x0, x0"
                 */
                vmem iter2(iter);
                if (++iter2 != insn::bcond) continue;
                iter2 = iter2().imm();
                if (iter2() != insn::mov || iter2().rd() != 0) continue;
                
                pushINSN(insn::new_register_cmp(iter, 0, 0, 0, -1));
                goto gotpatches;
            }
        }
    }
    reterror("failed to find patch");
gotpatches:;
    retassure(patches.size(), "Failed to find a patch");
    RETCACHEPATCHES;
}
