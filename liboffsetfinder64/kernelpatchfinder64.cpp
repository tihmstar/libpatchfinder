//
//  kernelpatchfinder64.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "kernelpatchfinder64.hpp"
#include "all_liboffsetfinder.hpp"


using namespace std;
using namespace tihmstar;
using namespace offsetfinder64;


kernelpatchfinder64::kernelpatchfinder64(const char *filename)
    : machopatchfinder64(filename)
{
    //
}

kernelpatchfinder64::kernelpatchfinder64(const void *buffer, size_t bufSize)
    : machopatchfinder64(buffer,bufSize)
{
    //
}


loc_t kernelpatchfinder64::find_syscall0(){
    constexpr char sig_syscall_3[] = "\x06\x00\x00\x00\x03\x00\x0c\x00";
    loc_t sys3 = _vmem->memmem(sig_syscall_3, sizeof(sig_syscall_3)-1);
    return sys3 - (3 * 0x18) + 0x8;
}

loc_t kernelpatchfinder64::find_function_for_syscall(int syscall){
    loc_t syscallTable = find_syscall0();
    loc_t tableEntry = (syscallTable + 3*(syscall-1)*sizeof(uint64_t));
    return _vmem->deref(tableEntry);
}


loc_t kernelpatchfinder64::find_kerneltask(){
    loc_t strloc = findstr("current_task() == kernel_task", true);
    debug("strloc=%p\n",strloc);
    
    loc_t strref = find_literal_ref(strloc);
    debug("strref=%p\n",strref);

    loc_t bof = find_bof(strref);
    debug("bof=%p\n",bof);
    
    vmem iter(*_vmem,bof);

    loc_t kernel_task = 0;
    
    do{
        if (++iter == insn::mrs) {
            if (iter().special() == insn::systemreg::tpidr_el1) {
                uint8_t xreg = iter().rt();
                uint8_t kernelreg = (uint8_t)-1;
                
                vmem iter2(iter,(loc_t)iter);
                
                for (int i=0; i<5; i++) {
                    switch ((++iter2).type()) {
                        case insn::adrp:
                            kernel_task = iter2().imm();
                            kernelreg = iter2().rd();
                            break;
                        case insn::ldr:
                            if (kernelreg == iter2().rt()) {
                                kernel_task += iter2().imm();
                            }
                            break;
                        case insn::cmp:
                            if ((kernelreg == iter2().rm() && xreg == iter2().rn())
                                || (xreg == iter2().rm() && kernelreg == iter2().rn())) {
                                return kernel_task;
                            }
                            break;
                        default:
                            break;
                    }
                }
                kernel_task = 0;
            }
        }
    }while (iter < strref);
    reterror("failed to find kernel_task");
}


std::vector<patch> kernelpatchfinder64::get_MarijuanARM_patch(){
    std::vector<patch> patches;
    constexpr char release_arm[] = "RELEASE_ARM";
    constexpr char marijuanarm[] = "MarijuanARM";

    loc_t strloc = -1;
    while ((strloc = _vmem->memmem(release_arm, sizeof(release_arm)-1, strloc+1))) {
        patches.push_back({strloc,marijuanarm,sizeof(marijuanarm)-1});
    }

    //everything is fine as long as we found at least one instance
    /*
     Note: this check is redundant, since the first time strloc is 0 so the whole space is searched
        and an error is thrown if no occurence is found, but it feels bad to just assume that so there is another check here.
     */
    retassure(patches.size(), "Not a single instance of %s was found",release_arm);
    
    return patches;
}

std::vector<patch> kernelpatchfinder64::get_task_conversion_eval_patch(){
    std::vector<patch> patches;

    /*
     if (caller == kernel_task) {
         return KERN_SUCCESS;
     }

     if (caller == victim) {
         return KERN_SUCCESS;
     }
     */
    
    /* -> This inlines to -> */
    
    /*
     mrs        x8, tpidr_el1
     ldr        x8, [x8, #0x368]
     ldr        x21, [x21, #0x68]
     adrp       x9, #0xfffffff008895000 ; 0xfffffff008895200@PAGE
     ldr        x9, [x9, #0x200] ; 0xfffffff008895200@PAGEOFF, kernel_task
     cmp        x8, x21
     ccmp       x9, x8, #0x4
     b.ne       loc_fffffff0075f1c54
     */
    
    /*
     patch:
     ccmp       x9, x8, #0x4
     to:
     ccmp       x8, x8, #0x4
     */
    
    loc_t kernel_task = find_kerneltask();
    debug("kernel_task=%p\n",kernel_task);

    vmem iter(*_vmem);
    
    while (true) {
        try {
            ++iter;
        } catch (out_of_range &e) {
            break;
        }
        
        if (iter() == insn::mrs && iter().special() == insn::systemreg::tpidr_el1) {
            vmem iter2(iter,(loc_t)iter);
            uint8_t regtpidr = iter().rt();
            uint8_t regkernel_task = (uint8_t)-1;
            loc_t kernel_task_val = 0;
                        
            for (int i=0; i<10; i++) {
                switch ((++iter2).type()) {
                    case insn::ldr:
                        if (iter2().rt() == regkernel_task) {
                            kernel_task_val += iter2().imm();
                        }
                        break;
                    case insn::adrp:
                        kernel_task_val = iter2().imm();
                        regkernel_task = iter2().rd();
                        break;
                    case insn::ccmp:
                        if (iter2().special() == 0x4 &&
                                ((regkernel_task == iter2().rm() && regtpidr == iter2().rn())
                                 || (regtpidr == iter2().rm() && regkernel_task == iter2().rn()))
                            ) {
                            
                            loc_t ccmpPos = iter2;
                            debug("%s: patchloc=%p\n",__FUNCTION__,(void*)ccmpPos);
                            insn pins = insn::new_register_ccmp(iter2, iter2().condition(), iter2().special(), iter2().rn(), iter2().rn());
                            uint32_t opcode = pins.opcode();
                            patches.push_back({(loc_t)pins.pc(), &opcode, 4});
                            goto loop_continue;
                        }
                    default:
                        break;
                }
            }
        }
    loop_continue:
        continue;
    }
    
    return patches;
}

std::vector<patch> kernelpatchfinder64::get_disable_codesigning_patch(){
    std::vector<patch> patches;
    
    reterror("todo implement");
    return patches;
}


//#pragma mark patchfinder64
//
//namespace tihmstar{
//    namespace patchfinder64{
//
//        loc_t jump_stub_call_ptr_loc(insn bl_insn){
//            assure(bl_insn == insn::bl);
//            insn fdst(bl_insn,(loc_t)bl_insn.imm());
//            insn ldr((fdst+1));
//            if (!((fdst == insn::adrp && ldr == insn::ldr && (fdst+2) == insn::br))) {
//                retcustomerror("branch destination not jump_stub_call", bad_branch_destination);
//            }
//            return (loc_t)fdst.imm() + ldr.imm();
//        }
//
//        bool is_call_to_jump_stub(insn bl_insn){
//            try {
//                jump_stub_call_ptr_loc(bl_insn);
//                return true;
//            } catch (tihmstar::bad_branch_destination &e) {
//                return false;
//            }
//        }
//
//    }
//}
//
//#pragma mark common patchs
//constexpr char patch_nop[] = "\x1F\x20\x03\xD5";
//constexpr size_t patch_nop_size = sizeof(patch_nop)-1;
//
//
//#pragma mark v0rtex
//loc_t patchfinder64::find_zone_map(){
//    loc_t str = findstr("zone_init",true);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn ptr(_segments,ref);
//
//    loc_t ret = 0;
//
//    while (++ptr != insn::adrp);
//    ret = (loc_t)ptr.imm();
//
//    while (++ptr != insn::add);
//    ret += ptr.imm();
//
//    return ret;
//}
//
//loc_t patchfinder64::find_kernel_map(){
//    return find_sym("_kernel_map");
//}
//
//loc_t patchfinder64::find_kernel_task(){
//    return find_sym("_kernel_task");
//}
//
//loc_t patchfinder64::find_realhost(){
//    loc_t sym = find_sym("_KUNCExecute");
//
//    insn ptr(_segments,sym);
//
//    loc_t ret = 0;
//
//    while (++ptr != insn::adrp);
//    ret = (loc_t)ptr.imm();
//
//    while (++ptr != insn::add);
//    ret += ptr.imm();
//
//    return ret;
//}
//
//loc_t patchfinder64::find_bzero(){
//    return find_sym("___bzero");
//}
//
//loc_t patchfinder64::find_bcopy(){
//    return find_sym("_bcopy");
//}
//
//loc_t patchfinder64::find_copyout(){
//    return find_sym("_copyout");
//}
//
//loc_t patchfinder64::find_copyin(){
//    return find_sym("_copyin");
//}
//
//loc_t patchfinder64::find_ipc_port_alloc_special(){
//    loc_t sym = find_sym("_KUNCGetNotificationID");
//    insn ptr(_segments,sym);
//
//    while (++ptr != insn::bl);
//    while (++ptr != insn::bl);
//
//    return (loc_t)ptr.imm();
//}
//
//loc_t patchfinder64::find_ipc_kobject_set(){
//    loc_t sym = find_sym("_KUNCGetNotificationID");
//    insn ptr(_segments,sym);
//
//    while (++ptr != insn::bl);
//    while (++ptr != insn::bl);
//    while (++ptr != insn::bl);
//
//    return (loc_t)ptr.imm();
//}
//
//loc_t patchfinder64::find_ipc_port_make_send(){
//    loc_t sym = find_sym("_convert_task_to_port");
//    insn ptr(_segments,sym);
//    while (++ptr != insn::bl);
//    while (++ptr != insn::bl);
//
//    return (loc_t)ptr.imm();
//}
//
//loc_t patchfinder64::find_chgproccnt(){
//    loc_t str = findstr("\"chgproccnt: lost user\"",true);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn functop(_segments,ref);
//
//    while (--functop != insn::stp);
//    while (--functop == insn::stp);
//    ++functop;
//
//    return (loc_t)functop.pc();
//}
//
//loc_t patchfinder64::find_kauth_cred_ref(){
//    return find_sym("_kauth_cred_ref");
//}
//
//loc_t patchfinder64::find_osserializer_serialize(){
//    return find_sym("__ZNK12OSSerializer9serializeEP11OSSerialize");
//}
//
//uint32_t patchfinder64::find_vtab_get_external_trap_for_index(){
//    loc_t sym = find_sym("__ZTV12IOUserClient");
//    sym += 2*sizeof(uint64_t);
//
//    loc_t nn = find_sym("__ZN12IOUserClient23getExternalTrapForIndexEj");
//
//    insn data(_segments,sym,insn::kText_and_Data);
//    --data;
//    for (int i=0; i<0x200; i++) {
//        if ((++data).doublevalue() == (uint64_t)nn)
//            return i;
//        ++data;
//    }
//    return 0;
//}
//
//uint32_t patchfinder64::find_vtab_get_retain_count(){
//    loc_t sym = find_sym("__ZTV12IOUserClient");
//    sym += 2*sizeof(uint64_t);
//
//    loc_t nn = find_sym("__ZNK8OSObject14getRetainCountEv");
//
//    insn data(_segments,sym,insn::kText_and_Data);
//    --data;
//    for (int i=0; i<0x200; i++) {
//        if ((++data).doublevalue() == (uint64_t)nn)
//            return i;
//        ++data;
//    }
//    return 0;
//}
//
//uint32_t patchfinder64::find_proc_ucred(){
//    loc_t sym = find_sym("_proc_ucred");
//    return (uint32_t)insn(_segments,sym).imm();
//}
//
//uint32_t patchfinder64::find_task_bsd_info(){
//    loc_t sym = find_sym("_get_bsdtask_info");
//    return (uint32_t)insn(_segments,sym).imm();
//}
//
//uint32_t patchfinder64::find_vm_map_hdr(){
//    loc_t sym = find_sym("_vm_map_create");
//
//    insn stp(_segments, sym);
//
//    while (++stp != insn::bl);
//
//    while (++stp != insn::cbz && stp != insn::cbnz);
//
//    while (++stp != insn::stp || stp.rt() != stp.other());
//
//    return (uint32_t)stp.imm();
//}
//
//typedef struct mig_subsystem_struct {
//    uint32_t min;
//    uint32_t max;
//    char *names;
//} mig_subsys;
//
//mig_subsys task_subsys ={ 0xd48, 0xd7a , NULL};
//uint32_t patchfinder64::find_task_itk_self(){
//    loc_t task_subsystem=memmem(&task_subsys, 4);
//    assure(task_subsystem);
//    task_subsystem += 4*sizeof(uint64_t); //index0 now
//
//    insn mach_ports_register(_segments, (loc_t)insn::deref(_segments, task_subsystem+3*5*8));
//
//    while (++mach_ports_register != insn::bl || mach_ports_register.imm() != (uint64_t)find_sym("_lck_mtx_lock"));
//
//    insn ldr(mach_ports_register);
//
//    while (++ldr != insn::ldr || (ldr+1) != insn::cbz);
//
//    return (uint32_t)ldr.imm();
//}
//
//uint32_t patchfinder64::find_task_itk_registered(){
//    loc_t task_subsystem=memmem(&task_subsys, 4);
//    assure(task_subsystem);
//    task_subsystem += 4*sizeof(uint64_t); //index0 now
//
//    insn mach_ports_register(_segments, (loc_t)insn::deref(_segments, task_subsystem+3*5*8));
//
//    while (++mach_ports_register != insn::bl || mach_ports_register.imm() != (uint64_t)find_sym("_lck_mtx_lock"));
//
//    insn ldr(mach_ports_register);
//
//    while (++ldr != insn::ldr || (ldr+1) != insn::cbz);
//    while (++ldr != insn::ldr);
//
//    return (uint32_t)ldr.imm();
//}
//
//
////IOUSERCLIENT_IPC
//mig_subsys host_priv_subsys = { 400, 426 } ;
//uint32_t patchfinder64::find_iouserclient_ipc(){
//    loc_t host_priv_subsystem=memmem(&host_priv_subsys, 8);
//    assure(host_priv_subsystem);
//
//    insn memiterator(_segments,host_priv_subsystem,insn::kData_only);
//    loc_t thetable = 0;
//    while (1){
//        --memiterator;--memiterator; //dec 8 byte
//        struct _anon{
//            uint64_t ptr;
//            uint64_t z0;
//            uint64_t z1;
//            uint64_t z2;
//        } *obj = (struct _anon*)(void*)memiterator;
//
//        if (!obj->z0 && !obj->z1 &&
//            !memcmp(&obj[0], &obj[1], sizeof(struct _anon)) &&
//            !memcmp(&obj[0], &obj[2], sizeof(struct _anon)) &&
//            !memcmp(&obj[0], &obj[3], sizeof(struct _anon)) &&
//            !memcmp(&obj[0], &obj[4], sizeof(struct _anon)) &&
//            !obj[-1].ptr && obj[-1].z0 == 1 && !obj[-1].z1) {
//            thetable = (loc_t)memiterator.pc();
//            break;
//        }
//    }
//
//    loc_t iokit_user_client_trap_func = (loc_t)insn::deref(_segments, thetable + 100*4*8 - 8);
//
//    insn bl_to_iokit_add_connect_reference(_segments,iokit_user_client_trap_func);
//    while (++bl_to_iokit_add_connect_reference != insn::bl);
//
//    insn iokit_add_connect_reference(bl_to_iokit_add_connect_reference,(loc_t)bl_to_iokit_add_connect_reference.imm());
//
//    while (++iokit_add_connect_reference != insn::add || iokit_add_connect_reference.rd() != 8 || ++iokit_add_connect_reference != insn::ldxr || iokit_add_connect_reference.rn() != 8);
//
//    return (uint32_t)((--iokit_add_connect_reference).imm());
//}
//
//uint32_t patchfinder64::find_ipc_space_is_task_11(){
//    loc_t str = findstr("\"ipc_task_init\"",true);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str,1);
//    retassure(ref, "literal ref to str");
//
//    insn istr(_segments,ref);
//
//    while (--istr != insn::str);
//
//    return (uint32_t)istr.imm();
//}
//
//uint32_t patchfinder64::find_ipc_space_is_task(){
//    loc_t str = findstr("\"ipc_task_init\"",true);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    loc_t bref = 0;
//    bool do_backup_plan = false;
//
//    try {
//        bref = find_rel_branch_source(insn(_segments,ref), true, 2, 0x2000);
//
//    } catch (tihmstar::limit_reached &e) {
//        try {
//            //previous attempt doesn't work on some 10.0.2 devices, trying something else...
//            do_backup_plan = bref = find_rel_branch_source(insn(_segments,ref), true, 1, 0x2000);
//        } catch (tihmstar::limit_reached &ee) {
//            try {
//                //this seems to be good for iOS 9.3.3
//                do_backup_plan = bref = find_rel_branch_source(insn(_segments,ref-4), true, 1, 0x2000);
//            } catch (tihmstar::limit_reached &eee) {
//                //this is for iOS 11(.2.6)
//                return find_ipc_space_is_task_11();
//            }
//        }
//    }
//
//    insn istr(_segments,bref);
//
//    if (!do_backup_plan) {
//        while (++istr != insn::str);
//    }else{
//        while (--istr != insn::str);
//    }
//
//    return (uint32_t)istr.imm();
//}
//
//uint32_t patchfinder64::find_sizeof_task(){
//    loc_t str = findstr("\0tasks",true)+1;
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn thebl(_segments, ref);
//
//    loc_t zinit = 0;
//    try {
//        zinit = find_sym("_zinit");
//    } catch (tihmstar::symbol_not_found &e) {
//        loc_t str = findstr("zlog%d",true);
//        retassure(str, "Failed to find str2");
//
//        loc_t ref = find_literal_ref(_segments, str);
//        retassure(ref, "literal ref to str2");
//
//        insn functop(_segments,ref);
//        while (--functop != insn::stp || (functop+1) != insn::stp || (functop+2) != insn::stp || (functop-1) != insn::ret);
//        zinit = (loc_t)functop.pc();
//    }
//
//    while (++thebl != insn::bl || (loc_t)thebl.imm() != zinit);
//
//    --thebl;
//
//    return (uint32_t)thebl.imm();
//}
//
//loc_t patchfinder64::find_rop_add_x0_x0_0x10(){
//    constexpr char ropbytes[] = "\x00\x40\x00\x91\xC0\x03\x5F\xD6";
//    return [](const void *little, size_t little_len, vector<text_t>segments)->loc_t{
//        for (auto seg : segments) {
//            if (!seg.isExec)
//                continue;
//
//            if (loc_t rt = (loc_t)::memmem(seg.map, seg.size, little, little_len)) {
//                return rt-seg.map+seg.base;
//            }
//        }
//        return 0;
//    }(ropbytes,sizeof(ropbytes)-1,_segments);
//}
//
//loc_t patchfinder64::find_rop_ldr_x0_x0_0x10(){
//    constexpr char ropbytes[] = "\x00\x08\x40\xF9\xC0\x03\x5F\xD6";
//    return [](const void *little, size_t little_len, vector<text_t>segments)->loc_t{
//        for (auto seg : segments) {
//            if (!seg.isExec)
//                continue;
//
//            if (loc_t rt = (loc_t)::memmem(seg.map, seg.size, little, little_len)) {
//                return rt-seg.map+seg.base;
//            }
//        }
//        return 0;
//    }(ropbytes,sizeof(ropbytes)-1,_segments);
//}
//
//loc_t patchfinder64::find_exec(std::function<bool(patchfinder64::insn &i)>cmpfunc){
//    insn i(_segments);
//    while (true) {
//        if (cmpfunc(i))
//            return i;
//        try {
//            ++i;
//        } catch (out_of_range &e) {
//            break;
//        }
//    }
//    return 0;
//}
//
//
//
//#pragma mark patch_finders
//void slide_ptr(class patch *p,uint64_t slide){
//    slide += *(uint64_t*)p->_patch;
//    memcpy((void*)p->_patch, &slide, 8);
//}
//
//patch patchfinder64::find_sandbox_patch(){
//    loc_t str = findstr("process-exec denied while updating label",false);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn bdst(_segments, ref);
//    for (int i=0; i<4; i++) {
//        while (--bdst != insn::bl){
//        }
//    }
//    --bdst;
//
//    loc_t cbz = find_rel_branch_source(bdst, true);
//
//    return patch(cbz, patch_nop, patch_nop_size);
//}
//
//
//patch patchfinder64::find_amfi_substrate_patch(){
//    loc_t str = findstr("AMFI: hook..execve() killing pid %u: %s",false);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn funcend(_segments, ref);
//    while (++funcend != insn::ret);
//
//    insn tbnz(funcend);
//    while (--tbnz != insn::tbnz);
//
//    constexpr char mypatch[] = "\x1F\x20\x03\xD5\x08\x79\x16\x12\x1F\x20\x03\xD5\x00\x00\x80\x52\xE9\x01\x80\x52";
//    return {(loc_t)tbnz.pc(),mypatch,sizeof(mypatch)-1};
//}
//
//patch patchfinder64::find_cs_enforcement_disable_amfi(){
//    loc_t str = findstr("csflags",true);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn cbz(_segments, ref);
//    while (--cbz != insn::cbz);
//
//    insn movz(cbz);
//    while (++movz != insn::movz);
//    --movz;
//
//    int anz = static_cast<int>((movz.pc()-cbz.pc())/4 +1);
//
//    char mypatch[anz*4];
//    for (int i=0; i<anz; i++) {
//        ((uint32_t*)mypatch)[i] = *(uint32_t*)patch_nop;
//    }
//
//    return {(loc_t)cbz.pc(),mypatch,static_cast<size_t>(anz*4)};
//}
//
//patch patchfinder64::find_i_can_has_debugger_patch_off(){
//    loc_t str = findstr("Darwin Kernel",false);
//    retassure(str, "Failed to find str");
//
//    str -=4;
//
//    return {str,"\x01",1};
//}
//
//patch patchfinder64::find_amfi_patch_offsets(){
//    loc_t str = findstr("int _validateCodeDirectoryHashInDaemon",false);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn bl_amfi_memcp(_segments, ref);
//
//    loc_t memcmp = 0;
//
//    loc_t jscpl = 0;
//    while (1) {
//        while (++bl_amfi_memcp != insn::bl);
//
//        try {
//            jscpl = jump_stub_call_ptr_loc(bl_amfi_memcp);
//        } catch (tihmstar::bad_branch_destination &e) {
//            continue;
//        }
//        if (haveSymbols()) {
//            if (insn::deref(_segments, jscpl) == (uint64_t)(memcmp = find_sym("_memcmp")))
//                break;
//        }else{
//            //check for _memcmp function signature
//            insn checker(_segments, memcmp = (loc_t)insn::deref(_segments, jscpl));
//            if (checker == insn::cbz
//                && (++checker == insn::ldrb && checker.rn() == 0)
//                && (++checker == insn::ldrb && checker.rn() == 1)
////                ++checker == insn::sub //i'm too lazy to implement this now, first 3 instructions should be good enough though.
//                ) {
//                break;
//            }
//        }
//
//    }
//
//    /* find*/
//    //movz w0, #0x0
//    //ret
//    insn ret0(_segments, memcmp);
//    for (;; --ret0) {
//        if (ret0 == insn::movz && ret0.rd() == 0 && ret0.imm() == 0 && (ret0+1) == insn::ret) {
//            break;
//        }
//    }
//
//    uint64_t gadget = ret0.pc();
//    return {jscpl,&gadget,sizeof(gadget),slide_ptr};
//}
//
//patch patchfinder64::find_proc_enforce(){
//    loc_t str = findstr("Enforce MAC policy on process operations", false);
//    retassure(str, "Failed to find str");
//
//    loc_t valref = memmem(&str, sizeof(str));
//    retassure(valref, "Failed to find val ref");
//
//    loc_t proc_enforce_ptr = valref - (5 * sizeof(uint64_t));
//
//    loc_t proc_enforce_val_loc = (loc_t)insn::deref(_segments, proc_enforce_ptr);
//
//    uint8_t mypatch = 1;
//    return {proc_enforce_val_loc,&mypatch,1};
//}
//
//vector<patch> patchfinder64::find_nosuid_off(){
//    loc_t str = findstr("\"mount_common(): mount of %s filesystem failed with %d, but vnode list is not empty.\"", false);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn ldr(_segments,ref);
//
//    while (--ldr != insn::ldr);
//
//    loc_t cbnz = find_rel_branch_source(ldr, 1);
//
//    insn bl_vfs_context_is64bit(ldr,cbnz);
//    while (--bl_vfs_context_is64bit != insn::bl || bl_vfs_context_is64bit.imm() != (uint64_t)find_sym("_vfs_context_is64bit"));
//
//    //patch1
//    insn movk(bl_vfs_context_is64bit);
//    while (--movk != insn::movk || movk.imm() != 8);
//
//    //patch2
//    insn orr(bl_vfs_context_is64bit);
//    while (--orr != insn::orr || movk.imm() != 8);
//
//    return {{(loc_t)movk.pc(),patch_nop,patch_nop_size},{(loc_t)orr.pc(),"\xE9\x03\x08\x2A",4}}; // mov w9, w8
//}
//
//patch patchfinder64::find_remount_patch_offset(){
//    loc_t off = find_syscall0();
//
//    loc_t syscall_mac_mount = (off + 3*(424-1)*sizeof(uint64_t));
//
//    loc_t __mac_mount = (loc_t)insn::deref(_segments, syscall_mac_mount);
//
//    insn patchloc(_segments, __mac_mount);
//
//    while (++patchloc != insn::tbz || patchloc.rt() != 8 || patchloc.other() != 6);
//
//    --patchloc;
//
//    constexpr char mypatch[] = "\xC8\x00\x80\x52"; //movz w8, #0x6
//    return {(loc_t)patchloc.pc(),mypatch,sizeof(mypatch)-1};
//}
//
//patch patchfinder64::find_lwvm_patch_offsets(){
//    loc_t str = findstr("_mapForIO", false);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn functop(_segments,ref);
//
//    while (--functop != insn::stp || (functop+1) != insn::stp || (functop+2) != insn::stp || (functop-2) != insn::ret);
//
//    insn dstfunc(functop);
//    loc_t destination = 0;
//    while (1) {
//        while (++dstfunc != insn::bl);
//
//        try {
//            destination = jump_stub_call_ptr_loc(dstfunc);
//        } catch (tihmstar::bad_branch_destination &e) {
//            continue;
//        }
//
//        if (haveSymbols()) {
//            if (insn::deref(_segments, destination) == (uint64_t)find_sym("_PE_i_can_has_kernel_configuration"))
//                break;
//        }else{
//            //check for _memcmp function signature
//            insn checker(_segments, (loc_t)insn::deref(_segments, destination));
//            uint8_t reg = 0;
//            if ((checker == insn::adrp && (static_cast<void>(reg = checker.rd()),true))
//                && (++checker == insn::add && checker.rd() == reg)
//                && ++checker == insn::ldr
//                && ++checker == insn::ret
//                ) {
//                break;
//            }
//        }
//
//    }
//
//    while (++dstfunc != insn::bcond || dstfunc.other() != insn::cond::NE);
//
//    loc_t target = (loc_t)dstfunc.imm();
//
//    return {destination,&target,sizeof(target),slide_ptr};
//}
//
//loc_t patchfinder64::find_sbops(){
//    loc_t str = findstr("Seatbelt sandbox policy", false);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = memmem(&str, sizeof(str));
//    retassure(ref, "Failed to find ref");
//
//    return (loc_t)insn::deref(_segments, ref+0x18);
//}
//
//enum OFVariableType : uint32_t{
//    kOFVariableTypeBoolean = 1,
//    kOFVariableTypeNumber,
//    kOFVariableTypeString,
//    kOFVariableTypeData
//} ;
//
//enum OFVariablePerm : uint32_t{
//    kOFVariablePermRootOnly = 0,
//    kOFVariablePermUserRead,
//    kOFVariablePermUserWrite,
//    kOFVariablePermKernelOnly
//};
//struct OFVariable {
//    const char *variableName;
//    OFVariableType     variableType;
//    OFVariablePerm     variablePerm;
//    uint32_t           _padding;
//    uint32_t           variableOffset;
//};
//
//
//patch patchfinder64::find_nonceEnabler_patch(){
//    if (!haveSymbols()){
//        info("Falling back to find_nonceEnabler_patch_nosym, because we don't have symbols");
//        return find_nonceEnabler_patch_nosym();
//    }
//
//    loc_t str = findstr("com.apple.System.boot-nonce",true);
//    retassure(str, "Failed to find str");
//
//    loc_t sym = find_sym("_gOFVariables");
//
//    insn ptr(_segments,sym, insn::kText_and_Data);
//
//#warning TODO: doublecast works, but is still kinda ugly
//    OFVariable *varp = (OFVariable*)(void*)ptr;
//    OFVariable nullvar = {0};
//    for (OFVariable *vars = varp;memcmp(vars, &nullvar, sizeof(OFVariable)) != 0; vars++) {
//
//        if ((loc_t)vars->variableName == str) {
//            uint8_t mypatch = (uint8_t)kOFVariablePermUserWrite;
//            loc_t location =  sym + ((uint8_t*)&vars->variablePerm - (uint8_t*)varp);
//            return {location,&mypatch,1};
//        }
//    }
//
//    reterror("failed to find \"com.apple.System.boot-nonce\"");
//    return {0,0,0};
//}
//
//patch patchfinder64::find_nonceEnabler_patch_nosym(){
//    loc_t str = findstr("com.apple.System.boot-nonce",true);
//    retassure(str, "Failed to find str");
//
//    loc_t valref = memmem(&str, sizeof(str));
//    retassure(valref, "Failed to find val ref");
//
//    loc_t str2 = findstr("com.apple.System.sep.art",true);
//    retassure(str2, "Failed to find str2");
//
//    loc_t valref2 = memmem(&str2, sizeof(str2));
//    retassure(valref2, "Failed to find val ref2");
//
//    auto diff = abs(valref - valref2);
//
//    assure(diff % sizeof(OFVariable) == 0 && diff < 0x50); //simple sanity check
//
//    insn ptr(_segments, valref, insn::kText_and_Data);
//
//    OFVariable *vars = (OFVariable*)(void*)ptr;
//    if ((loc_t)vars->variableName == str) {
//        uint8_t mypatch = (uint8_t)kOFVariablePermUserWrite;
//        loc_t location = valref + offsetof(OFVariable, variablePerm);
//        return {location,&mypatch,1};
//    }
//
//    reterror("failed to find \"com.apple.System.boot-nonce\"");
//    return {0,0,0};
//}
//
//#pragma mark KPP bypass
//loc_t patchfinder64::find_gPhysBase(){
//    loc_t ref = find_sym("_ml_static_ptovirt");
//
//    insn tgtref(_segments, ref);
//
//    loc_t gPhysBase = 0;
//
//    if (tgtref != insn::adrp)
//        while (++tgtref != insn::adrp);
//    gPhysBase = (loc_t)tgtref.imm();
//
//    while (++tgtref != insn::ldr);
//    gPhysBase += tgtref.imm();
//
//    return gPhysBase;
//}
//
//loc_t patchfinder64::find_gPhysBase_nosym(){
//    loc_t str = findstr("\"pmap_map_high_window_bd: area too large", false);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str);
//    retassure(ref, "literal ref to str");
//
//    insn tgtref(_segments, ref);
//
//    loc_t gPhysBase = 0;
//
//    while (++tgtref != insn::adrp);
//    gPhysBase = (loc_t)tgtref.imm();
//
//    while (++tgtref != insn::ldr);
//    gPhysBase += tgtref.imm();
//
//    return gPhysBase;
//}
//
//loc_t patchfinder64::find_kernel_pmap(){
//    if (haveSymbols()) {
//        return find_sym("_kernel_pmap");
//    }else{
//        return find_kernel_pmap_nosym();
//    }
//}
//
//loc_t patchfinder64::find_kernel_pmap_nosym(){
//    loc_t str = findstr("\"pmap_map_bd\"", true);
//    retassure(str, "Failed to find str");
//
//    loc_t ref = find_literal_ref(_segments, str, 1);
//    retassure(ref, "literal ref to str");
//
//    insn btm(_segments,ref);
//    while (++btm != insn::ret);
//
//    insn kerne_pmap_ref(btm);
//    while (--kerne_pmap_ref != insn::adrp);
//
//    uint8_t reg = kerne_pmap_ref.rd();
//    loc_t kernel_pmap = (loc_t)kerne_pmap_ref.imm();
//
//    while (++kerne_pmap_ref != insn::ldr || kerne_pmap_ref.rn() != reg);
//    assure(kerne_pmap_ref.pc()<btm.pc());
//
//    kernel_pmap += kerne_pmap_ref.imm();
//
//    return kernel_pmap;
//}
//
//loc_t patchfinder64::find_cpacr_write(){
//    return memmem("\x40\x10\x18\xD5", 4);
//}
//
//loc_t patchfinder64::find_idlesleep_str_loc(){
//    loc_t entryp = find_entry();
//
//    insn finder(_segments,entryp);
//    assure(finder == insn::b);
//
//    insn deepsleepfinder(finder, (loc_t)finder.imm());
//    while (--deepsleepfinder != insn::nop);
//
//    loc_t fref = find_literal_ref(_segments, (loc_t)(deepsleepfinder.pc())+4+0xC);
//
//    insn str(finder,fref);
//    while (++str != insn::str);
//    while (++str != insn::str);
//
//    loc_t idlesleep_str_loc = (loc_t)str.imm();
//    int rn = str.rn();
//    while (--str != insn::adrp || str.rd() != rn);
//    idlesleep_str_loc += str.imm();
//
//    return idlesleep_str_loc;
//}
//
//loc_t patchfinder64::find_deepsleep_str_loc(){
//    loc_t entryp = find_entry();
//
//    insn finder(_segments,entryp);
//    assure(finder == insn::b);
//
//    insn deepsleepfinder(finder, (loc_t)finder.imm());
//    while (--deepsleepfinder != insn::nop);
//
//    loc_t fref = find_literal_ref(_segments, (loc_t)(deepsleepfinder.pc())+4+0xC);
//
//    insn str(finder,fref);
//    while (++str != insn::str);
//
//    loc_t idlesleep_str_loc = (loc_t)str.imm();
//    int rn = str.rn();
//    while (--str != insn::adrp || str.rd() != rn);
//    idlesleep_str_loc += str.imm();
//
//    return idlesleep_str_loc;
//}
//
loc_t kernelpatchfinder64::find_rootvnode() {
    return find_sym("_rootvnode");
}

loc_t kernelpatchfinder64::find_allproc(){
    loc_t str = findstr("\"pgrp_add : pgrp is dead adding process\"",true);
    retassure(str, "Failed to find str");
    
    loc_t ref = find_literal_ref(str);
    retassure(ref, "ref to str");
    
    vmem ptr(*_vmem,ref);
    
    while (++ptr != insn::and_ || ptr().rd() != 8 || ptr().rn() != 8 || ptr().imm() != 0xffffffffffffdfff);
    
    loc_t retval = (loc_t)find_register_value(ptr-2, 8);
    
    return retval;
}

