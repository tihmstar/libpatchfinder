//
//  kernelpatchfinder64_iOS27.cpp
//  libpatchfinder
//
//  Created by erd on 16.09.26.
//
#include <libgeneral/macros.h>

#include "kernelpatchfinder64_iOS27.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all64.h"
#include "sbops64.h"
#include <string.h>

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

patchfinder64::loc_t kernelpatchfinder64_iOS27::findnops(uint16_t nopCnt, bool useNops, uint32_t nopOpcode){
    loc_t r = 0;
    /*
        is iOS 27 starting to jit some stuff? o.O
     */
    while (!r){
        r = kernelpatchfinder64_iOS26::findnops(nopCnt, useNops, nopOpcode);
        if (!useNops) break; //no checking if we don't reserve them
        if (_vmem->deref(r) == 0) break;
        auto iter = _vmem->getIter(r);
        if (--iter == insn::ret) break;
        for (int i=0; i<40; i++) {
            auto isn = ++iter;
            if (isn == insn::pacibsp) break;
            if (isn.supertype() == insn::sut_branch_imm && isn.imm() > isn.pc() && isn.imm() < isn.pc() + 0x200){
                r = 0;
                break;
            }
            if (isn == insn::ret) {
                r = 0;
                break;
            }
        }
    }
    return r;
}

patchfinder64::loc_t kernelpatchfinder64_iOS27::find_query_trustcache(){
    UNCACHELOC;
    try {
        return find_sym("_query_trust_cache");
    } catch (...) {
        //
    }
    /*
        A12 PPL stuff
     */
    auto iter = _vmem->getIter();
    loc_t target = 0;
    try {
        while (!target) {
            while (++iter != insn::movz || iter().subtype() != insn::st_immediate || iter().rd() != 15 || iter().imm() != 0x63)
                ;
            target = iter;
            if (++iter != insn::b)
                target = 0;
        }
    } catch (tihmstar::out_of_range &e) {
        //
    }
    if (target){
        debug("target=0x%016llx",target);

        loc_t bref = find_branch_ref(target, 0);
        debug("bref=0x%016llx",bref);
        
        iter = bref;

        for (int i=0; i<10; i++) {
            if (--iter == insn::bti) goto found_bof;
        }
        /*
            iPhone11,2 iOS 18.0 the bti instruction disappeared
         */
        iter = bref;
        for (int i=0; i<10; i++) {
            if (--iter == insn::cbz) goto found_bof;
        }
        reterror("Failed to find query_trustcache");

    found_bof:;
        {
            //iOS 27.0 AppleTV11,1
            while (true){
                if (--iter == insn::bl) break;
                if (iter().supertype() == insn::sut_branch_imm) continue;
                if (iter() == insn::cmp) continue;
                break;
            }
            ++iter;
        }
        RETCACHELOC(iter);
    }else{
        /*
            iPhone12,1 iOS 27.0.1
query_trust_cache:
0xfffffff00a6f829c         mov        x8, x0
0xfffffff00a6f82a0         mov        w0, #0x4
0xfffffff00a6f82a4         cmp        w8, #0x3
0xfffffff00a6f82a8         b.hi       loc_fffffff00a6f834c
0xfffffff00a6f82ac         cbz        x1, loc_fffffff00a6f834c
0xfffffff00a6f82b0         pacibsp
         */
        debug("Failed to find A12 PPL stuff, retrying with A13 method...");
        iter = 0;
        loc_t candidate = 0;
        while (true) {
            uint8_t bufreg = 0;
            if (++iter != insn::mov || iter().subtype() != insn::st_register || iter().rm() != 0) continue;
            bufreg = iter().rd();
            if (++iter != insn::movz || iter().imm() != 4 || iter().rd() != 0) continue;
            if (++iter != insn::cmp || iter().rn() != bufreg || iter().imm() != 3) continue;
            if ((++iter).supertype() != insn::sut_branch_imm) continue;
            candidate = iter.pc() - 4*3;
            debug("candidate=0x%016llx",candidate);
            break;
        }
        RETCACHELOC(candidate);
    }
}

patchfinder64::loc_t kernelpatchfinder64_iOS27::find_ml_io_map(){
    UNCACHELOC;
    
    auto iter = _vmem->getIter();
    int64_t x2val = -1;
    int64_t x3val = -1;
    int64_t x4val = -1;
    loc_t tgt = 0;
    auto isn = iter();
    while (true) {
        try {
            isn = ++iter;
        } catch (...) {
            break;
        }
        if (isn == insn::movz && isn.rd() == 2) x2val = isn.imm();
        else if (isn == insn::movz && isn.rd() == 3) x3val = isn.imm();
        else if (isn == insn::movz && isn.rd() == 4) x4val = isn.imm();
        else {
            if (isn == insn::b && x2val == 7 && x3val == 3 && x4val == 0){
                retassure(!tgt, "got unexpected multiple hits");
                tgt = isn;
                tgt -= 4*3;
            }
            x2val = -1;
            x3val = -1;
            x4val = -1;
        }
    }
    retassure(tgt,"Failed to find find_ml_io_map");
    RETCACHELOC(tgt);
}

std::vector<patch> kernelpatchfinder64_iOS27::get_codesignature_patches(){
    UNCACHEPATCHES;

    {
        //add disabling launch constraints
        loc_t str = findstr("AMFI: Validation Category info: current", false);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);
        
        loc_t bof = find_bof(ref);
        debug("bof=0x%16llx",bof);

        pushINSN(insn::new_immediate_movz(bof, 0, 0, 0));
        pushINSN(insn::new_general_ret(bof+4));
    }

    {
        //Hello iOS 16.4!
        loc_t query_trust_cache = find_query_trustcache();
        debug("query_trust_cache=0x%016llx",query_trust_cache);
        loc_t stub_ptr = 0;
        loc_t stub_query_trust_cache = 0;
        try {
            stub_ptr = memmem(&query_trust_cache, sizeof(query_trust_cache));
        } catch (...) {
            //
        }
        if (!stub_ptr){
            /*
                Stub can be PAC-ed (linker stuff)
                AppleTV11,1 iOS 27.0
             */
            loc_t stub_search = query_trust_cache - _base;
            try {
                stub_ptr = memmem(&stub_search, 6);
            } catch (...) {
                //
            }
        }
        
        if (stub_ptr){
            debug("stub_ptr=0x%016llx",stub_ptr);
            stub_query_trust_cache = find_literal_ref(stub_ptr);
        }
        if (!stub_query_trust_cache){
            /*
                On A12 it's not a stub
             */
            stub_query_trust_cache = query_trust_cache;
        }else{
            assure(stub_query_trust_cache);
            stub_query_trust_cache -=4;
            debug("stub_query_trust_cache=0x%016llx",stub_query_trust_cache);
        }

        bool didFindTargetFunc = 0;
        loc_t trustcache_check_call = -4;
        while (true) {
            try {
                trustcache_check_call = find_call_ref(stub_query_trust_cache,0,trustcache_check_call+4);
            } catch (...) {
                break;
            }
            debug("trustcache_check_call=0x%016llx",trustcache_check_call);
            loc_t trustcache_check = find_bof(trustcache_check_call);
            debug("trustcache_check=0x%016llx",trustcache_check);
            
            int cnt_bl = 0;
            auto iter = _vmem->getIter(trustcache_check);
            
            while (++iter != insn::ret){
                if (iter() == insn::bl) cnt_bl++;
            }
            if (cnt_bl != 2){
                debug("wrong target, ignoring...");
                continue;
            }
            
            retassure(!didFindTargetFunc, "Already found target, but it should be just on, right??");
            didFindTargetFunc = true;
            debug("Correct target!");
            pushINSN(insn::new_immediate_movz(trustcache_check+4*0, 1, 0, 0));
            pushINSN(insn::new_immediate_cbz(trustcache_check+4*1, trustcache_check+4*3, 3));
            pushINSN(insn::new_immediate_str_unsigned(trustcache_check+4*2, 0, 3, 0));
            pushINSN(insn::new_general_ret(trustcache_check+4*3));
        }
        retassure(didFindTargetFunc, "Failed to find a patch");
    }

    addPatches(get_trustcache_true_patch());
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS27::get_trustcache_true_patch(){
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
    
    iter = bof;
    while (++iter != insn::bl)
        ;
    loc_t b2 = iter().imm();
    debug("b2=0x%016llx",b2);

    loc_t refs = -4;
    while (true) {
        try {
            refs = find_call_ref(b2,0,refs+4);
        } catch (tihmstar::out_of_range &e) {
            break;
        }
        iter = refs;
        if (--iter == insn::movz && iter().rd() == 3 && iter().imm() == 0){
            debug("refs=0x%016llx",refs);
            pushINSN(insn::new_immediate_movz(refs, 0, 0, 0));
        }
    }

    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder64_iOS27::get_force_boot_ramdisk_patch(){
    UNCACHEPATCHES;
    
    addPatches(kernelpatchfinder64_iOS26::get_force_boot_ramdisk_patch());
    
    loc_t str = findstr(": boot from ramdisk ", false);
    assure(str);
    while (_vmem->deref(--str) & 0xFF)
        ;
    str++;
    debug("str=0x%016llx",str);

    loc_t ref = find_literal_ref(str);
    debug("ref=0x%16llx",ref);
    
    auto iter = _vmem->getIter(ref);
    
    while (--iter != insn::cbz)
        ;
    
    pushINSN(insn::new_general_nop(iter));
    
    while (--iter != insn::bl)
        ;
    
    loc_t rdfunc = iter().imm();
    debug("rdfunc=0x%16llx",rdfunc);

    iter = rdfunc;
    
    int passedBLs = 0;
    loc_t pachingloc = 0;
    uint8_t off=0;
    while (++iter != insn::ret) {
        if (iter() == insn::movz && iter().rd() == 0 && iter().imm() == 1) {
            pushINSN(insn::new_immediate_movz(iter, 0, 0, 0));
        }else if (iter() != insn::bl && iter().supertype() == insn::sut_branch_imm){
            pushINSN(insn::new_general_nop(iter));
        }else if (iter() == insn::bl){
            passedBLs++;
        }else if (iter() == insn::cmp && iter().imm() == 'm'){
            auto iter2 = iter;
            assure(--iter2 == insn::ldrb && iter2().rn() == 31);
            off = iter2().imm();
            pachingloc = iter2;
        }
    }

    debug("off=0x%x",off);
    debug("pachingloc=0x%016llx",pachingloc);
    pushINSN(insn::new_immediate_movz(pachingloc+4*0, '\0\0dm', 0, 0));
    pushINSN(insn::new_immediate_movk(pachingloc+4*1, '0', 0, 16));
    pushINSN(insn::new_immediate_str_unsigned(pachingloc+4*2, off, 31, 0));

    
    /*
        Fix apfs_vfsop_mount:3026: md0s1 apfs_iokit_mount_eligibility not eligible, err: 1
     */
    loc_t str2 = findstr("apfs_iokit_mount_eligibility not eligible", false);
    assure(str2);
    while (_vmem->deref(--str2) & 0xFF)
        ;
    str2++;
    debug("str2=0x%016llx",str2);

    loc_t ref2 = find_literal_ref(str2);
    debug("ref2=0x%16llx",ref2);
    
    iter = ref2;
    
    for (int i=0; i<20; i++) {
        if (--iter == insn::bl && iter().imm() == rdfunc) {
            pushINSN(insn::new_immediate_movk(iter, 1, 0, 0));
            RETCACHEPATCHES;
        }
    }
    reterror("Failed to find patches");
}
