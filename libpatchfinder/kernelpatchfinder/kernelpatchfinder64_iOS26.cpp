//
//  kernelpatchfinder64_iOS26.cpp
//  libpatchfinder
//
//  Created by erd on 11.11.25.
//
#include <libgeneral/macros.h>

#include "kernelpatchfinder64_iOS26.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all64.h"
#include "sbops64.h"
#include <string.h>

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

std::vector<patch> kernelpatchfinder64_iOS26::get_force_boot_ramdisk_patch(){
    UNCACHEPATCHES;

    {
        //no rootfs auth patch
        loc_t str = findstr("rootvp not authenticated after mounting", false);
        debug("str=0x%16llx",str);

        loc_t ref = find_literal_ref(str);
        debug("ref=0x%16llx",ref);

        vmem iter = _vmem->getIter(ref);
        
        while ((--iter).supertype() != insn::sut_branch_imm)
            ;
        ++iter;
        loc_t bref = find_branch_ref(iter, -0x200);
        debug("bref=0x%16llx",bref);
        pushINSN(insn::new_general_nop(bref));
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

std::vector<patch> kernelpatchfinder64_iOS26::get_codesignature_patches(){
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
        
        if (stub_ptr){
            debug("stub_ptr=0x%016llx",stub_ptr);
            stub_query_trust_cache = -4;
            auto iter = _vmem->getIter();
            while (true) {
                stub_query_trust_cache = find_literal_ref(stub_ptr, 0, stub_query_trust_cache+4);
                iter = stub_query_trust_cache;
                if (iter() == insn::ldr && ++iter == insn::br) break;
            }
            debug("ref stub_ptr=0x%016llx",stub_query_trust_cache);
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
            pushINSN(insn::new_immediate_cbz(trustcache_check+4*1, trustcache_check+4*3, 2));
            pushINSN(insn::new_immediate_str_unsigned(trustcache_check+4*2, 0, 2, 0));
            pushINSN(insn::new_general_ret(trustcache_check+4*3));
        }
        retassure(didFindTargetFunc, "Failed to find a patch");
    }

    addPatches(get_trustcache_true_patch()); //needed for iPhone 11,2 iOS 17.0
    RETCACHEPATCHES;
}

