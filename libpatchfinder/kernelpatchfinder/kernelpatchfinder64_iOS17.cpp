//
//  kernelpatchfinder64_iOS17.cpp
//  libpatchfinder
//
//  Created by erd on 20.06.23.
//

#include "kernelpatchfinder64_iOS17.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include <libgeneral/macros.h>
#include "../all64.h"
#include "sbops64.h"
#include <string.h>

using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

std::vector<patch> kernelpatchfinder64_iOS17::get_codesignature_patches(){
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
        loc_t query_trust_cache = find_sym("_query_trust_cache");
        debug("query_trust_cache=0x%016llx",query_trust_cache);
        loc_t stub_ptr = memmem(&query_trust_cache, sizeof(query_trust_cache));
        debug("stub_ptr=0x%016llx",stub_ptr);

        loc_t stub_query_trust_cache = find_literal_ref(stub_ptr);
        assure(stub_query_trust_cache);
        stub_query_trust_cache -=4;
        debug("stub_query_trust_cache=0x%016llx",stub_query_trust_cache);

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

    RETCACHEPATCHES;
}
