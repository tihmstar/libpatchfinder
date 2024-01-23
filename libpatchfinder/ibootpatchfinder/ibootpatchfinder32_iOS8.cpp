//
//  ibootpatchfinder32_iOS8.cpp
//  libpatchfinder
//
//  Created by erd on 16.10.23.
//

#include "ibootpatchfinder32_iOS8.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;



std::vector<patch> ibootpatchfinder32_iOS8::set_root_ticket_hash(const void *hash, size_t hashSize){
    UNCACHEPATCHES;
    
    loc_t str = (loc_t)findstr("root-ticket-hash", true);
    debug("str=0x%08x",str);
    assure(str);
    
    loc_t ref = find_literal_ref_thumb(str);
    debug("ref=0x%08x",ref);
    assure(ref);
    
    vmem_thumb iter = _vmemThumb->getIter(ref);
    while (++iter != arm32::bl)
        ;
    while (++iter != arm32::bl)
        ;
    
    loc_t ticket_get_hash_func = iter().imm();
    debug("ticket_get_hash_func=0x%08x",ticket_get_hash_func);
    
    loc_t nopspace = (loc_t)findnops(hashSize/4, true, 0x00000000);
    debug("nopspace=0x%08x",nopspace);
    
    patches.push_back({nopspace,hash,hashSize});
    
    iter = ticket_get_hash_func;
    while (++iter != arm32::ldr)
        ;
    assure(iter().subtype() == st_literal);
    loc_t ldrloc = iter;
    loc_t imm = iter().imm();
    debug("ldrloc=0x%08x",ldrloc);
    debug("imm=0x%08x",imm);
    
    patches.push_back({imm,&nopspace,sizeof(uint32_t)});

    if (ldrloc & 0b11) {
        pushINSN(thumb::new_T1_general_nop(ldrloc));
        ldrloc+=2;
    }
    pushINSN(thumb::new_T1_literal_ldr(ldrloc, imm, 1));
    iter = ldrloc;
    
    while (++iter != arm32::blx) {
        pushINSN(thumb::new_T1_general_nop(iter));
        assure(iter.pc() < imm);
    }
    patches.pop_back();

    --iter;
    pushINSN(thumb::new_T1_immediate_movs(iter, 0x14, 2));
    
    RETCACHEPATCHES;
}
