//
//  ibootpatchfinder32_iOS5.cpp
//  libpatchfinder
//
//  Created by Elcomsoft R&D on 10.01.23.
//
#include <libgeneral/macros.h>

#include "ibootpatchfinder32_iOS5.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

std::vector<patch> ibootpatchfinder32_iOS5::get_sigcheck_img3_patch(){
    std::vector<patch> patches;
    
    loc_t cert_ref = find_literal_ref_thumb('CERT');
    assure(cert_ref);
    debug("cert_ref=0x%08x",cert_ref);
    
    loc_t bof = find_bof_thumb(cert_ref);
    debug("bof=0x%08x",bof);
    
    loc_t bref = find_call_ref_thumb(bof);
    debug("bref=0x%08x",bref);
    
    pushINSN(thumb::new_T1_immediate_movs(bref, 0, 0));
    pushINSN(thumb::new_T1_immediate_str(bref+2, 0, 3, 0));

    return patches;
}

std::vector<patch> ibootpatchfinder32_iOS5::set_root_ticket_hash(const void *hash, size_t hashSize){
    std::vector<patch> patches;

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
    loc_t imm = iter().imm();
    debug("imm=0x%08x",imm);
    
    uint8_t reg = iter().rt();
        
    while (++iter != arm32::ldr) {
        assure(iter() != arm32::pop);
    }
    
    assure(iter().rn() == reg);
    assure(iter().insnsize() == 4);
    
    pushINSN(thumb::new_T3_register_mov(iter().pc(), iter().rt(), iter().rn()));

    while (++iter != arm32::bl) {
        uint8_t rd = -1;
        try {
            rd = iter().rd();
        } catch (...) {
            continue;
        }
        if (rd != 1) continue;
        if (iter() == arm32::add && iter().rn() == reg) {
            nopspace += 8; //correction for -8 down below (in case we don't find this)
            nopspace -= iter().imm();
            break;
        }
    }
    nopspace -= 8;
    patches.push_back({imm,&nopspace,sizeof(uint32_t)});
    return patches;
}
