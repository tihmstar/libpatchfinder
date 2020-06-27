//
//  kernelpatchfinderiOS13.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 27.06.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//


#include "OFexception.hpp"
#include "kernelpatchfinder64iOS13.hpp"

using namespace tihmstar;
using namespace offsetfinder64;
using namespace libinsn;

kernelpatchfinder64iOS13::kernelpatchfinder64iOS13(const char *filename)
    : kernelpatchfinder64(filename)
{
    //
}

kernelpatchfinder64iOS13::kernelpatchfinder64iOS13(const void *buffer, size_t bufSize)
    : kernelpatchfinder64(buffer,bufSize)
{
    //
}


loc_t kernelpatchfinder64iOS13::find_cs_blob_generation_count(){
    loc_t strloc = findstr("\"success, but no blob!\"", true);
    debug("strloc=%p\n",strloc);

    loc_t strref = find_literal_ref(strloc);
    debug("strref=%p\n",strref);

    vmem iter(*_vmem,strref);

    if (iter() == insn::add) --iter;
    
    loc_t bref = find_branch_ref((loc_t)iter,-0x1000);
    debug("bref=%p\n",bref);
    
    loc_t bof = find_bof(0xfffffff007d61bbc);
    debug("bof=%p\n",bof);

    loc_t mmm = find_literal_ref(0xfffffff0078e9680);
    debug("mmm=%p\n",mmm);

    reterror("todo");
}
