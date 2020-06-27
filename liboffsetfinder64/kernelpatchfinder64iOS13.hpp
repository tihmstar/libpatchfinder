//
//  kernelpatchfinderiOS13.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 27.06.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef kernelpatchfinder64iOS13_hpp
#define kernelpatchfinder64iOS13_hpp

#include "kernelpatchfinder64.hpp"

namespace tihmstar {
namespace offsetfinder64 {
    class kernelpatchfinder64iOS13 : public kernelpatchfinder64{
        
    public:
        kernelpatchfinder64iOS13(const char *filename);
        kernelpatchfinder64iOS13(const void *buffer, size_t bufSize);

        
        loc_t find_cs_blob_generation_count();
        
    };
}
}
#endif /* kernelpatchfinderiOS13_hpp */
