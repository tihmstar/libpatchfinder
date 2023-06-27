//
//  kernelpatchfinder_iOS13.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 27.06.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef kernelpatchfinder64_iOS13_hpp
#define kernelpatchfinder64_iOS13_hpp

#include "kernelpatchfinder64_iOS12.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS13 : public kernelpatchfinder64_iOS12{
    public:
        using kernelpatchfinder64_iOS12::kernelpatchfinder64_iOS12;
        
        /*
            Provides a set of generic kernelpatches for jailbreaking
         */
        virtual std::vector<patch> get_generic_kernelpatches() override;
                
        virtual loc_t find_cs_blob_generation_count() override;
        
    };
}
}
#endif /* kernelpatchfinder_iOS13_hpp */
