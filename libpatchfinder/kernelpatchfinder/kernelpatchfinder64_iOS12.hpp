//
//  kernelpatchfinder64_iOS12.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 22.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef kernelpatchfinder64_iOS12_hpp
#define kernelpatchfinder64_iOS12_hpp

#include "kernelpatchfinder64_iOS9.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS12 : public kernelpatchfinder64_iOS9{
    public:
        using kernelpatchfinder64_iOS9::kernelpatchfinder64_iOS9;
        
        /*
            Provides a set patches to disable codesignature checks
         */
        virtual std::vector<patch> get_codesignature_patches() override;
        
        virtual std::vector<patch> get_mount_patch() override;
    };
}
}

#endif /* kernelpatchfinder64_iOS12_hpp */
