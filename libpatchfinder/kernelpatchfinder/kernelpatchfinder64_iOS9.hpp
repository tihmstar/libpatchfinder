//
//  kernelpatchfinder64_iOS9.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 25.02.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef kernelpatchfinder64_iOS9_hpp
#define kernelpatchfinder64_iOS9_hpp

#include "kernelpatchfinder64_iOS8.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS9 : public kernelpatchfinder64_iOS8{
    public:
        using kernelpatchfinder64_iOS8::kernelpatchfinder64_iOS8;
        
        virtual std::vector<patch> get_mount_patch() override;
    };
}
}
#endif /* kernelpatchfinder64_iOS9_hpp */
