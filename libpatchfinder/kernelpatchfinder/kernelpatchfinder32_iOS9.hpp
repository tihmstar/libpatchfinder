//
//  kernelpatchfinder32_iOS9.hpp
//  libpatchfinder
//
//  Created by tihmstar on 26.07.21.
//

#ifndef kernelpatchfinder32_iOS9_hpp
#define kernelpatchfinder32_iOS9_hpp

#include "kernelpatchfinder32_iOS8.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder32_iOS9 : public kernelpatchfinder32_iOS8{
    public:
        using kernelpatchfinder32_iOS8::kernelpatchfinder32_iOS8;
        
        virtual std::vector<patch> get_mount_patch() override;
    };
}
}
#endif /* kernelpatchfinder32_iOS9_hpp */
