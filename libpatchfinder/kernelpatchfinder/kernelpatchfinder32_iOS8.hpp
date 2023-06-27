//
//  kernelpatchfinder32_iOS8.hpp
//  libpatchfinder
//
//  Created by tihmstar on 13.08.21.
//

#ifndef kernelpatchfinder32_iOS8_hpp
#define kernelpatchfinder32_iOS8_hpp

#include "kernelpatchfinder32_iOS6.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder32_iOS8 : public kernelpatchfinder32_iOS6{
    public:
        using kernelpatchfinder32_iOS6::kernelpatchfinder32_iOS6;
        
#pragma mark Patch finders
        virtual std::vector<patch> get_cs_enforcement_disable_amfi_patch() override;
    };
}
}
#endif /* kernelpatchfinder32_iOS8_hpp */
