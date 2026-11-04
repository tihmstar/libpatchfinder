//
//  kernelpatchfinder64_iOS26.hpp
//  libpatchfinder
//
//  Created by erd on 11.11.25.
//

#ifndef kernelpatchfinder64_iOS26_hpp
#define kernelpatchfinder64_iOS26_hpp

#include "kernelpatchfinder64_iOS18.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS26 : public kernelpatchfinder64_iOS18{
    public:
        using kernelpatchfinder64_iOS18::kernelpatchfinder64_iOS18;
        
        virtual std::vector<patch> get_force_boot_ramdisk_patch() override;
    };
}
}
#endif /* kernelpatchfinder64_iOS26_hpp */
