//
//  kernelpatchfinder32_iOS3.hpp
//  libpatchfinder
//
//  Created by erd on 18.12.23.
//

#ifndef kernelpatchfinder32_iOS3_hpp
#define kernelpatchfinder32_iOS3_hpp

#include "kernelpatchfinder32_base.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder32_iOS3 : public kernelpatchfinder32_base{
    public:
        using kernelpatchfinder32_base::kernelpatchfinder32_base;
        
        virtual std::vector<patch> get_codesignature_patches() override;
        virtual std::vector<patch> get_amfi_validateCodeDirectoryHashInDaemon_patch() override;
        
        /*
            calls to AppleImage3NORAccessUserClient doesn't check img3 signature anymore
         */
        virtual std::vector<patch> get_AppleImage3NORAccess_sigcheck_patch() override;
    };
}
}
#endif /* kernelpatchfinder32_iOS3_hpp */
