//
//  kernelpatchfinder32_iOS11.hpp
//  libpatchfinder
//
//  Created by tihmstar on 21.07.21.
//

#ifndef kernelpatchfinder32_iOS11_hpp
#define kernelpatchfinder32_iOS11_hpp

#include "kernelpatchfinder32_iOS10.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder32_iOS11 : public kernelpatchfinder32_iOS10{
    public:
        using kernelpatchfinder32_iOS10::kernelpatchfinder32_iOS10;
        
        /*
            Provides a set patches to disable codesignature checks
         */
        virtual std::vector<patch> get_codesignature_patches() override;
        
        virtual std::vector<patch> get_mount_patch() override;
        
        virtual std::vector<patch> get_allow_UID_key_patch() override;

        virtual std::vector<patch> get_always_get_task_allow_patch() override;
    };
}
}

#endif /* kernelpatchfinder32_iOS11_hpp */
