//
//  kernelpatchfinder64.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef kernelpatchfinder64_hpp
#define kernelpatchfinder64_hpp

#include <libpatchfinder/machopatchfinder64.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder.hpp>

namespace tihmstar {
    namespace patchfinder {
        class kernelpatchfinder64 : public machopatchfinder64, public kernelpatchfinder{
            kernelpatchfinder64(machopatchfinder64 &&mv);
        protected:
            kernelpatchfinder64(kernelpatchfinder64 &&mv);
            kernelpatchfinder64(const char *filename);
            kernelpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership = false);
        public:
            kernelpatchfinder64(const kernelpatchfinder64 &cpy) = delete;

            virtual std::string get_xnu_kernel_version() override;
            virtual const void *memoryForLoc(loc64_t loc) override;

            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement) override;
            
            static kernelpatchfinder64 *make_kernelpatchfinder64(const char *filename);
            static kernelpatchfinder64 *make_kernelpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership = false);
            static kernelpatchfinder64 *make_kernelpatchfinder64(machopatchfinder64 &&mv);
                        
            virtual ~kernelpatchfinder64();
        };
    };
};

#endif /* kernelpatchfinder64_hpp */
