//
//  kernelpatchfinder32.hpp
//  libpatchfinder
//
//  Created by tihmstar on 09.07.21.
//

#ifndef kernelpatchfinder32_hpp
#define kernelpatchfinder32_hpp

#include <libpatchfinder/machopatchfinder32.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder.hpp>

namespace tihmstar {
    namespace patchfinder {
        class kernelpatchfinder32 : public machopatchfinder32, public kernelpatchfinder{
            kernelpatchfinder32(machopatchfinder32 &&mv);
        protected:
            uint8_t _syscall_entry_size;
            kernelpatchfinder32(kernelpatchfinder32 &&mv);
            kernelpatchfinder32(const char *filename);
            kernelpatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership = false);
        public:
            kernelpatchfinder32(const kernelpatchfinder32 &cpy) = delete;
            virtual ~kernelpatchfinder32();
            

            virtual std::string get_xnu_kernel_version_number_string() override;
            virtual std::string get_kernel_version_string() override;
            virtual const void *memoryForLoc(loc64_t loc) override;
            
            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement) override;

            
#pragma mark static
            static kernelpatchfinder32 *make_kernelpatchfinder32(const char *filename);
            static kernelpatchfinder32 *make_kernelpatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership = false);
            static kernelpatchfinder32 *make_kernelpatchfinder32(machopatchfinder32 &&mv);
        };
    };
};
#endif /* kernelpatchfinder32_hpp */
