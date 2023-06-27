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

            virtual std::string get_xnu_kernel_version() override;
            virtual const void *memoryForLoc(loc64_t loc) override;

            
            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement) override;
            
            static kernelpatchfinder32 *make_kernelpatchfinder32(const char *filename);
            static kernelpatchfinder32 *make_kernelpatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership = false);
            static kernelpatchfinder32 *make_kernelpatchfinder32(machopatchfinder32 &&mv);
            
            virtual ~kernelpatchfinder32();
        };
    };
};
#endif /* kernelpatchfinder32_hpp */
