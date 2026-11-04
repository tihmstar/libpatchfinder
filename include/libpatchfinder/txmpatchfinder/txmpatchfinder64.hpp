//
//  txmpatchfinder64.hpp
//  libpatchfinder
//
//  Created by erd on 13.10.26.
//

#ifndef txmpatchfinder64_hpp
#define txmpatchfinder64_hpp

#include <libpatchfinder/machopatchfinder64.hpp>
#include <libpatchfinder/txmpatchfinder/txmpatchfinder.hpp>

namespace tihmstar {
    namespace patchfinder {
        class txmpatchfinder64 : public machopatchfinder64, public txmpatchfinder{
            txmpatchfinder64(machopatchfinder64 &&mv);
        protected:
            txmpatchfinder64(txmpatchfinder64 &&mv);
            txmpatchfinder64(const char *filename);
            txmpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership = false);
        public:
            txmpatchfinder64(const txmpatchfinder64 &cpy) = delete;
            virtual ~txmpatchfinder64();

            virtual const void *memoryForLoc(loc64_t loc) override;
            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement) override;
            virtual std::string get_txm_version_number_string();

            
#pragma mark static
            static txmpatchfinder64 *make_txmpatchfinder64(const char *filename);
            static txmpatchfinder64 *make_txmpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership = false);
            static txmpatchfinder64 *make_txmpatchfinder64(machopatchfinder64 &&mv);
        };
    };
};
#endif /* txmpatchfinder64_hpp */
