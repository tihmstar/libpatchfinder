//
//  machopatchfinder32.hpp
//  patchfinder
//
//  Created by tihmstar on 06.07.21.
//

#ifndef machopatchfinder32_hpp
#define machopatchfinder32_hpp

#include <libpatchfinder/patchfinder32.hpp>

struct symtab_command;
namespace tihmstar {
    namespace patchfinder {
        
        class machopatchfinder32 : public patchfinder32{
            const struct symtab_command *__symtab;
            
            void loadSegments();
            __attribute__((always_inline)) const struct symtab_command *getSymtab();
            
            void init();
            
        public:
            machopatchfinder32(const char *filename);
            machopatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership = false);

            machopatchfinder32(const machopatchfinder32 &cpy) = delete; //delete copy constructor
            machopatchfinder32(machopatchfinder32 &&mv); //move constructor
            
            bool haveSymbols() { return __symtab != NULL;};
            loc_t find_sym(const char *sym);
            std::string sym_for_addr(loc_t addr);
            loc_t bl_jump_stub_ptr_loc(loc_t bl_insn);
        };
    };
};

#endif /* machopatchfinder32_hpp */
