//
//  offsetfinder64.hpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef offsetfinder64_hpp
#define offsetfinder64_hpp

#include <string>
#include <stdint.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <vector>

#include <stdlib.h>

typedef uint64_t offset_t;


namespace tihmstar {
    
    class exception : public std::exception{
        std::string _err;
        int _code;
    public:
        exception(int code, std::string err) : _err(err), _code(code) {};
        exception(std::string err) : _err(err), _code(0) {};
        exception(int code) : _code(code) {};
        const char *what(){return _err.c_str();}
        int code(){return _code;}
    };
    namespace patchfinder64{
        typedef uint8_t* loc_t;
        
        class patch{
        public:
            loc_t _location;
            const void *_patch;
            size_t _patchSize;
            patch(loc_t location, const void *patch, size_t patchSize) : _location(location){
                _patch = malloc(patchSize);
                memcpy((void*)_patch, patch, _patchSize=patchSize);
            }
            ~patch(){
                free((void*)_patch);
            }
            
        };
    }
    class offsetfinder64 {
    public:
        struct text_t{
            patchfinder64::loc_t map;
            size_t size;
            patchfinder64::loc_t base;
            bool isExec;
        };
        
    private:
        bool _freeKernel;
        uint8_t *_kdata;
        size_t _ksize;
        offset_t _kslide;
        std::vector<text_t> _segments;
        
        struct symtab_command *__symtab;
        void loadSegments(uint64_t slide);
        __attribute__((always_inline)) struct symtab_command *getSymtab();
        
    public:
        offsetfinder64(const char *filename);
        offsetfinder64(void* buf, size_t size, uint64_t base);
        
        patchfinder64::loc_t memmem(const void *little, size_t little_len);
        
        patchfinder64::loc_t find_sym(const char *sym);
        
        patchfinder64::patch find_sandbox_patch();
        patchfinder64::patch find_amfi_substrate_patch();
        patchfinder64::patch find_cs_enforcement_disable_amfi();
        patchfinder64::patch find_i_can_has_debugger_patch_off();
        patchfinder64::patch find_amfi_patch_offsets();
        patchfinder64::patch find_proc_enforce();
        std::vector<patchfinder64::patch> find_nosuid_off();
        
        ~offsetfinder64();
    };
    using segment_t = std::vector<tihmstar::offsetfinder64::text_t>;
    namespace patchfinder64{
        
        loc_t find_literal_ref(segment_t segemts, offset_t kslide, loc_t pos);
    }
}



#endif /* offsetfinder64_hpp */
