//
//  OFexception.h
//  liboffsetfinder64
//
//  Created by tihmstar on 24.02.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef OFexception_h
#define OFexception_h

#include <libgeneral/macros.h>
#include <libgeneral/exception.hpp>

namespace tihmstar {
    class OFexception : public tihmstar::exception{
    public:
        OFexception(int code, const char *filename, const char *err ...) : tihmstar::exception(code,filename,err){}
        
        
        std::string build_commit_count() const override {
            return VERSION_COMMIT_COUNT;
        };
        
        std::string build_commit_sha() const override{
            return VERSION_COMMIT_SHA;
        };
    };
    //custom exceptions for makeing it easy to catch
    class out_of_range : public OFexception{
    public:
        out_of_range(int code, const char * filename, const char *err...)
            : OFexception(code, filename, err){};
    };
    
    class symbol_not_found : public OFexception{
    public:
        symbol_not_found(int code, const char * filename, const char * sym)
            : OFexception(code,filename,"failed to find symbol: %s", sym) {};
    };
    
    class load_command_not_found : public OFexception{
        int _cmd;
    public:
        int cmd() const { return _cmd;};
        load_command_not_found(int code, const char * filename, int cmd)
            : OFexception(code, filename,"failed to find cmd: %s",cmd), _cmd(cmd) {};
    };
    
    class symtab_not_found : public OFexception{
    public:
        symtab_not_found(int code, const char * filename, const char * err ...)
            : OFexception(code,filename,err) {};
    };
    
    class limit_reached : public OFexception{
    public:
        limit_reached(int code, const char * filename, const char * err ...)
            : OFexception(code,filename,err) {};
    };
    
    class bad_branch_destination : public OFexception{
    public:
        bad_branch_destination(int code, const char * filename, const char * err ...)
            : OFexception(code,filename,err) {};
    };
};


#endif /* OFexception_h */
