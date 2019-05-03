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
        OFexception(int code, std::string err, std::string filename) :exception(code,err,filename){}
        
        
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
        out_of_range(std::string err)
            : OFexception(__LINE__, err, "exception.cpp"){};
    };
    
    class symbol_not_found : public OFexception{
    public:
        symbol_not_found(int code, std::string sym, std::string filename)
            : OFexception(code,{"failed to find symbol: " + sym},filename) {};
    };
    
    class load_command_not_found : public OFexception{
        int _cmd;
    public:
        int cmd() const { return _cmd;};
        load_command_not_found(int code, int cmd, std::string filename)
            : OFexception(code,{"failed to find cmd: " + std::to_string(cmd)},filename), _cmd(cmd) {};
    };
    
    class symtab_not_found : public OFexception{
    public:
        symtab_not_found(int code, std::string err, std::string filename)
            : OFexception(code,err,filename) {};
    };
    
    class limit_reached : public OFexception{
    public:
        limit_reached(int code, std::string err, std::string filename)
            : OFexception(code,err,filename) {};
    };
    
    class bad_branch_destination : public OFexception{
    public:
        bad_branch_destination(int code, std::string err, std::string filename)
            : OFexception(code,err,filename) {};
    };
};


#endif /* OFexception_h */
