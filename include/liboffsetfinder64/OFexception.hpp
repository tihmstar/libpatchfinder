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
        using exception::exception;
    };
    //custom exceptions for makeing it easy to catch
    class out_of_range : public OFexception{
        using OFexception::OFexception;
    };

    class not_found : public OFexception{
        using OFexception::OFexception;
    };

    
    class symbol_not_found : public OFexception{
        using OFexception::OFexception;
    };
    
    class load_command_not_found : public OFexception{
        int _cmd;
    public:
        int cmd() const { return _cmd;};
        load_command_not_found(const char *commit_count_str, const char *commit_sha_str, int line, const char *filename, int cmd)
            : OFexception(commit_count_str,commit_sha_str,line,filename, "failed to find cmd: %s",cmd), _cmd(cmd) {};
    };
    
    class symtab_not_found : public OFexception{
        using OFexception::OFexception;
    };
    
    class limit_reached : public OFexception{
        using OFexception::OFexception;
    };
    
    class bad_branch_destination : public OFexception{
        using OFexception::OFexception;
    };
};


#endif /* OFexception_h */
