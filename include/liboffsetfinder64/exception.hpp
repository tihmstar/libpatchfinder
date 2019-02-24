//
//  exception.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef exception_hpp
#define exception_hpp

#include <string>

namespace tihmstar {
    class exception : public std::exception{
        std::string _err;
        int _code;
        std::string _filename;
    public:
        exception(int code, std::string err, std::string filename);
        
        //custom error can be used
        const char *what();
        
        /*
         -first lowest two bytes of code is sourcecode line
         -next two bytes is strlen of filename in which error happened
         */
        int code() const;
        
        //Information about build
        virtual std::string build_commit_count() const {
            return "build_commit_count: override me!";
        };
        virtual std::string build_commit_sha() const{
            return "build_commit_sha: override me!";
        };
    };
};

#endif /* exception_hpp */
