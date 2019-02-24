//
//  exception.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include "all_liboffsetfinder.hpp"
#include <liboffsetfinder64/exception.hpp>
#include <string>

using namespace tihmstar;

exception::exception(int code, std::string err, std::string filename) :
    _err(err),
    _code(code),
    _filename(filename){
        error("initing exception with build: count=%s sha=%s",build_commit_count().c_str(),build_commit_sha().c_str());
    };

const char *exception::what(){
    return _err.c_str();
}

int exception::code() const{
    return _code | (int)(_filename.size()<<16);
}
