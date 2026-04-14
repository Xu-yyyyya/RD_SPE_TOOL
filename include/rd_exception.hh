#ifndef mt_RD_EXCEPTION_H
#define mt_RD_EXCEPTION_H

#include <string>

struct RdException: public std::exception
{
    std::string m;
    RdException(std::string msg)
    {
        m = msg;
    }

    const char* what () const throw ()
    {
        return m.data();
    }
};

#endif

