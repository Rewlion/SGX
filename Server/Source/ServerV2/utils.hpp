#pragma once

#include <iostream>

namespace SGX::Server::Common
{
    namespace
    {
        template <class String>
        void print(String str)
        {
            std::cout << str;
        }

        void LOG()
        {
            std::cout << std::endl;
        }
    }

    template <class  String, class...Strings>
    void LOG(String &&first, Strings&&... rest)
    {
        print(first);
        LOG(rest...);
    }
}