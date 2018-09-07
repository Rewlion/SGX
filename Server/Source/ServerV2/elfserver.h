#pragma once

#include "crypto.h"

#include <ServerV2/ThirdParty/boost/asio/io_service.hpp>

#include <memory>
#include <string>

namespace SGX::Server
{
	using namespace boost::asio;

    class ElfServer
    {
    public:
        explicit ElfServer(const std::string& iniSettingsFile);
        void Listen();

    private:
        void ParseSettings(const std::string& iniSettingsFile);
        void CheckSettings() const;
    private:
        io_service IOService;

        std::string Address;
        short Port;
        std::string ElfLocation;

        Crypto::ServerCryptoContext CryptoContext;
    };
}
