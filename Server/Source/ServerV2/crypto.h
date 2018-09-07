#pragma once

#include <string>
#include <vector>

namespace SGX::Server::Crypto
{
    struct ServerCryptoContext
    {
        std::string PrivateKey;
        std::string PublicKey;
    };

    struct EncryptionContext
    {
        std::string ServerPrivateKey;
        std::string ClientPublicKey;
    };

    ServerCryptoContext GenerateServerContext();
    std::vector<char> EncryptBuffer(const std::vector<char>& buffer, EncryptionContext context);
}