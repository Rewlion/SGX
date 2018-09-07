#include "elfserver.h"
#include "utils.hpp"

#include <ServerV2/ThirdParty/boost/asio/ip/address.hpp>
#include <ServerV2/ThirdParty/boost/asio/ip/tcp.hpp>
#include <ServerV2/ThirdParty/boost/asio/read.hpp>
#include <ServerV2/ThirdParty/boost/asio/write.hpp>
#include <ServerV2/ThirdParty/inih/cpp/INIReader.h>

#include <array>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <ostream>
#include <fstream>
#include <thread>

#define STRING_KEY_SIZE 64

namespace SGX::Server
{
    typedef std::shared_ptr<ip::tcp::socket> SocketPtr;
    using Common::LOG;

    namespace
    {
        bool isPortCorrect(short port)
        {
            if (port > 0)
                return true;

            return false;
        }

        void ReceiveClientPublicKey(SocketPtr connection, char* bufferIn, const size_t size)
        {
            read(*connection, boost::asio::buffer(bufferIn, size));
        }

        void SendServerPublicKey(SocketPtr connection, std::string publicKey)
        {
            write(*connection, boost::asio::buffer(publicKey.data(), publicKey.size()));
        }

        void SendServerPublicKeySize(SocketPtr connection, std::string publicKey)
        {
            uint64_t tmp_buffer[1];
            tmp_buffer[0] = publicKey.size();
            write(*connection, boost::asio::buffer(tmp_buffer, sizeof(uint64_t)));
        }

        std::ifstream::pos_type GetFileSize(std::ifstream& file)
        {
            file.seekg(0, std::ios::end);
            std::ifstream::pos_type size = file.tellg();
            file.seekg(0, std::ios::beg);
            
            return size;
        }

        std::vector<char> ReadElfFile(const std::string& elfLocation)
        {
            std::ifstream elfFile(elfLocation, std::ios::binary);
            if (!elfFile.is_open())
                throw "Server cannot find an elf file.";

            std::ifstream::pos_type elfSize = GetFileSize(elfFile);
            std::vector<char> buffer(elfSize);
            elfFile.read(buffer.data(), elfSize);

            return buffer;
        }

        void SendSizeOfElfFile(SocketPtr connection, const uint64_t size)
        {
            write(*connection, boost::asio::buffer(&size, sizeof(size)));
        }

        void SendElfFile(SocketPtr connection, const std::vector<char>& elfFile)
        {
            write(*connection, boost::asio::buffer(elfFile.data(), elfFile.size()));
        }

        void InitializeClientSession(SocketPtr connection, const std::string ElfLocation, const Crypto::ServerCryptoContext serverCryptoContext)
        {
           try 
           {
               LOG("Accepted new connection from:", connection->remote_endpoint().address().to_string());

               std::array<char, STRING_KEY_SIZE> buffer;
               ReceiveClientPublicKey(connection, buffer.data(), STRING_KEY_SIZE);
               std::string clientPublicKey(buffer.begin(), buffer.end());
               LOG("Received client's public key:", clientPublicKey);

               SendServerPublicKeySize(connection, serverCryptoContext.PublicKey);
               LOG("Sent server's public key size:", serverCryptoContext.PublicKey.size());

               SendServerPublicKey(connection, serverCryptoContext.PublicKey);
               LOG("Sent server's public key:", serverCryptoContext.PublicKey);

               std::vector<char> elfFile = ReadElfFile(ElfLocation);
               LOG("size of elf file:", elfFile.size());

               Crypto::EncryptionContext encryptionContext{ serverCryptoContext.PrivateKey, clientPublicKey };
               std::vector<char> encryptedElfFile = Crypto::EncryptBuffer(elfFile, encryptionContext);
               LOG("encrypted elf file");

               SendSizeOfElfFile(connection, encryptedElfFile.size());
               LOG("Sent size of encrypted elf file:", encryptedElfFile.size());

               SendElfFile(connection, encryptedElfFile);
               LOG("Sent encrypted elf file");
           }
           catch (std::exception& error)
           {
               LOG("Error:", error.what());
               connection->close();
           }
        }
    }

    ElfServer::ElfServer(const std::string& iniSettingsFile)
    {
        ParseSettings(iniSettingsFile);
        CheckSettings();
        LOG("server settings:", "\nAddress:", Address, "\nPort:", Port, "\nElfLocation:", ElfLocation, "\n");

        CryptoContext = Crypto::GenerateServerContext();
        LOG("server's crypto context: {private_key:", CryptoContext.PrivateKey, ", public_key", CryptoContext.PublicKey, "}");
    }

    void  ElfServer::ParseSettings(const std::string& iniSettingsFile)
    {
        INIReader reader(iniSettingsFile);
        Address     = reader.Get("server", "address", "UNKNOWN");
        Port        = static_cast<short>(reader.GetInteger("server", "port", -1));
        ElfLocation = reader.Get("server", "elf_location", "UNKNOWN");
    }

    void ElfServer::CheckSettings() const
    {
        bool shouldExit = false;
        if (Address == "UNKNOWN")
        {
            shouldExit = true;
            LOG("Error: the `address` value in settings.ini is not initialized.");
        }
        if (Port == -1)
        {
            shouldExit = true;
            LOG("Error: the `port` value in settings.ini is not initialized.");
        }
        if (isPortCorrect(Port) == false)
        {
            shouldExit = true;
            LOG("Error: the `port` value in settings.ini is not correct initialized( Port <= 0 )");
        }
        if (ElfLocation == "UNKNOWN")
        {
            shouldExit = true;
            LOG("Error: the `elf_location` value in settings.ini is not initialized.");
        }

        if (shouldExit)
            exit(EXIT_FAILURE);
    }

    void ElfServer::Listen()
    {
        LOG("Listening...\n");
        ip::tcp::endpoint endpoint(ip::address::from_string(Address), Port);
        ip::tcp::acceptor acceptor(IOService, endpoint);

        try
        {
            while (true)
            {
                std::shared_ptr<ip::tcp::socket> connection(new ip::tcp::socket(IOService));
                acceptor.accept(*connection);
                std::thread(InitializeClientSession, connection, ElfLocation, CryptoContext).detach();
            }
        }
        catch (boost::system::system_error& error)
        {
            LOG("Error:", error.what());
        }
    }

}

