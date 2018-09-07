#include <ServerV2/ThirdParty/boost/asio/io_service.hpp>
#include <ServerV2/ThirdParty/boost/asio/ip/address.hpp>
#include <ServerV2/ThirdParty/boost/asio/ip/tcp.hpp>
#include <ServerV2/ThirdParty/boost/asio/write.hpp>
#include <ServerV2/ThirdParty/boost/asio/read.hpp>

#include <string>
#include <exception>
#include <iostream>
#include <cstdint>

#define G_STR "33f3392b7f5f936747e19e0db32af0e3620fcbb5546cb5dba583542a6994eb5f"
#define KEY_SIZE 64

using namespace boost::asio;

std::string SendPublicKeyToServer(const std::string& key, const std::wstring serverAddress)
{
	return "";
}

std::string GetElfFromServer(const std::wstring serverAddress)
{
	return "";
}

int main()
{
    //std::string response = SendPublicKeyToServer("KIKIKOKOTROLOLO", L"127.0.0.1:8989");
    try
    {
        io_service service;
        ip::tcp::endpoint ep(ip::address::from_string("127.0.0.1"), 8989);
        ip::tcp::socket sock(service);
        sock.connect(ep);

        boost::asio::write(sock, boost::asio::buffer(G_STR, KEY_SIZE));
        char buffer[KEY_SIZE];
        boost::asio::read(sock, boost::asio::buffer(buffer, KEY_SIZE));
        uint64_t sizeofElf;
        boost::asio::read(sock, boost::asio::buffer(&sizeofElf, sizeof(sizeofElf)));
        char* elfFile = new char[sizeofElf];
        boost::asio::read(sock, boost::asio::buffer(elfFile, sizeofElf));
    }
    catch (std::exception error)
    {
        std::string str = error.what();
    }
}