#include <ServerV2\elfserver.h>

int main()
{
    volatile bool stop = false;

    SGX::Server::ElfServer server("settings.ini");
    server.Listen();

    while (!stop)
    {

    }
}