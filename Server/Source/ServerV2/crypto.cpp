#include "crypto.h"
#include "utils.hpp"

#include <ServerV2/ThirdParty/aes/aes.h>
#include <ServerV2/ThirdParty/mpir/mpir.h>

#include <cstdlib>
#include <ctime>

#define G_STR "33f3392b7f5f936747e19e0db32af0e3620fcbb5546cb5dba583542a6994eb5f"
#define P_STR "c000000000000000000000000000000000000000000000000000000000000031"
#define KEY_SIZE 32

using SGX::Server::Common::LOG;

namespace SGX::Server::Crypto
{
    ServerCryptoContext GenerateServerContext()
    {
        srand((unsigned int)time(NULL));
        unsigned char c = 0;
        mpz_t big_num_private_key;
        mpz_init(big_num_private_key);
        for (size_t i = 0; i < KEY_SIZE; i++)
        {
            c = rand();
            mpz_add_ui(big_num_private_key, big_num_private_key, c);
            if (i < KEY_SIZE - 1)
                mpz_mul_ui(big_num_private_key, big_num_private_key, 256);
        }

        char str_key[2 * KEY_SIZE + 1];
        mpz_get_str(str_key, 16, big_num_private_key);
        std::string private_key_str(str_key);

        mpz_t g;
        mpz_init_set_str(g, G_STR, 16);
        mpz_t p;
        mpz_init_set_str(p, P_STR, 16);

        mpz_t big_num_public_key;
        mpz_init(big_num_public_key);
        mpz_powm(big_num_public_key, g, big_num_private_key, p);

        mpz_get_str(str_key, 16, big_num_public_key);
        std::string public_key_str = std::string(str_key);

        return ServerCryptoContext{ private_key_str, public_key_str };
    }

    std::vector<char> EncryptBuffer(const std::vector<char>& buffer, EncryptionContext context)
    {
        size_t bufferSize = buffer.size();
        if (bufferSize % 16 > 0)
            bufferSize = (bufferSize / 16 + 1) * 16;
        char* fileBuffer = (char*)calloc(bufferSize, sizeof(*fileBuffer));
        char* encBuffer = (char*)calloc(bufferSize, sizeof(*fileBuffer));
        memcpy(fileBuffer, buffer.data(), buffer.size());

        mpz_t server_key, client_key, enc_key, prime_num;
        mpz_init(enc_key);
        mpz_init_set_str(server_key, context.ServerPrivateKey.c_str(), 16);
        mpz_init_set_str(client_key, context.ClientPublicKey.c_str(), 16);
        mpz_init_set_str(prime_num, P_STR, 16);
        mpz_powm(enc_key, client_key, server_key, prime_num);
        unsigned char key[KEY_SIZE];
        mpz_export(key, NULL, 1, 1, 1, 0, enc_key);
        char enc_key_c_str[2 * KEY_SIZE + 1];
        mpz_get_str(enc_key_c_str, 16, enc_key);

        LOG("session key:", std::string(enc_key_c_str));

        for (size_t offset = 0; offset < bufferSize; offset += 16)
            AES_ECB_encrypt((uint8_t*)(fileBuffer + offset), key, (uint8_t*)(encBuffer + offset), 16);

        std::vector<char> encryptedVector(encBuffer, encBuffer + bufferSize);

        return encryptedVector;
    }
}