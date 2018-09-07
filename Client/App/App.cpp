/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <exception>
#include <iostream>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>

#include <mpir.h>

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>

using namespace boost::asio;

# include <unistd.h>
# include <pwd.h>
# include <sys/mman.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#define KEY_T char* 
#define KEY_SIZE 64
#define CHS_IN_256B 33
#define SERVER_PORT 8989

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    fprintf(stderr, "%s\n", str);
}

int ocall_mprotect(void *ptr, size_t len, int prot)
{
    int rtr_val = mprotect(ptr, len, prot);
    return rtr_val;
}

void ocall_print_numu(uint64_t num)
{
    fprintf(stderr, "0x%lx\n", num);
}

void ocall_print_nums(int64_t num)
{
    fprintf(stderr, "%li\n", num);
}

void ocall_print_pointer(void* p)
{
    fprintf(stderr, "%p\n", p);
}

namespace
{
    std::string WStringToString(const std::wstring& str)
    {
        return std::string(str.begin(), str.end());
    }
}

void SendPublicKeyToServer(ip::tcp::socket& sock, const char* key)
{
    boost::asio::write(sock, boost::asio::buffer(key, KEY_SIZE));
}

char* GetElfFromServer(ip::tcp::socket& sock, char* server_key_buffer,
    size_t* sizeof_elf)
{
    uint64_t key_size;
    boost::asio::read(sock, boost::asio::buffer(&key_size, sizeof(key_size)));
    boost::asio::read(sock, boost::asio::buffer(server_key_buffer, key_size));
    boost::asio::read(sock, boost::asio::buffer(sizeof_elf, sizeof(*sizeof_elf)));
    char* elfFile = new char[*sizeof_elf];
    boost::asio::read(sock, boost::asio::buffer(elfFile, *sizeof_elf));

    return elfFile;
}

char* TalkToServer(const char* server_addr, const char* key, 
    char* server_key_buffer, size_t* sizeof_elf)
{
    io_service service;
    ip::tcp::endpoint ep(ip::address::from_string(server_addr), SERVER_PORT);
    ip::tcp::socket sock(service);
    sock.connect(ep);
    SendPublicKeyToServer(sock, key);
    return GetElfFromServer(sock, server_key_buffer, sizeof_elf);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("Usage: %s <server IP addr>", argv[0]);
        printf(" <func_name> <int arg>\n");
        return -1;
    }
	
    if (initialize_enclave() < 0) {
        printf("Error while creating the enclave...\n");
        return -1;
    }

    char *endptr = NULL;
    int input = (int)strtol(argv[3], &endptr, 10);
    if (*endptr != '\0')
    {
        printf("ERROR: Cannot read input number from cmd line.\n");
        return -1;
    }
 
    int ret_val = 0;
    int encrypted = 1;
    KEY_T A = (KEY_T)calloc(2*CHS_IN_256B, sizeof(*A));
    KEY_T B = (KEY_T)calloc(2*CHS_IN_256B, sizeof(*B));
    if (A == NULL || B == NULL)
    {
        printf("Calloc error\n");
        return -1;
    }

    ecall_generate_key_DH(global_eid, A);
    printf("(%s:%i): A(Client public key): %064s\n", __FILE__, __LINE__, A);
    const char* serverAddress = argv[1];
    size_t code_size = 0;
    char* code_ptr = TalkToServer(serverAddress, A, B, &code_size);
    printf("(%s:%i): B(Server public key): %064s\n", __FILE__, __LINE__, B);
    ecall_inject_code(global_eid, &ret_val, (char*)code_ptr, code_size,
        encrypted, B);


    ecall_execute_code(global_eid, &ret_val, argv[2], input);
    printf("ret_val=%i\n", ret_val);

    sgx_destroy_enclave(global_eid);
    free(A);
    free(B);
    return 0;
}

