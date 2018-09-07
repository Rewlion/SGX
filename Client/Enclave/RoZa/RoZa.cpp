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

/* Test Array Attributes */

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"

#include "aes.h"
#include "parser.h"

#include "mpir.h"

#define PROT_READ   0x1     /* page can be read */                              
#define PROT_WRITE  0x2     /* page can be written */                           
#define PROT_EXEC   0x4     /* page can be executed */

#define HEX 16
#define CHS_IN_256B 33 	//32+1
#define KEY_SIZE 256
#define G_STR "33f3392b7f5f936747e19e0db32af0e3620fcbb5546cb5dba583542a6994eb5f"
#define P_STR "c000000000000000000000000000000000000000000000000000000000000031"

mpz_t a;
char* decr_code = NULL;
size_t injected_code_size = 0;

char* strcpy(char* dest, const char* src)
{
    size_t i;
    for (i = 0; src[i] != '\0'; i++)
        dest[i] = src[i];
}

void ecall_roza_function(char arr[20])
{
    ocall_print_string(arr);
}

unsigned char* generate_key(size_t bytes)
{
    unsigned char* buffer = (unsigned char*)malloc(bytes);
    sgx_read_rand(buffer, bytes);
    return buffer;
}

void ecall_generate_key_DH(char* A_str)
{
    unsigned char* buffer = generate_key(32);

    mpz_init(a);
    for(size_t i = 0; i < 32; i++)
    {
        mpz_add_ui(a, a, buffer[i]);
        if (i < 31)
            mpz_mul_ui(a, a, 256);
    }

    mpz_t g;
    mpz_init_set_str(g, G_STR, 16);
    mpz_t p;
    mpz_init_set_str(p, P_STR, 16);

    mpz_t A;
    mpz_init(A);
    mpz_powm(A, g, a, p);

    mpz_get_str(A_str, 16, A);

    mpz_clear(A);
    mpz_clear(g);
    mpz_clear(p);
}

int ecall_inject_code(char* code, size_t code_size, int encrypted, char* B_str)
{
    int (*f_ptr)(int) = NULL;

    decr_code = (char*)malloc(code_size);

    int result = 0;
    ocall_mprotect(&result,
        (void*)((unsigned long)decr_code-(unsigned long)decr_code%4096),
        code_size, PROT_READ|PROT_WRITE|PROT_EXEC);
    if (result == -1)
        return -1;

    if (encrypted)
    {
        mpz_t B, p;
        mpz_init_set_str(B, B_str, 16);
        mpz_init_set_str(p, P_STR, 16);
        mpz_t S;
        mpz_init(S);
        mpz_powm(S, B, a, p);

        char* S_str = (char*)calloc(2*CHS_IN_256B, sizeof(*S_str));
        char* a_str = (char*)calloc(2*CHS_IN_256B, sizeof(*S_str));
        if (S_str == NULL || a_str == NULL)
            return -1;
        mpz_get_str(S_str, 16, S);
        mpz_get_str(a_str, 16, a);
        ocall_print_string("Client private key:");
        ocall_print_string(a_str);
        ocall_print_string("Session key (used in AES):");
        ocall_print_string(S_str);
        free(S_str);
        free(a_str);

        unsigned char* S_buf = 
            (unsigned char*)calloc(CHS_IN_256B, sizeof(*S_buf));
        if (S_buf == NULL)
            return -1;
        mpz_export(S_buf, NULL, 1, 1, 1, 0, S);

        size_t mem_size = (code_size % 16 == 0)
            ? code_size : (code_size + 16 - (code_size % 16));
        for (size_t offset = 0; offset < mem_size; offset+=16)
            AES_ECB_decrypt((uint8_t*)code+offset, S_buf,
            (uint8_t*)decr_code+offset, 16);
        free(S_buf);
    }
    else
    {
        memcpy(decr_code, code, code_size);
    }
    injected_code_size = code_size;

    return 0;
}

int ecall_execute_code(char* func_name, int input)
{
    int (*f_ptr)(int) = NULL;
    int result = 0;

    Func_data func_data = mini_elf_parser(decr_code, func_name);
    if (func_data.status != 0)
        return -1;

    f_ptr = (int (*)(int))(decr_code + func_data.func_offset);
    result = (*f_ptr)(input);

    return result;
}
