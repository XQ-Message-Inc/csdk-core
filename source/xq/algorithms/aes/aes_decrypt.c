//
//  aes_decrypt.c
//  xqc
//
//  Created by Ike E on 10/21/20.
//


#include <stdio.h>
#include <memory.h>
#include <stdarg.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <xq/config.h>
#include <xq/services/quantum/quantum.h>
#include <xq/services/crypto.h>
#include <xq/algorithms/aes/aes_encrypt.h>


_Bool xq_aes_decrypt(
                     uint8_t* data, size_t data_len,
                     char* key,
                     struct xq_message_payload* result,
                     struct xq_error_info* error   ) {

    /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
     status of enc/dec operations */
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();
    
    /* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte
     integers on the stack as 64 bits of contigous salt material -
     ofcourse this only works if sizeof(int) >= 4 */
    //uint8_t salt[] = "Salted__";
    
    uint8_t salt[8] = {0};
    uint8_t* needle = data;
    
    _Bool compat = (key[0] == '.' && key[1] == 'A' );
    if (key[0] == '.') key += 2;
    
    int key_data_len = (int)strlen(key);
    size_t len =  data_len;
    
    _Bool salted = strncmp( "Salted__", (char*)data, 8) == 0 ;

    if (salted) {
        needle += 16;
        len -= 16;
        memccpy(salt, data + 8, '\0', 8 );
    }
    else {
        char prefix[8] = {0};
        memcpy(prefix, (char*)data, 8);
    }

    int i;
    unsigned char gen_key[32]={0}, gen_iv[32]={0};
    
    
    
    /*
     * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
     * nrounds is the number of times the we hash the material. More rounds are more secure but
     * slower.
     */
    i = EVP_BytesToKey(EVP_aes_256_cbc(), (compat) ? EVP_md5() : STRONG_HASH() , salt, (unsigned char*)key, key_data_len, (compat) ? 1 : AES_ROUNDS, gen_key, gen_iv);
    if (i != 32) {
        fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i);
        EVP_CIPHER_CTX_free(de);
        return -1;
    }
    
    if (EVP_DecryptInit_ex(de, EVP_aes_256_cbc(), NULL, gen_key, gen_iv)){

        /* plaintext will always be equal to or lesser than length of ciphertext*/
        _Bool nullmem = result->data == 0;
        int p_len = 0, f_len = 0;
        if (nullmem) result->data = malloc(len);
        if (!compat){
            EVP_CIPHER_CTX_set_padding(de, AES_PADDING);
        }
        if (!EVP_DecryptUpdate(de, result->data, &p_len, needle, len )) {
            ERR_print_errors_fp(stderr);
            result->length = 0;
            if (nullmem) free(result->data);
            return 0;
        }
        
        if (!compat && AES_PADDING > 0 && !EVP_DecryptFinal_ex(de, result->data+p_len, &f_len)) {
            ERR_print_errors_fp(stderr);
            result->length = 0;
            if (nullmem) free(result->data);
            return 0;
        }
        
        result->length = p_len + f_len;

        
    }
    else {
        ERR_print_errors_fp(stderr);
    }
    
    EVP_CIPHER_CTX_free(de);
   
    
    if (len <= 0 ) {
        fprintf(stderr, "[ERROR] AES decrypted yielded an empty string.\n");
    }
    
    return len > 0;
    
}
