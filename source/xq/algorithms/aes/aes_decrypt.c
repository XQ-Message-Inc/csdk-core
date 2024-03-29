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


struct aes_dec_data {
    uint8_t salt[8];
    EVP_CIPHER_CTX* ctx;
};


/**
 * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_decrypt_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx)
{
  int i, nrounds = AES_ROUNDS;

 unsigned char key[32]={0}, iv[32]={0};
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(AES_CIPHER, AES_HASH(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  
  
  EVP_CIPHER_CTX_set_padding(e_ctx, AES_PADDING);
  
  EVP_DecryptInit_ex(e_ctx, AES_CIPHER, NULL, key, iv);

  return 0;
}


/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
_Bool aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int len, uint8_t* plaintext, uint32_t *plaintext_len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int p_len = len, f_len = 0;
  if (plaintext == 0) plaintext = malloc(p_len);
  else if (plaintext_len && *plaintext_len < p_len) {
    fprintf(stderr, "Length of ciphertext %i is less than expected %i\n ", *plaintext_len, p_len);
  }
  

  /* allows reusing of 'e' for multiple encryption cycles */
  if (!EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL)){
    ERR_print_errors_fp(stderr);
    return 0;
  }

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  if (!EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, len)){
    ERR_print_errors_fp(stderr);
    return 0;
  }

  /* update ciphertext with the final remaining bytes */
  if (!EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len)){
    ERR_print_errors_fp(stderr);
    return 0;
  }

  *plaintext_len = p_len + f_len;
  return 1;
}

_Bool xq_aes_decrypt(
                     uint8_t* data, size_t data_len,
                     char* key,
                     struct xq_message_payload* result,
                     void* ctx,
                     struct xq_error_info* error
) {
   if ( result == 0) {
        if (error) {
            xq_strcat(error->content, "No object was provided to store results" , MAX_ERROR_LENGTH);
            error->responseCode = 0;
        }
        return 0; // Fail
    }
    
     uint8_t* needle = data;
    _Bool salted = strncmp( "Salted__", (char*)data, 8) == 0 ;

    uint8_t salt[8];
    const int prefix_offset = 16;
    
    if (salted) {
        needle += prefix_offset;
        memccpy(salt, data + 8, '\0', 8 );
    }

    //-----------------------------
    
    int key_offset =  (key[0] == '.') ? 2 : 0;
    int key_length = ((int)strlen(key)) - key_offset;
    int max_length = data_len;
    
    
    if ( result->length == 0 ) {
        result->length = prefix_offset + (max_length);
        result->data = calloc( 1, result->length);
        
    }
    
    else if (result->length < max_length ) {
        if (error) {
            xq_strcat(error->content, "The provided buffer is not large enough to hold result" , MAX_ERROR_LENGTH);
            error->responseCode = 0;
        }
        return 0; // Fail
    }
    
    EVP_CIPHER_CTX *en;
    
    _Bool success = 0;
    
    struct aes_dec_data* aes_data = (struct aes_dec_data* ) ctx;
    
    if (!aes_data) {
        // Step 1: Initialize
        en = EVP_CIPHER_CTX_new();
        if (!en) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
        
        uint8_t key32[32], iv32[32];
        if (aes_decrypt_init((unsigned char*)&key[key_offset], key_length, salt, en) != 0) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
        
        // Step 2: Decrypt
        int len = (int) data_len - prefix_offset;
        // result->length -= prefix_offset;
        success = aes_decrypt(en, needle, len, result->data, &result->length);
        // Step 3: Cleanup (if context is local)
        if (!ctx) {
            EVP_CIPHER_CTX_free(en);
        }
    
    }
    
    else{
        en = (EVP_CIPHER_CTX*) aes_data->ctx;
        int len = (int) data_len - prefix_offset;
        success = aes_decrypt(en, needle, len, result->data, &result->length);
    }

    return success;
}


_Bool xq_aes_decrypt_file_start(
                    char* key,
                    const char* in_file_path,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   ){
                     
    FILE* in_fp = fopen(in_file_path, "rb");
    if (!in_fp) {
        if (error) {
            sprintf(error->content, "Input file %s fould not be opened", in_file_path );
            error->responseCode = -1;
        }
        return 0;
    }
    


    int key_offset =  (key[0] == '.') ? 2 : 0;
    int key_length = ((int)strlen(key)) - key_offset;
    size_t data_read = 0;

    uint32_t token_and_extra = 0;
    uint32_t name_length = 0;
    stream_info->header_index = 0;
    
    fseek(in_fp, 0, SEEK_END);
    stream_info->data_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    
    // 1. Skip the token length and token
    int written = fread(&token_and_extra, sizeof(uint32_t), 1, in_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to read token length to file");
        fclose(in_fp);
        return 0;
    }

    fseek(in_fp, TOKEN_LENGTH, SEEK_CUR);

    // 2. Read the name length and OTP encrypted name
    written = fread(&name_length, sizeof(uint32_t), 1, in_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to read filename length to file");
        fclose(in_fp);
        return 0;
    }

    written = 0;
    long data_index = 0;
    memset(stream_info->filename, 0, sizeof(stream_info->filename));
        
    written = fread(stream_info->filename, 1, name_length, in_fp);
    for (data_index = 0; data_index < name_length; ++data_index) {
        int key_index = key_offset  + (data_index % key_length);
        stream_info->filename[data_index] = key[key_index] ^ stream_info->filename[data_index];
    }
    
    if (strlen(stream_info->filename) < name_length) {
        if (error) sprintf( error->content, "Failed to write complete filename to file");
        fclose(in_fp);
        return 0;
    }
    fprintf(stdout,"DETECTED NAME: %s\n", stream_info->filename );
    

    struct aes_dec_data* dec =  malloc(sizeof(struct aes_dec_data));
    
    // Write the 8 byte salt to the file (right after the name)

    written = fread(dec->salt, 1, 8, in_fp);
    if (written < 8) {
         if (error) sprintf( error->content, "Failed to read AES information");
        fclose(in_fp);
        return 0;
    }
    
    fprintf(stdout,"DETECTED SALT: %s\n", dec->salt );
    

    data_index = 0;
    
    
     // RAND_bytes(salt, 8);
    dec->ctx = EVP_CIPHER_CTX_new();
    if (!dec->ctx) {
        ERR_print_errors_fp(stderr);
        fclose(in_fp);
        return 0;
    }
    
    if (aes_decrypt_init((unsigned char*)&key[key_offset], key_length, dec->salt, dec->ctx) != 0) {
        ERR_print_errors_fp(stderr);
        fclose(in_fp);
        return 0;
    }

    /// END ENCRYPT FILE DATA
    ///
    stream_info->fp = in_fp;
    stream_info->data_index = 0;
    stream_info->key = strdup(key + key_offset);
    stream_info->key_length = key_length;
    stream_info->header_index = ftell(in_fp);
    stream_info->data_size -= stream_info->header_index;
    stream_info->extra = dec;
    if (stream_info->algorithm == 0) stream_info->algorithm = Algorithm_AES;
    
    return 1;
    
}

size_t xq_aes_decrypt_file_step( struct xq_file_stream* stream_info, uint8_t* data, size_t data_length,struct xq_error_info *error){
       if (stream_info == 0 || stream_info->extra == 0) {
        return 0;
    }
    
    struct aes_dec_data* dec =  (struct aes_dec_data*) stream_info->extra;
    
    EVP_CIPHER_CTX* en = (EVP_CIPHER_CTX*) dec->ctx;

     if (!stream_info || (!stream_info->fp && !stream_info->native_handle) || !stream_info->key || stream_info->key_length == 0 || data_length == 0) {
        return -1;
    }

    int count_index = 0;
    int written = 0;
    size_t data_index = 0;

    size_t bytes_read;
    
    if (stream_info->fp){
        fseek(stream_info->fp, stream_info->header_index + stream_info->data_index, SEEK_SET);
        bytes_read = fread(data,1,data_length, stream_info->fp);
    }
    else {
        bytes_read = pread(stream_info->native_handle, data, data_length, stream_info->header_index + stream_info->data_index);
    }
    
    if (bytes_read == -1) {
        return -1;
    }
    

    else if (bytes_read == 0) {
        return 0;
    }
    
    size_t si = stream_info->data_index;
    
    uint32_t plaintext_len = data_length;

     _Bool success = aes_decrypt(en, &data[written], bytes_read, data, &plaintext_len);
     if (!success) {
        return 0;
     }
     stream_info->data_index += bytes_read;
     return bytes_read;
}

_Bool xq_aes_decrypt_file_end(struct xq_file_stream* stream_info ){
    if (stream_info) {
        fclose(stream_info->fp);
        if (stream_info->extra) {
            struct aes_dec_data* dec = (struct aes_dec_data*) stream_info->extra;
            EVP_CIPHER_CTX_free(dec->ctx);
            dec->ctx = 0;
        }
    }
    return 1;
}

void* xq_aes_create_dec_ctx(unsigned char *key_data, int key_data_len, uint8_t* salt, struct xq_error_info *error){

    struct aes_dec_data* d = malloc(sizeof(struct aes_dec_data));
    
     d->ctx = EVP_CIPHER_CTX_new();
        if (!d->ctx) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
        
        int key_offset =  (key_data[0] == '.') ? 2 : 0;
        int key_length = key_data_len - key_offset;
        
        memcpy(d->salt, salt, 8);
        if (aes_decrypt_init((unsigned char*)&key_data[key_offset], key_length,(unsigned char*) &d->salt, d->ctx) != 0) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
  
    return d;
}

void xq_aes_destroy_dec_ctx(void* ctx){
    printf("*** DESTROYING AES CONTEXT...\n");
    struct aes_dec_data* d = (struct aes_dec_data*) ctx;
    if (d && d->ctx) {
        EVP_CIPHER_CTX_free(d->ctx);
        free(d);
    }
}

void* xq_aes_reset_dec_ctx(void* ctx, unsigned char *key_data, int key_data_len,  uint8_t* salt, struct xq_error_info *error) {

    struct aes_dec_data* d = (struct aes_dec_data*) ctx;
    if (!d) return 0;
    
      int i, nrounds = AES_ROUNDS;

    unsigned char key[32]={0}, iv[32]={0};
    int key_offset =  (key_data[0] == '.') ? 2 : 0;
        int key_length = key_data_len - key_offset;
  i = EVP_BytesToKey(AES_CIPHER, AES_HASH(), salt, (unsigned char*)&key_data[key_offset], key_length, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return 0;
  }

    if (!EVP_DecryptInit_ex(d->ctx, AES_CIPHER, NULL, key, iv)){
         printf("Key size is %d bits - should be 256 bits\n", i);
        return 0;
    }
    
    return d;

}
