//
//  fips_encrypt.c
//  xqc
//
//  Created by Ike E on 10/21/20.
//

#include <stdio.h>
#include <memory.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/provider.h>
#endif
#include <xq/config.h>
#include <xq/services/quantum/quantum.h>
#include <xq/services/crypto.h>
#include <xq/algorithms/fips/fips_encrypt.h>
#include <openssl/rand.h>


struct fips_enc_data {
    uint8_t salt[8];
    EVP_CIPHER_CTX* ctx;
};

/**
 * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int fips_encrypt_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx)
{
  int i, nrounds = FIPS_ROUNDS;
  unsigned char key[32], iv[32];
  
  
  
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(FIPS_CIPHER, FIPS_HASH(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  
  EVP_CIPHER_CTX_set_padding(e_ctx, FIPS_PADDING);
  
  EVP_EncryptInit_ex(e_ctx, FIPS_CIPHER, NULL, key, iv);

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
_Bool fips_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int len, uint8_t* ciphertext, uint32_t *ciphertext_len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = len + AES_BLOCK_SIZE, f_len = 0;
  if (ciphertext == 0) ciphertext = malloc(c_len);
  else if (ciphertext_len && *ciphertext_len < c_len) {
    fprintf(stderr, "Length of ciphertext %i is less than expected %i\n ", *ciphertext_len, c_len);
  }

  /* allows reusing of 'e' for multiple encryption cycles */
  if (!EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL)){
    ERR_print_errors_fp(stderr);
    return 0;
  }

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  if (!EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, len)){
    ERR_print_errors_fp(stderr);
    return 0;
  }

  /* update ciphertext with the final remaining bytes */
  if (!EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len)){
    ERR_print_errors_fp(stderr);
    return 0;
  }

  *ciphertext_len = c_len + f_len;
  return 1;
}

void* xq_fips_create_ctx(unsigned char *key_data, int key_data_len, uint8_t* salt, struct xq_error_info *error){
    struct fips_enc_data* d = malloc(sizeof(struct fips_enc_data));
    
     d->ctx = EVP_CIPHER_CTX_new();
        if (!d->ctx) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
        
        int key_offset =  (key_data[0] == '.') ? 2 : 0;
        int key_length = key_data_len - key_offset;
        
        RAND_bytes(salt, 8);
        if (fips_encrypt_init((unsigned char*)&key_data[key_offset], key_length,(unsigned char*) &d->salt, d->ctx) != 0) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
  
    return d;
}

static inline void create_salt(uint8_t* salt){
    int i;
    
        for (  i = 0; i < 8 ; ++i ) {
            salt[i] = 48 + ((uint8_t) rand() % 74);
        }
}

void xq_fips_destroy_ctx(void* ctx){
    struct fips_enc_data* d = (struct fips_enc_data*) ctx;
    if (d && d->ctx) {
        EVP_CIPHER_CTX_free(d->ctx);
        free(d);
    }
}


_Bool xq_fips_encrypt(
 uint8_t* data, size_t data_len,
                     char* key,
                     struct xq_message_payload* result,
                     void* ctx,
                     struct xq_error_info* error
){

    if ( result == 0) {
        if (error) {
            xq_strcat(error->content, "No object was provided to store results" , MAX_ERROR_LENGTH);
            error->responseCode = 0;
        }
        return 0; // Fail
    }
    
    int key_offset =  (key[0] == '.') ? 2 : 0;
    int key_length = ((int)strlen(key)) - key_offset;
    int max_length = data_len;
    const int prefix_offset = 16;
    
    if ( result->length == 0 ) {
        result->length = prefix_offset + max_length + AES_BLOCK_SIZE;
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
    
    struct fips_enc_data* fips_data = (struct fips_enc_data* ) ctx;
    
    if (!fips_data) {
        // Step 1: Initialize
        en = EVP_CIPHER_CTX_new();
        if (!en) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
        uint8_t salt[8] = {0};
        create_salt(salt);
        
        // RAND_bytes(salt, 8);
        if (fips_encrypt_init((unsigned char*)&key[key_offset], key_length, salt, en) != 0) {
            ERR_print_errors_fp(stderr);
            return 0;
        }
        
        // Step 2: Encrypt
        int len = (int) data_len;
        result->length -= prefix_offset;
        success = fips_encrypt(en, data, len, result->data + prefix_offset, &result->length);
        if (success){
            memccpy(result->data, "Salted__", '\0', 8);
            memccpy(result->data + 8, salt , '\0', 8);
            result->length += prefix_offset;
        }
        // Step 3: Cleanup (if context is local)
        if (!ctx) {
            EVP_CIPHER_CTX_free(en);
        }
    
    }
    
    else{
        en = (EVP_CIPHER_CTX*) fips_data->ctx;
         int len = (int) data_len;
        result->length -= prefix_offset;
        success = fips_encrypt(en, data, len, result->data + prefix_offset, &result->length);
        if (success){
            memccpy(result->data, "Salted__", '\0', 8);
            memccpy(result->data + 8, fips_data->salt , '\0', 8);
            result->length += prefix_offset;
        }
    }

    return success;
}


_Bool xq_fips_encrypt_file_start(const char* in_file_path,
                      const char* out_file_path,
                      char* token,
                      char* key,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   ){
                     
     FILE* out_fp =0;
    _Bool is_native = stream_info && stream_info->native_handle;
    
    if (is_native) {
        out_fp = fdopen(stream_info->native_handle, "rb+");
    }
    else if (out_file_path){
        out_fp = fopen(out_file_path, "wb");
        fclose(out_fp);
        out_fp = fopen(out_file_path, "rb+");
        if (!out_fp) {
            if (error) {
                sprintf(error->content, "Output file %s fould not be opened", out_file_path );
                error->responseCode = -1;
            }
            return 0;
        }
    }
    
    char filename[512] = {0};
    if (out_file_path){
        if (!xq_get_file_name(in_file_path, filename)) {
            strcpy(filename, out_file_path);
        }
    }
    else {
        strcpy(filename, "unnamed");
    }
    
    int key_offset =  (key[0] == '.') ? 2 : 0;
    int key_length = ((int)strlen(key)) - key_offset;

    
    uint32_t token_and_extra = TOKEN_LENGTH + 8;
    uint32_t name_length = strlen(filename);
    
    
    // 1. Write the token length and token
    int written = fwrite(&token_and_extra, sizeof(uint32_t), 1, out_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to write token length to file");
        fclose(out_fp);
        return 0;
    }
    written = fwrite(token, sizeof(uint8_t), TOKEN_LENGTH, out_fp);
    if (written < TOKEN_LENGTH) {
        if (error) sprintf( error->content, "Failed to write token to file");

        fclose(out_fp);
        return 0;
    }
    
    // 2. Write the name length and OTP encrypted name
    written = fwrite(&name_length, sizeof(uint32_t), 1, out_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to write filename length to file");

        fclose(out_fp);
        return 0;
    }
    
    written = 0;
    long data_index = 0;
    for (data_index = 0; data_index < name_length; ++data_index) {
        int key_index = key_offset  + (data_index % key_length);
        uint8_t b = key[key_index] ^ filename[data_index];
        written += fwrite(&b, sizeof(uint8_t), 1, out_fp);
    }
    
    /// START ENCRYPT FILE DATA
    struct fips_enc_data* enc =  malloc(sizeof(struct fips_enc_data));
    enc->ctx = EVP_CIPHER_CTX_new();
    if (!enc->ctx) {
        ERR_print_errors_fp(stderr);
        fclose(out_fp);
        return 0;
    }
    create_salt(enc->salt);
    stream_info->extra = enc;
    
    // RAND_bytes(salt, 8);
    if (fips_encrypt_init((unsigned char*)&key[key_offset], key_length, enc->salt, enc->ctx) != 0) {
        ERR_print_errors_fp(stderr);
        fclose(out_fp);
        return 0;
    }
    
    // Write the 8 byte salt to the file (right after the name)
    fwrite(enc->salt, 1, 8, out_fp);
    
    printf("ENC SALT: %s\n", enc->salt);
    
    // Create a 64 bit section for our original file size.
    // We will add the actual value in the end section.
    stream_info->header_index = ftell(out_fp);
    stream_info->data_index = 0;
    stream_info->key = strdup(key + key_offset);
    stream_info->key_length = key_length;
    if (stream_info->algorithm == 0) stream_info->algorithm = Algorithm_FIPS;
    
    
    if (is_native) {
        fflush(out_fp);
        stream_info->fp = 0;
    }
    else {
        stream_info->fp = out_fp;
    }
    
    /// END ENCRYPT FILE DATA
    
    
    return 1;
 }
 
 size_t xq_fips_encrypt_file_step(struct xq_file_stream *stream_info, uint8_t *data,
                           size_t data_length,struct xq_error_info *error){
    
    if (stream_info == 0 || stream_info->extra == 0) {
        return 0;
    }
    
    struct fips_enc_data* enc =  (struct fips_enc_data*) stream_info->extra;
    
    EVP_CIPHER_CTX* en = (EVP_CIPHER_CTX*) enc->ctx;
    

    uint8_t out_buffer[FIPS_STREAM_CHUNK_SIZE + AES_BLOCK_SIZE];
    _Bool has_more = 1;
    int count_index = 0;
    uint32_t ciphertext_len;
    size_t total_written = 0;
    size_t total_read = 0;
    size_t original_index = stream_info->data_index;

    
     do {
        int to_write =  (data_length < FIPS_STREAM_CHUNK_SIZE) ? data_length : FIPS_STREAM_CHUNK_SIZE;
        if (to_write == 0) break;
        ciphertext_len = sizeof(out_buffer);
        
        _Bool success = fips_encrypt(en, &data[total_read], to_write, out_buffer, &ciphertext_len);
        if (!success) {
            return 0;
        }

        ssize_t actual_write = 0;
        if (stream_info->native_handle) {
            actual_write = pwrite(stream_info->native_handle, out_buffer, ciphertext_len, stream_info->header_index + original_index + total_written);
        
        }
        else if (stream_info->fp){
            actual_write = fwrite(out_buffer,1,ciphertext_len, stream_info->fp);
        }
        
        if (actual_write < ciphertext_len) {
            if (error) {
                error->responseCode = -1;
                sprintf(error->content,"An error occured while writing encrypted content: %s", strerror(errno));
                return 0;
            }
        }
            
        total_written += ciphertext_len;
        total_read += to_write;
        has_more = (total_read < data_length);
        

    } while (has_more);
    
    stream_info->data_index += total_written;
    
    return total_read;
 }
                     
_Bool xq_fips_encrypt_file_end(struct xq_file_stream *stream_info, struct xq_error_info *error){
     if (stream_info) {
     
         if (stream_info->fp > 0) {
            fclose(stream_info->fp);
            stream_info->fp = 0;
        }
        
        if (stream_info->extra) {
            struct fips_enc_data* enc = (struct fips_enc_data*) stream_info->extra;
            EVP_CIPHER_CTX_free(enc->ctx);
            enc->ctx = 0;
        }
    }
    return 1;
}



int xq_enable_fips(struct xq_config *cfg, const char *fips_conf_dir) {

  #if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    OSSL_PROVIDER *fips;
    OSSL_PROVIDER *base;
    unsigned long err = 0;
    
    // Check whether fips is already enabled.
    if (OSSL_PROVIDER_available(NULL, "fips") == 1) return 1;

    if (fips_conf_dir != NULL) {
        if (!OSSL_LIB_CTX_load_config(NULL, fips_conf_dir)) {
          ERR_print_errors_fp(stderr);
          fprintf(stderr, "Failed to load FIPS configuration.\n");
          exit(EXIT_FAILURE);
        }
    }
    
    // Unload the Base provider
    if (cfg->_base_provider != 0) {
        OSSL_PROVIDER_unload(cfg->_base_provider);
        cfg->_base_provider = 0;
    }
      
    // Load the FIPS provider
    fips = OSSL_PROVIDER_load(NULL, "fips");
    if (fips == NULL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to load FIPS provider.\n");
        exit(EXIT_FAILURE);
    }
    printf("FIPS Enabled: %s\n",
         OSSL_PROVIDER_available(NULL, "fips") == 1  ? "yes" : "no");

    // Enable FIPS
    int res = EVP_default_properties_enable_fips(NULL, 1);
    if (res == 0 ) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to set default FIPS property.\n");
        exit(EXIT_FAILURE);
    }

    cfg->_fips_provider = fips;
    cfg->_base_provider = base;

    return 1;
    
  #else
    fprintf(stderr, "OpenSSL version is not supported with FIPS mode.");
    exit(EXIT_FAILURE); // Exit if FIPS mode is requested with unsupported version.
    return 0;
  #endif

}

int xq_disable_fips(struct xq_config *cfg) {

    #if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (cfg == 0) {
      return 0;
    }
      
    // Disable FIPS
    int res = EVP_default_properties_enable_fips(NULL, 0);
    if (res == 0 ) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to set default FIPS property.\n");
        return 0;
    }

    // Unload the FIPS provider
    if (cfg->_fips_provider != 0) {
        OSSL_PROVIDER_unload(cfg->_fips_provider);
        cfg->_fips_provider = 0;
    }
      
    // Reload the base provider
    if (cfg->_base_provider == 0) {
        cfg->_base_provider = OSSL_PROVIDER_load(NULL, "base");
        if (cfg->_base_provider == NULL) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Failed to load base provider\n");
            return 0;
        }
    }
    
    printf("FIPS Enabled: %s\n",
        OSSL_PROVIDER_available(NULL, "fips") == 1  ? "yes" : "no");

      
    return 1;
    #else
    fprintf(stderr, "OpenSSL version is not FIPS compliant.");
    return 0;
    #endif
}
