//
//  encrypt.c
//  xqc
//
//  Created by Ike E on 10/21/20.
//

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include <xq/config.h>
#include <xq/services/quantum/quantum.h>
#include <xq/services/crypto.h>
#include <xq/algorithms/otp/otp_encrypt.h>
#include <xq/algorithms/aes/aes_encrypt.h>
#include <xq/algorithms/fips/fips_encrypt.h>
#include <xq/services/sub/packet.h>


_Bool xq_encrypt(
                 struct xq_config* config,
              enum algorithm_type algorithm,
              uint8_t* data, size_t data_len,
              int entropy_bytes,
                 struct xq_quantum_pool* pool,
              struct xq_message_payload* result,
              struct xq_error_info* error   )
{
    
    if (algorithm == Algorithm_Autodetect) {
        //TODO: This should be detected from the configuration file. For now, set to OTP.
        algorithm =  Algorithm_OTP;
    }
    
    //  Determine the number of bits we will actually need to request.
    int entropy_bits = entropy_bytes << 2;
    
    // Make sure the user did not request a larger quantum set than allowed.
    if (entropy_bits > MAX_QUANTUM_SIZE ) {
        if (error) {
            sprintf( error->content, "Entropy of %i exceeds max allowed bits of %i", entropy_bits, MAX_QUANTUM_SIZE );
            error->responseCode = -1;
        }
        return 0;
    }
    
    // Use a preallocated buffer. Alternatively, we could dynamically allocate an array, as long as it is
    // cleaned up properly after use.
    char raw_entropy[MAX_QUANTUM_SIZE] = {0};
    struct xq_quantum_key quantum = { raw_entropy, entropy_bits };
    
    // Fetch the entropy bytes from the server.
    if ( !xq_svc_quantum( config, &quantum, pool , error) ) return 0;
    
    // Create a buffer for our hex bytes.
  //  char key[MAX_QUANTUM_SIZE/4] = {0};
    struct xq_hex_quantum_key key = { 0, entropy_bytes };
    

    // Convert the quantum entropy bits to hexadecimal.
   
    _Bool success = 0;
    
    switch (algorithm) {
        case Algorithm_OTP: {
            xq_key_to_hex(&quantum, &key, Indicator_OTP);
            success = xq_otp_encrypt(data, data_len, key.data, result, 0, error);
        }
        break;
        case Algorithm_AES: {
            xq_key_to_hex(&quantum, &key, Indicator_AES);
            success = xq_aes_encrypt( data,  data_len, key.data, result, 0, error);
        }
        break;
        case Algorithm_FIPS: {
            xq_key_to_hex(&quantum, &key, Indicator_FIPS);
            success = xq_aes_encrypt( data,  data_len, key.data, result, 0, error);
        }
            
        break;
        default: break;
    }
    
    if (success) {
        result->token_or_key = key.data;
    }
    else {
        xq_destroy_hex_quantum_key(&key);
    }
    
    return success;
}



_Bool xq_encrypt_and_store_token(
                                 struct xq_config* config,
                                 enum algorithm_type algorithm,
                                 uint8_t* data,  size_t data_len,
                                 int entropy_bytes,
                                 struct xq_quantum_pool* pool,
                                 const char* recipients,
                                 int hours_to_expiration,
                                 _Bool delete_on_read,
                                 struct xq_metadata* metadata,
                                 struct xq_message_payload* result,
                                 struct xq_error_info* error   ) {
    
    struct xq_message_payload int_payload = {0,0};
    
    if (!xq_encrypt(config, algorithm, data, data_len, entropy_bytes, pool, &int_payload, error)) {
        return 0;
    }
    
    struct xq_message_token_request request = {
        int_payload.token_or_key,
        (int) strlen(int_payload.token_or_key),
        recipients,
        hours_to_expiration, // expire in 2 hours
        delete_on_read // delete on read
    };
    
    struct xq_message_token message_token = { 0,0 };
    _Bool success = xq_svc_store_key(config, &request, metadata, &message_token, error);
    if (!success) {
        free(int_payload.data);
        if (int_payload.token_or_key) free(int_payload.token_or_key);
        if (message_token.data) free(message_token.data);
        return 0;
    }
    result->data = int_payload.data;
    result->length = int_payload.length;
    result->token_or_key = calloc(message_token.length + 1, 1);
    memcpy(result->token_or_key, message_token.data, message_token.length);
    free(message_token.data);
    free(int_payload.token_or_key);
    return 1;
    
}


void* xq_create_enc_ctx(enum algorithm_type algorithm, unsigned char *key_data, int key_data_len, uint8_t* salt, struct xq_error_info *error){
    switch (algorithm) {
        case Algorithm_OTP: return xq_otp_create_enc_ctx(key_data, key_data_len, salt, error);
        case Algorithm_AES: return xq_aes_create_enc_ctx(key_data, key_data_len, salt, error);
        case Algorithm_FIPS: return xq_fips_create_enc_ctx(key_data, key_data_len, salt, error);
        default:
        fprintf(stderr, "Invalid algorithm - no context available.\n");
    }
    return 0;
}

void xq_destroy_enc_ctx(enum algorithm_type algorithm, void* ctx){
    if (ctx == 0) return;
    switch (algorithm) {
        case Algorithm_OTP: return;
        break;
        case Algorithm_AES: xq_aes_destroy_enc_ctx(ctx);
        break;
        case Algorithm_FIPS: xq_fips_destroy_enc_ctx(ctx);
        break;
        default:
        fprintf(stderr, "Invalid algorithm - no action available.\n");;
    }
}

void* xq_reset_enc_ctx(enum algorithm_type algorithm,void* ctx, unsigned char *key_data, int key_data_len,  uint8_t* salt,   struct xq_error_info *error){
    switch (algorithm) {
        case Algorithm_OTP: return 0;
        case Algorithm_AES: return xq_aes_reset_enc_ctx(ctx, key_data, key_data_len, salt, error);
        case Algorithm_FIPS: return 0;
        default:
        fprintf(stderr, "Invalid algorithm - no action available.\n");
    }
    return 0;
}
