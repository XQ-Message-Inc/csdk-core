//
//  decrypt.c
//  xqc
//
//  Created by Ike E on 10/21/20.
//

#include <stdio.h>

#include <time.h>
#include <stdlib.h>

#include <xq/config.h>
#include <xq/connect.h>
#include <xq/services/quantum/quantum.h>
#include <xq/services/sub/packet.h>
#include <xq/services/crypto.h>
#include <xq/algorithms/otp/otp_decrypt.h>
#include <xq/algorithms/aes/aes_decrypt.h>


_Bool xq_decrypt_with_token( struct xq_config* config, enum algorithm_type algorithm,  uint8_t* data,  size_t data_len, char* token, struct xq_message_payload* result, struct xq_error_info* error   ) {
    
    // 1st. fetch the key from the validation server using the provided token.
    char keyBits[MAX_QUANTUM_SIZE * 2] = {0};
    struct xq_key key = { keyBits ,sizeof(keyBits)};
    _Bool success = xq_svc_get_key(config, token, &key, error);
    
    if ( !success ) {
        return 0;
    }
    
    success = xq_decrypt_with_key(config, algorithm, data, data_len, key.data, result, error);
    return success;
    
}

_Bool xq_decrypt_with_key( struct xq_config* config, enum algorithm_type algorithm,  uint8_t* data,  size_t data_len, char* key, struct xq_message_payload* result, struct xq_error_info* error   ) {
    
    _Bool success = 0;
    
   
    if (algorithm == Algorithm_Autodetect) {
        
        // If the first character is a period, the next should indicate the algorithm type.
        if (key[0] == '.' ) {
            if (key[1] == Indicator_AES ) algorithm = Algorithm_AES;
            // OTP by default.
            else algorithm = Algorithm_OTP;
        }
        // OTP by default.
        else algorithm = Algorithm_OTP;
    }
    
    switch (algorithm) {
            
        case Algorithm_OTP: {
            success = xq_otp_decrypt(data, data_len, key, result,0, error);
        }
        break;
            
        case Algorithm_AES:{
            success = xq_aes_decrypt(data, data_len, key, result, 0, error);
        }
        break;
            
            
        default: break;
    }
    
    return success;
    
}

void* xq_create_dec_ctx(enum algorithm_type algorithm, unsigned char *key_data, int key_data_len, uint8_t* salt, struct xq_error_info *error){
    switch (algorithm) {
        case Algorithm_OTP: return 0;
        case Algorithm_AES: return xq_aes_create_dec_ctx(key_data, key_data_len, salt, error);
        default:
        fprintf(stderr, "Invalid algorithm - no context available.\n");
    }
    return 0;
}

void* xq_reset_dec_ctx(enum algorithm_type algorithm,void* ctx, unsigned char *key_data, int key_data_len,  uint8_t* salt,   struct xq_error_info *error){
    switch (algorithm) {
        case Algorithm_OTP: return 0;
        case Algorithm_AES:
         return xq_aes_reset_dec_ctx(ctx, key_data, key_data_len, salt, error);
        default:
        fprintf(stderr, "Invalid algorithm - no action available.\n");
    }
    return 0;
}



void xq_destroy_dec_ctx(enum algorithm_type algorithm, void* ctx){
    if (ctx == 0) return;
    switch (algorithm) {
        case Algorithm_OTP: return;
        break;
        case Algorithm_AES: xq_aes_destroy_dec_ctx(ctx);
        break;
        default:
        fprintf(stderr, "Invalid algorithm - no action available.\n");
    }
}
