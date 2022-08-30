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
#include <xq/algorithms/nist/nist_decrypt.h>


_Bool xq_decrypt_file(struct xq_config* config,
                        const char* in_file_path,
                        const char* out_file_dir,
                        struct xq_message_payload* resulting_file_path,
                        struct xq_error_info* error  ) {
                        
    // 1. get the token and algorithm.
    char token_data[64]={0};
    struct xq_message_token token = {token_data, sizeof(token_data)};
    if (!xq_get_file_token(config, in_file_path, &token, error)){
        return 0;
    }
    
    // 2. Fetch the token from the server.
    char keyBits[MAX_QUANTUM_SIZE * 2] = {0};
    struct xq_key key = { keyBits , sizeof(keyBits)};
    
    _Bool success = xq_svc_get_key(config, token.data, &key, error);
    
    if ( !success ) {
        return 0;
    }
    
    // 3. Decrypt using the key and token.
    enum algorithm_type algorithm = xq_algorithm_from_token(token_data);
    switch (algorithm) {
    
        case Algorithm_OTP:
            return xq_otp_decrypt_file(key.data, in_file_path, out_file_dir, resulting_file_path, error);
        break;
        
        default:
        if (error) {
          sprintf(error->content, "This algorithm is not currently supported.");
          error->responseCode = -1;
        }
        return 0;
    }
}


_Bool xq_decrypt_file_start(struct xq_config* config, const char* in_file_path,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   ){
                     
       // 1. get the token and algorithm.
    char token_data[64]={0};
    struct xq_message_token token = {token_data, sizeof(token_data)};
    if (!xq_get_file_token(config, in_file_path, &token, error)){
        return 0;
    }
    
    // 2. Fetch the token from the server.
    char keyBits[MAX_QUANTUM_SIZE * 2] = {0};
    struct xq_key key = { keyBits , sizeof(keyBits)};
    
    _Bool success = xq_svc_get_key(config, token.data, &key, error);
    
    if ( !success ) {
        return 0;
    }
    
    // 3. Decrypt using the key and token.
    enum algorithm_type algorithm = xq_algorithm_from_token(token_data);
    
    switch (algorithm) {
    
        case Algorithm_OTP:
            return xq_otp_decrypt_file_start(key.data, in_file_path, stream_info, error);
        break;
        
        default:
        if (error) {
          sprintf(error->content, "This algorithm is not currently supported.");
          error->responseCode = -1;
        }
        return 0;
    }
    
    return 0;
}

int xq_decrypt_file_step( struct xq_file_stream* stream_info, uint8_t* data, int data_length){
    return xq_otp_decrypt_file_step(stream_info, data, data_length);
}

_Bool xq_decrypt_file_end(struct xq_file_stream* stream_info ){
    return xq_otp_decrypt_file_end(stream_info);
}
