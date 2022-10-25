//
//  otp_encrypt.c
//  xqc
//
//  Created by Ike E on 10/19/20.
//


#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <stdarg.h>
#include <stdlib.h>
#include <xq/config.h>
#include <xq/services/quantum/quantum.h>
#include <xq/services/crypto.h>
#include <xq/algorithms/otp/otp_encrypt.h>
#include <unistd.h>
#include <errno.h>


_Bool xq_otp_encrypt(
                     uint8_t* data, size_t data_len,
                     char* key,
                     struct xq_message_payload* result,
                     void* context,
                     struct xq_error_info* error   ) {
    
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
    
    if ( result->length == 0 ) {
        result->data = malloc( max_length + 1 );
    }
    
    else if (result->length < max_length ) {
        if (error) {
            xq_strcat(error->content, "The provided buffer is not large enough to hold result" , MAX_ERROR_LENGTH);
            error->responseCode = 0;
        }
        return 0; // Fail
    }
    
   
    register int m_idx = 0,k_idx = 0;
    do {
        k_idx = key_offset  + (m_idx % key_length);
        result->data[m_idx] = ((uint8_t)data[m_idx]) ^ ((uint8_t)key[k_idx]);
    } while (++m_idx < data_len );
    result->length = m_idx;
    return 1;
    
}


_Bool xq_otp_encrypt_file_start( const char* in_file_path,
                      const char* out_file_path,
                      char* token,
                      char* key,
                      struct xq_file_stream* stream_info,
                      struct xq_error_info* error   ){


    FILE* out_fp =0;
    _Bool is_native = stream_info && stream_info->native_handle;
    
    if (is_native) {
        out_fp = fdopen(stream_info->native_handle, "wb");
    }
    else if (out_file_path){
        out_fp = fopen(out_file_path, "wb");
        if (!out_fp) {
            if (error) {
                sprintf(error->content, "Output file %s fould not be opened", out_file_path );
                error->responseCode = -1;
            }
            return 0;
        }
    }

    
    int key_offset =  (key[0] == '.') ? 2 : 0;
    int key_length = ((int)strlen(key)) - key_offset;

    
    uint32_t token_length = (uint32_t) strlen((const char*)token);
    uint32_t name_length = strlen(out_file_path);
    
    
    // 1. Write the token length and token
    int written = fwrite(&token_length, sizeof(uint32_t), 1, out_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to write token length to file");
        fclose(out_fp);
        return 0;
    }
    written = fwrite(token, sizeof(uint8_t), token_length, out_fp);
    if (written < token_length) {
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
        uint8_t b = key[key_index] ^ out_file_path[data_index];
        written += fwrite(&b, sizeof(uint8_t), 1, out_fp);
    }
    
    if (written < name_length) {
        if (error) sprintf( error->content, "Failed to write complete filename to file");
        fclose(out_fp);
        return 0;
    }
    
    if (is_native) {
        fflush(out_fp);
       // fclose(out_fp);
        stream_info->fp = 0;
    }
    else {
        stream_info->fp = out_fp;
    }
    stream_info->header_index = ftell(out_fp);
    stream_info->data_index = 0;
    stream_info->key = strdup(key + key_offset);
    stream_info->key_length = key_length;
    if (stream_info->algorithm == 0) stream_info->algorithm = Algorithm_OTP;
    return 1;

}


size_t xq_otp_encrypt_file_step(struct xq_file_stream *stream_info, uint8_t *data,
                           size_t data_length, struct xq_error_info *error){
                        
    if (!stream_info || (!stream_info->fp && stream_info->native_handle == 0 ) || !stream_info->key || stream_info->key_length == 0 || data_length == 0) {
        if (error){
            error->responseCode = -1;
            if (!stream_info) {
                sprintf(error->content, "[xq_otp_encrypt_file_step] Stream info is null");
            }
            else if (!stream_info->fp && stream_info->native_handle == 0) {
                 sprintf(error->content, "[xq_otp_encrypt_file_step] Stream info file pointer and native handle are both null");
            }
            else if (!stream_info->key ) {
                 sprintf(error->content, "[xq_otp_encrypt_file_step] stream info key is null");
            }
            else if (stream_info->key_length == 0) {
                 sprintf(error->content, "[xq_otp_encrypt_file_step] stream info key length is zero");
            }
            else if (data_length == 0) {
                 sprintf(error->content, "[xq_otp_encrypt_file_step] Data length is zero");
            }
            else {
                sprintf(error->content, "[xq_otp_encrypt_file_step] One or more validation checks failed.");
            }
            
            
        }
        return 0;
    }
    

   
    uint8_t out_buffer[OTP_STREAM_CHUNK_SIZE];
    _Bool has_more = 1;
    int count_index = 0;
    size_t written = 0;
    size_t original_index = stream_info->data_index;
    
    
     do {
        int to_write =  (data_length < OTP_STREAM_CHUNK_SIZE) ? data_length : OTP_STREAM_CHUNK_SIZE;
        if (to_write == 0) break;
        
        for (count_index = 0; count_index < to_write; ++stream_info->data_index, ++count_index) {
            size_t key_index =  (stream_info->data_index % stream_info->key_length);
            out_buffer[count_index] = data[count_index + written] ^ stream_info->key[key_index];
        }
        
        ssize_t actual_write = 0;
        if (stream_info->native_handle) {
            actual_write = pwrite(stream_info->native_handle, out_buffer, to_write, stream_info->header_index + original_index + written);
        
        }
        else if (stream_info->fp){
            actual_write = fwrite(out_buffer,1,to_write, stream_info->fp);
        }
        
        if (actual_write<to_write) {
            if (error) {
                error->responseCode = -1;
                sprintf(error->content,"An error occured while writing encrypted content: %s", strerror(errno));
                return 0;
            }
        }
            
        written += to_write;
        has_more = (written < data_length);
    
    } while (has_more);
    
    return written;

}


_Bool xq_otp_encrypt_file_end(struct xq_file_stream *stream_info,struct xq_error_info *error) {
    if (stream_info) {
        fclose(stream_info->fp);
    }
    return 1;
}



void* xq_otp_create_ctx(unsigned char *key_data, int key_data_len, uint8_t* salt, struct xq_error_info *error){
    fprintf(stdout, "CREATING OTP CONTEXT.\n");
    return 0;
}

void xq_otp_destroy_ctx(void* ctx){
    
}
