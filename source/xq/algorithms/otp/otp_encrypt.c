//
//  otp_encrypt.c
//  xqc
//
//  Created by Ike E on 10/19/20.
//


#include <stdio.h>
#include <memory.h>
#include <stdarg.h>
#include <stdlib.h>
#include <xq/config.h>
#include <xq/services/quantum/quantum.h>
#include <xq/services/crypto.h>
#include <xq/algorithms/otp/otp_encrypt.h>

_Bool xq_otp_encrypt(
                     uint8_t* data, size_t data_len,
                     char* key,
                     struct xq_message_payload* result,
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


_Bool xq_otp_encrypt_file(
                      const char* in_file_path, const char* out_file_path,
                     char* token,
                     char* key,
                     struct xq_error_info* error  ) {
    
    FILE* in_fp = fopen(in_file_path, "rb");
    if (!in_fp) {
        if (error) {
            sprintf(error->content, "Input file %s fould not be opened", in_file_path );
            error->responseCode = -1;
        }
        return 0;
    }
    
    FILE* out_fp = fopen(out_file_path, "wb");
    if (!out_fp) {
        if (error) {
            sprintf(error->content, "Output file %s fould not be opened", out_file_path );
            error->responseCode = -1;
        }
        fclose(in_fp);
        return 0;
    }
    
    char filename[512] = {0};
    xq_get_file_name(in_file_path, filename);
    
    
    int key_offset =  (key[0] == '.') ? 2 : 0;
    int key_length = ((int)strlen(key)) - key_offset;
    fseek(in_fp, 0, SEEK_END);
    int max_length = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    
    uint32_t token_length = (uint32_t) strlen((const char*)token);
    uint32_t name_length = strlen(filename);
    
    
    // 1. Write the token length and token
    int written = fwrite(&token_length, sizeof(uint32_t), 1, out_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to write token length to file");
        fclose(in_fp);
        fclose(out_fp);
        return 0;
    }
    written = fwrite(token, sizeof(uint8_t), token_length, out_fp);
    if (written < token_length) {
        if (error) sprintf( error->content, "Failed to write token to file");
        fclose(in_fp);
        fclose(out_fp);
        return 0;
    }
    
    // 2. Write the name length and OTP encrypted name
    written = fwrite(&name_length, sizeof(uint32_t), 1, out_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to write filename length to file");
        fclose(in_fp);
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
    
    if (written < name_length) {
        if (error) sprintf( error->content, "Failed to write complete filename to file");
        fclose(in_fp);
        fclose(out_fp);
        return 0;
    }
    
    // Read in 8k chunks by default
    uint8_t out_buffer[8192] = {0};
    _Bool has_more = 1;
    int count_index = 0;
    data_index = 0;
      do {
        written = 0;
        memset(out_buffer, 0, sizeof(out_buffer));
        int count_read = fread(out_buffer, sizeof(uint8_t), sizeof(out_buffer), in_fp);
        has_more = count_read == sizeof(out_buffer);
        if (count_read > 0 ){
           // Encode all the entries in the buffer.
           for (count_index = 0; count_index < count_read; ++data_index, ++count_index) {
                int key_index = key_offset  + (data_index % key_length);
                out_buffer[count_index] ^= key[key_index];
            }
           
           // Write the buffer to the file
           written = fwrite(&out_buffer,1,count_read, out_fp);
        }
    } while (has_more && written > 0);
    
    if (has_more) {
        sprintf( error->content, "Failed to write entire file data");
        fclose(in_fp);
        fclose(out_fp);
        return 0;
    }


    fclose(in_fp);
    fclose(out_fp);
    return 1;
    
}
