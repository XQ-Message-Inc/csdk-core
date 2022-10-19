//
//  otp_decrypt.c
//  xqc
//
//  Created by Ike E on 10/21/20.
//

#include <stdio.h>
#include <memory.h>
#include <stdarg.h>
#include <stdlib.h>
#include <xq/config.h>
#include <xq/services/quantum/quantum.h>
#include <xq/services/crypto.h>
#include <xq/algorithms/otp/otp_decrypt.h>

_Bool xq_otp_decrypt(
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
    if ( key_length <= 0 ) return 0;
    
    size_t max_length = data_len;// > key_length ? data_length : key_length;
    
    if ( result->length == 0 ) {
        result->data = malloc(  max_length + 1 );
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

_Bool xq_otp_decrypt_file(  char* key,
                            const char* in_file_path,
                            const char* out_file_dir,
                            struct xq_message_payload* resulting_file_path,
                            struct xq_error_info* error ) {
                            
    FILE* in_fp = fopen(in_file_path, "rb");
    if (!in_fp) {
        if (error) {
            sprintf(error->content, "Input file %s fould not be opened", in_file_path );
            error->responseCode = -1;
        }
        return 0;
    }
    
    char filename[512] = {0};
    char out_file_path[512] = {0};

    int key_offset =  (key[0] == '.') ? 2 : 0;
    int key_length = ((int)strlen(key)) - key_offset;

    uint32_t token_length = 0;
    uint32_t name_length = 0;
    
    
    // 1. Skip the token length and token
    int written = fread(&token_length, sizeof(uint32_t), 1, in_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to read token length to file");
        fclose(in_fp);
        return 0;
    }
    fseek(in_fp, token_length, SEEK_CUR);

    // 2. Read the name length and OTP encrypted name
    written = fread(&name_length, sizeof(uint32_t), 1, in_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to read filename length to file");
        fclose(in_fp);
        return 0;
    }
    

    written = 0;
    long data_index = 0;
    
    
    if (out_file_dir[strlen(out_file_dir) - 1] == '/' ) {
    
        fread(filename, 1, name_length, in_fp);
        for (data_index = 0; data_index < name_length; ++data_index) {
            int key_index = key_offset  + (data_index % key_length);
            filename[data_index] = key[key_index] ^ filename[data_index];
        }
        
        if (strlen(filename) < name_length) {
            if (error) sprintf( error->content, "Failed to write complete filename to file");
            fclose(in_fp);
            return 0;
        }
        sprintf(out_file_path, "%s%s", out_file_dir, filename);
    }
    else {
        fseek(in_fp, name_length, SEEK_CUR);
        sprintf(out_file_path, "%s", out_file_dir);
    }
    
    // Open the output file
    
    FILE* out_fp = fopen(out_file_path, "wb");
    if (!out_fp) {
    perror("fopen");
        if (error) {
            sprintf(error->content, "Output file %s fould not be opened", filename );
            error->responseCode = -1;
        }
        fclose(in_fp);
        return 0;
    }
    
    
    // Read in 8k chunks by default
    uint8_t out_buffer[8192] = {0};
    _Bool has_more = 1;
    int count_index = 0;
    int k_idx;
    data_index = 0;
      do {
        written = 0;
        int count_read = fread(out_buffer, sizeof(uint8_t), sizeof(out_buffer), in_fp);
        has_more = count_read == sizeof(out_buffer);
        if (count_read > 0 ){
           // Encode all the entries in the buffer.
           for (count_index = 0; count_index < count_read; ++data_index, ++count_index) {
                k_idx = key_offset  + (data_index % key_length);
                out_buffer[count_index] = out_buffer[count_index] ^ ((uint8_t)key[k_idx]);
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
    
    if (resulting_file_path) {
        uint32_t len = strlen(out_file_path);
        if (resulting_file_path->data) {
            if (resulting_file_path->length < len) {
                memcpy(resulting_file_path->data, out_file_path, resulting_file_path->length );
            }
            memcpy(resulting_file_path->data, out_file_path, len );
            resulting_file_path->length = len;
        }
        else {
            resulting_file_path->length = len;
            resulting_file_path->data = (uint8_t*) strdup(out_file_path);
        }
    }
    return 1;
}



_Bool xq_otp_decrypt_file_start(
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

    uint32_t token_length = 0;
    uint32_t name_length = 0;
    stream_info->header_index = 0;
    
    fseek(in_fp, 0, SEEK_END);
    stream_info->data_size = ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    
    // 1. Skip the token length and token
    int written = fread(&token_length, sizeof(uint32_t), 1, in_fp);
    if (written <= 0) {
        if (error) sprintf( error->content, "Failed to read token length to file");
        fclose(in_fp);
        return 0;
    }

    fseek(in_fp, token_length, SEEK_CUR);

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
        
    fread(stream_info->filename, 1, name_length, in_fp);
    for (data_index = 0; data_index < name_length; ++data_index) {
        int key_index = key_offset  + (data_index % key_length);
        stream_info->filename[data_index] = key[key_index] ^ stream_info->filename[data_index];
    }
    
    if (strlen(stream_info->filename) < name_length) {
        if (error) sprintf( error->content, "Failed to write complete filename to file");
        fclose(in_fp);
        return 0;
    }
    
    stream_info->fp = in_fp;
    stream_info->data_index = 0;
    stream_info->key = strdup(key + key_offset);
    stream_info->key_length = key_length;
    stream_info->header_index = ftell(in_fp);
    stream_info->data_size -= stream_info->header_index;
    

    return 1;
                     
}

size_t xq_otp_decrypt_file_step( struct xq_file_stream* stream_info, uint8_t* data, size_t data_length){

    
    //////////////////
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
    

    if (bytes_read == 0) {
        return 0;
    }
    
    size_t si = stream_info->data_index;
    
     for (count_index = 0; count_index < bytes_read; ++si, ++count_index) {
        int key_index =  (si % stream_info->key_length);
        data[count_index] = data[count_index + written] ^ stream_info->key[key_index];
     }
     
     stream_info->data_index += bytes_read;
     
     return bytes_read;
}

_Bool xq_otp_decrypt_file_end(struct xq_file_stream* stream_info ){
    if (stream_info) {
        fclose(stream_info->fp);
    }
    return 0;
}
