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
#include <ext/mime/mime.h>
#include <xq/config.h>
#include <xq/services/quantum/quantum.h>
#include <xq/services/crypto.h>
#include <xq/algorithms/otp/otp_encrypt.h>
#include <xq/algorithms/aes/aes_encrypt.h>
#include <xq/algorithms/fips/fips_encrypt.h>
#include <xq/services/sub/packet.h>

enum algorithm_type algorithm_from_key(const char* key){
    if (key == 0 || strlen(key) < 2 || key[0] != '.') return Algorithm_OTP;
    switch(key[1]){
       case Indicator_OTP: return Algorithm_OTP;
       case Indicator_AES: return Algorithm_AES;
       case Indicator_FIPS: return Algorithm_FIPS;
       default: return Algorithm_OTP;
    }
}

_Bool xq_get_file_token(struct xq_config *config, const char *in_file_path,
                            struct xq_message_token *token,
                            struct xq_error_info *error) {

  // 1.  Extract the file token.
  FILE *in_fp = fopen(in_file_path, "rb");
  if (in_fp == 0) {
    if (error) {
      sprintf(error->content, "Failed to open file: %s", in_file_path);
      error->responseCode = -1;
    }
    return 0;
  }

  // 2. Read the length of the file token.
  uint32_t token_length = 43;
  uint32_t token_and_overflow = 0;
  int bytes_read = fread(&token_and_overflow, sizeof(uint32_t), 1, in_fp);

  if (bytes_read <= 0 || token_and_overflow < 43) {
    fclose(in_fp);
    if (error) {
      sprintf(error->content, "Failed to read any token bytes");
      error->responseCode = -1;
    }
    return 0;
  }

  char token_read[64] = {0};

  bytes_read = fread(token_read, 1, token_length, in_fp);
  if (bytes_read < token_length) {
    if (error) {
      sprintf(error->content, "Read %i bytes of token instead of %i",
              bytes_read, token_length);
      error->responseCode = -1;
    }
    return 0;
  }

  fclose(in_fp);

  if (token) {
    if (token->data) {
      strcpy(token->data, token_read);
    } else {
      token->data = strdup(token_read);
    }
    token->length = token_length;
  }

  return 1;
}

_Bool xq_encrypt_file(const char *in_file_path, const char *out_file_path,
                      char *token, char *key, struct xq_error_info *error) {

  enum algorithm_type algorithm = algorithm_from_key(key);

  encrypt_file_start_type _start = 0;
  encrypt_file_step_type _step = 0;
  encrypt_file_end_type _end = 0;

  switch (algorithm) {
  case Algorithm_OTP:
    _start = xq_otp_encrypt_file_start;
    _step = xq_otp_encrypt_file_step;
    _end = xq_otp_encrypt_file_end;
    break;

  case Algorithm_AES:
    _start = xq_aes_encrypt_file_start;
    _step = xq_aes_encrypt_file_step;
    _end = xq_aes_encrypt_file_end;
    break;
    
  case Algorithm_FIPS:
    _start = xq_fips_encrypt_file_start;
    _step = xq_fips_encrypt_file_step;
    _end = xq_fips_encrypt_file_end;
    break;

  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }
    return 0;
  }

  struct xq_file_stream stream_info = {0};
  stream_info.algorithm = algorithm;
  

  if (!_start(in_file_path, out_file_path, token, key, &stream_info, error)) {
    return 0;
  }

  FILE *in_fp = fopen(in_file_path, "rb");
  uint8_t out_buffer[OTP_STREAM_CHUNK_SIZE];
  _Bool has_more = 1;
  int count_index = 0;
  long data_index = 0;
  do {
    int count_read =
        fread(out_buffer, sizeof(uint8_t), sizeof(out_buffer), in_fp);
    has_more = count_read == sizeof(out_buffer);
    if (count_read > 0) {
      if (!_step(&stream_info, out_buffer, count_read, error)) {
        _end(&stream_info, 0);
        return 0;
      }
    }
  } while (has_more);

  if (!_end(&stream_info, error)) {
    return 0; // Failed to end file properly
  }

  return 1; // Encryption OK
}

_Bool xq_encrypt_file_and_store_token(
    struct xq_config *config, enum algorithm_type algorithm,
    const char *in_file_path, const char *out_file_path, int entropy_bytes,
    struct xq_quantum_pool *pool, const char *recipients,
    int hours_to_expiration, _Bool delete_on_read,
    struct xq_error_info *error) {

  struct xq_metadata metadata = {Metadata_File, 0, 0};

  // For files the token will need to be stored before encryption
  FILE *source_file = fopen(in_file_path, "rb");
  if (source_file) {
    fseek(source_file, 0, SEEK_END);
    long length = ftell(source_file);
    if (length == 0) {
      if (error)
        sprintf(error->content, "Cannot encrypt an empty file %s",
                in_file_path);
      fclose(source_file);
      return 0;
    }
    fclose(source_file);

    char metadata_string[512] = {0};
    metadata.data = metadata_string;
    char in_file_name[512] = {0};
    xq_get_file_name(in_file_path, in_file_name);
    const char *mime_type = getMegaMimeType(in_file_path);
    sprintf(metadata.data, "{\"type\":\"%s\",\"size\":%li,\"title\":\"%s\"}",
            mime_type, length, in_file_name);
    metadata.length = strlen(metadata.data);

  } else {
    if (error)
      sprintf(error->content, "Failed to open input file %s", in_file_path);
    return 0;
  }

  //  Determine the number of bits we will actually need to request.
  int entropy_bits = entropy_bytes << 2;

  // Make sure the user did not request a larger quantum set than allowed.
  if (entropy_bits > MAX_QUANTUM_SIZE) {
    if (error) {
      sprintf(error->content, "Entropy of %i exceeds max allowed bits of %i",
              entropy_bits, MAX_QUANTUM_SIZE);
      error->responseCode = -1;
    }
    return 0;
  }

  // Use a preallocated buffer. Alternatively, we could dynamically allocate an
  // array, as long as it is cleaned up properly after use.
  char raw_entropy[MAX_QUANTUM_SIZE] = {0};
  struct xq_quantum_key quantum = {raw_entropy, entropy_bits};

  // Fetch the entropy bytes from the server.
  if (!xq_svc_quantum(config, &quantum, pool, error)) {
    if (error) {
      sprintf(error->content, "[xq_encrypt_file_and_store_token] %s (%li)",
              error->content, error->responseCode);
    }
    return 0;
  }

  // Create a buffer for our hex bytes.
  struct xq_hex_quantum_key key = {0, entropy_bytes};

  // Convert the quantum entropy bits to hexadecimal.

  _Bool success = 0;

  switch (algorithm) {
  case Algorithm_OTP: {
    success = xq_key_to_hex(&quantum, &key, Indicator_OTP);
  } break;
  case Algorithm_AES: {
    success = xq_key_to_hex(&quantum, &key, Indicator_AES);
  } break;
  case Algorithm_FIPS: {
    success = xq_key_to_hex(&quantum, &key, Indicator_FIPS);
  }

  break;
  default:
    break;
  }

  if (!success) {
    if (error) {
      sprintf(error->content, "[xq_svc_quantum] %s (%li)", error->content,
              error->responseCode);
    }
    return success;
  }

  // Attempt to to store the token.
  struct xq_message_token_request request = {
      key.data, key.length, recipients,
      hours_to_expiration, // expire in 2 hours
      delete_on_read       // delete on read
  };

  char token_data[64] = {0};
  struct xq_message_token message_token = {token_data, sizeof(token_data)};

  success =
      xq_svc_store_key(config, &request, &metadata, &message_token, error);

  if (!success) {
    xq_destroy_hex_quantum_key(&key);
    return 0;
  }
  
  _Bool res = xq_encrypt_file(in_file_path, out_file_path, (char*)message_token.data, key.data, error);
  xq_destroy_hex_quantum_key(&key);
  
  return res;
}

_Bool xq_encrypt_file_start(struct xq_config *config,  const char *in_file_path, const char *out_file_path,
                             enum algorithm_type algorithm,
                            int entropy_bytes,
                            struct xq_quantum_pool *pool, const char *recipients,
                            int hours_to_expiration, _Bool delete_on_read,
                            struct xq_file_stream *stream_info,
                            struct xq_error_info *error) {

    
  //  Determine the number of bits we will actually need to request.
  int entropy_bits = entropy_bytes << 2;

  // Make sure the user did not request a larger quantum set than allowed.
  if (entropy_bits > MAX_QUANTUM_SIZE) {
    if (error) {
      sprintf(error->content, "Entropy of %i exceeds max allowed bits of %i",
              entropy_bits, MAX_QUANTUM_SIZE);
      error->responseCode = -1;
    }
    return 0;
  }

  // Use a preallocated buffer. Alternatively, we could dynamically allocate an
  // array, as long as it is cleaned up properly after use.
  char raw_entropy[MAX_QUANTUM_SIZE] = {0};
  struct xq_quantum_key quantum = {raw_entropy, entropy_bits};
  
   struct xq_metadata metadata = {Metadata_File, 0, 0};
   
     // For files the token will need to be stored before encryption
     if (in_file_path){
          FILE *source_file = fopen(in_file_path, "rb");
          if (source_file) {
            fseek(source_file, 0, SEEK_END);
            long length = ftell(source_file);
            if (length == 0) {
              if (error)
                sprintf(error->content, "Cannot encrypt an empty file %s",
                        in_file_path);
              fclose(source_file);
              return 0;
            }
            fclose(source_file);

            char metadata_string[512] = {0};
            metadata.data = metadata_string;
            char in_file_name[512] = {0};
            xq_get_file_name(in_file_path, in_file_name);
            const char *mime_type = getMegaMimeType(in_file_path);
            sprintf(metadata.data, "{\"type\":\"%s\",\"size\":%li,\"title\":\"%s\"}",
                    mime_type, length, in_file_name);
            metadata.length = strlen(metadata.data);

          } else {
            if (error)
              sprintf(error->content, "Failed to open input file %s", in_file_path);
            return 0;
          }
     } else if (out_file_path && stream_info->native_handle) {
        char metadata_string[512] = {0};
        metadata.data = metadata_string;
        char in_file_name[512] = {0};
        xq_get_file_name(out_file_path, in_file_name);
        const char *mime_type = getMegaMimeType(out_file_path);
        sprintf(metadata.data, "{\"type\":\"%s\",\"title\":\"%s\"}",
                mime_type, in_file_name);
        metadata.length = strlen(metadata.data);
     }


  // Fetch the entropy bytes from the server.
  if (!xq_svc_quantum(config, &quantum, pool, error)) {
    if (error) {
      sprintf(error->content, "[xq_encrypt_file_and_store_token] %s (%li)",
              error->content, error->responseCode);
    }
    return 0;
  }

  // Create a buffer for our hex bytes.
  struct xq_hex_quantum_key key = {0, entropy_bytes};

  // Convert the quantum entropy bits to hexadecimal.

  _Bool success = 0;

  switch (algorithm) {
  case Algorithm_OTP: {
    success = xq_key_to_hex(&quantum, &key, Indicator_OTP);
  } break;
  case Algorithm_AES: {
    success = xq_key_to_hex(&quantum, &key, Indicator_AES);
  } break;
  case Algorithm_FIPS: {
    success = xq_key_to_hex(&quantum, &key, Indicator_FIPS);
  }

  break;
  default:
    break;
  }

  if (!success) {
    if (error) {
      sprintf(error->content, "[xq_svc_quantum] %s (%li)", error->content,
              error->responseCode);
    }
    return success;
  }

  // Attempt to to store the token.
  struct xq_message_token_request request = {
      key.data, key.length, recipients,
      hours_to_expiration, // expire in 2 hours
      delete_on_read       // delete on read
  };

  char token_data[64] = {0};
  struct xq_message_token message_token = {token_data, sizeof(token_data)};

  success =
      xq_svc_store_key(config, &request, &metadata, &message_token, error);

  if (!success) {
    xq_destroy_hex_quantum_key(&key);
    // if (message_token.data) free(message_token.data);
    return 0;
  }
  

 if (stream_info) stream_info->algorithm = algorithm;

  switch (algorithm) {
  case Algorithm_OTP: {
    return xq_otp_encrypt_file_start(in_file_path,out_file_path, token_data, key.data,
                                     stream_info, error);
  } break;
  
  case Algorithm_FIPS:{
    return xq_fips_encrypt_file_start(in_file_path,out_file_path, token_data, key.data,
                                     stream_info, error);
  } break;
  
  case Algorithm_AES: {
    return xq_aes_encrypt_file_start(in_file_path,out_file_path, token_data, key.data,
                                     stream_info, error);
  } break;
  
  
  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }

    return 0;
  }

  return 0;
}

size_t xq_encrypt_file_step(struct xq_file_stream *stream_info, uint8_t *data,
                           size_t data_length, struct xq_error_info *error) {

  switch (stream_info->algorithm) {
  case Algorithm_OTP:
    return xq_otp_encrypt_file_step(stream_info, data, data_length, error);

  case Algorithm_AES:
    return xq_aes_encrypt_file_step(stream_info, data, data_length, error);
    
  case Algorithm_FIPS:
    return xq_fips_encrypt_file_step(stream_info, data, data_length, error);

  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }
    return 0;
  }
}

_Bool xq_encrypt_file_end(struct xq_file_stream *stream_info,struct xq_error_info *error) {

  switch (stream_info->algorithm) {
  case Algorithm_OTP:
    return xq_otp_encrypt_file_end(stream_info, error);

  case Algorithm_AES:
     return xq_aes_encrypt_file_end(stream_info, error);
     
  case Algorithm_FIPS:
    return xq_fips_encrypt_file_end(stream_info, error);

  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }
    return 0;
  }
}
