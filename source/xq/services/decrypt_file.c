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
#include <xq/algorithms/fips/fips_decrypt.h>
#include <string.h>

#define STREAM_CHUNK_SIZE 8192

_Bool xq_decrypt_file(struct xq_config *config, const char *in_file_path,
                      const char *out_file_dir,
                      struct xq_message_payload *resulting_file_path,
                      struct xq_error_info *error) {

  // 1. get the token and algorithm.
  char token_data[64] = {0};
  struct xq_message_token token = {token_data, sizeof(token_data)};
  if (!xq_get_file_token(config, in_file_path, &token, error)) {
    return 0;
  }

  // 2. Fetch the token from the server.
  char keyBits[MAX_QUANTUM_SIZE * 2] = {0};
  struct xq_key key = {keyBits, sizeof(keyBits)};

  _Bool success = xq_svc_get_key(config, token.data, &key, error);

  if (!success) {
    return 0;
  }

  struct xq_file_stream stream_info = {0};

  // 3. Decrypt using the key and token.
  enum algorithm_type algorithm = algorithm_from_key(key.data);

  decrypt_file_start_type _start = 0;
  decrypt_file_step_type _step = 0;
  decrypt_file_end_type _end = 0;

  switch (algorithm) {
  case Algorithm_OTP:
    _start = xq_otp_decrypt_file_start;
    _step = xq_otp_decrypt_file_step;
    _end = xq_otp_decrypt_file_end;
    break;

  case Algorithm_AES:
    _start = xq_aes_decrypt_file_start;
    _step = xq_aes_decrypt_file_step;
    _end = xq_aes_decrypt_file_end;
    break;
    
  case Algorithm_FIPS:
    _start = xq_fips_decrypt_file_start;
    _step = xq_fips_decrypt_file_step;
    _end = xq_fips_decrypt_file_end;
    break;

  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }
    return 0;
  }

  stream_info.algorithm = algorithm;

  // Open file for decryption.
  if (!_start(key.data, in_file_path, &stream_info, error)) {
    return 0;
  }

  //---------------

  long written = 0;
  long data_index = 0;

  char out_file_path[512] = {0};

  if (out_file_dir[strlen(out_file_dir) - 1] == '/') {
    sprintf(out_file_path, "%s%s", out_file_dir, stream_info.filename);
  } else {
    sprintf(out_file_path, "%s", out_file_dir);
  }

  // Open the output file
  if (resulting_file_path) {
    uint32_t len = strlen(out_file_path);
    if (resulting_file_path->data) {
      if (resulting_file_path->length < len) {
        memcpy(resulting_file_path->data, out_file_path,
               resulting_file_path->length);
      }
      memcpy(resulting_file_path->data, out_file_path, len);
      resulting_file_path->length = len;
    } else {
      resulting_file_path->length = len;
      resulting_file_path->data = (uint8_t *)strdup(out_file_path);
    }
  }

  FILE *out_fp = fopen(out_file_path, "wb");
  if (!out_fp) {
    perror("fopen");
    if (error) {
      sprintf(error->content, "Output file %s fould not be opened",
              stream_info.filename);
      error->responseCode = -1;
    }
    _end(&stream_info, error);
    return 0;
  }

  //---------------------

  uint8_t out_buffer[STREAM_CHUNK_SIZE];
  _Bool has_more = 1;
  int count_index = 0;
  do {
    int count_read = _step(&stream_info, out_buffer, STREAM_CHUNK_SIZE, error);
    has_more = count_read == sizeof(out_buffer);
    if (count_read > 0) {
      fwrite(out_buffer, 1, count_read, out_fp);
    }
  } while (has_more);

  fclose(out_fp);
  _end(&stream_info, error);
  return 1;
}

_Bool xq_decrypt_file_start(struct xq_config *config, const char *in_file_path,
                            struct xq_file_stream *stream_info,
                            struct xq_error_info *error) {

  // 1. get the token and algorithm.
  char token_data[64] = {0};
  struct xq_message_token token = {token_data, sizeof(token_data)};
  if (!xq_get_file_token(config, in_file_path, &token, error)) {
    return 0;
  }

  // 2. Fetch the token from the server.
  char keyBits[MAX_QUANTUM_SIZE * 2] = {0};
  struct xq_key key = {keyBits, sizeof(keyBits)};

  _Bool success = xq_svc_get_key(config, token.data, &key, error);

  if (!success) {
    return 0;
  }

  // 3. Decrypt using the key and token.
  enum algorithm_type algorithm = algorithm_from_key(key.data);
  if (stream_info)
    stream_info->algorithm = algorithm;

  switch (algorithm) {

  case Algorithm_OTP:
    return xq_otp_decrypt_file_start(key.data, in_file_path, stream_info,
                                     error);
    break;

  case Algorithm_AES:
    return xq_aes_decrypt_file_start(key.data, in_file_path, stream_info,
                                     error);
    break;
    
  case Algorithm_FIPS:
    return xq_fips_decrypt_file_start(key.data, in_file_path, stream_info,
                                     error);
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

size_t xq_decrypt_file_step(struct xq_file_stream *stream_info, uint8_t *data,
                            size_t data_length, struct xq_error_info *error) {
  switch (stream_info->algorithm) {
  case Algorithm_OTP:
    return xq_otp_decrypt_file_step(stream_info, data, data_length, error);
    
  case Algorithm_AES:
    return xq_aes_decrypt_file_step(stream_info, data, data_length, error);
    
  case Algorithm_FIPS:
    return xq_fips_decrypt_file_step(stream_info, data, data_length, error);
  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }
  }
  return 0;
}

_Bool xq_decrypt_file_end(struct xq_file_stream *stream_info,
                          struct xq_error_info *error) {

  switch (stream_info->algorithm) {
  case Algorithm_OTP:
    return xq_otp_decrypt_file_end(stream_info, error);
  case Algorithm_AES:
    return xq_aes_decrypt_file_end(stream_info, error);
  case Algorithm_FIPS:
    return xq_fips_decrypt_file_end(stream_info, error);
  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }
  }
  return 0;
}

long xq_get_real_file_size(struct xq_config *config, const char *in_file_path,
                           struct xq_error_info *error) {

  FILE *in_fp = fopen(in_file_path, "rb");
  if (in_fp == 0) {
    if (error) {
      sprintf(error->content, "Failed to open file: %s", in_file_path);
      error->responseCode = -1;
    }
    return -1;
  }

  // 2. Read the length of the file token.
  uint32_t token_length = 0, name_length = 0;
  fread(&token_length, sizeof(uint32_t), 1, in_fp);
  if (token_length == -1) {
    fclose(in_fp);
    return -1;
  }
  fseek(in_fp, token_length, SEEK_CUR);

  // Read the length of the filename.
  fread(&name_length, sizeof(uint32_t), 1, in_fp);

  long header_len = (sizeof(uint32_t) * 2) + name_length + token_length;
  fseek(in_fp, 0, SEEK_END);
  long sz = ftell(in_fp) - header_len;
  fclose(in_fp);
  return sz;
}
