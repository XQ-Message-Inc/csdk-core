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
#include <xq/algorithms/nist/nist_encrypt.h>
#include <xq/services/sub/packet.h>

enum algorithm_type xq_algorithm_from_token(const char* token){
    if (token == 0 || strlen(token) < 2 || token[1] != '.') return Algorithm_OTP;
    switch(token[0]){
       case 'X': return Algorithm_OTP;
       case 'A': return Algorithm_AES;
       case 'D': return Algorithm_AES_Strong;
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
  uint32_t token_length = 0;
  int bytes_read = fread(&token_length, sizeof(uint32_t), 1, in_fp);

  if (bytes_read <= 0 || token_length == 0) {
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

  enum algorithm_type algorithm = xq_algorithm_from_token(token);

  switch (algorithm) {
  case Algorithm_OTP: {
    return xq_otp_encrypt_file(in_file_path, out_file_path, token, key, error);
  } break;
  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }

    return 0;
  }
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
    success = xq_key_to_hex(&quantum, &key, 'X');
  } break;
  case Algorithm_AES: {
    success = xq_key_to_hex(&quantum, &key, 'A');
  } break;
  case Algorithm_AES_Strong: {
    success = xq_key_to_hex(&quantum, &key, 'D');
  }

  break;
  case Algorithm_NIST: {
    success = xq_key_to_hex(&quantum, &key, 'N');
  } break;
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

  switch (algorithm) {
  case Algorithm_OTP:
    success = xq_otp_encrypt_file(in_file_path, out_file_path,
                                  (char *)message_token.data, key.data, error);
    break;

  default:
    if (error) {
      sprintf(error->content, "This algorithm is not currently supported.");
      error->responseCode = -1;
    }
    xq_destroy_hex_quantum_key(&key);

    return 0;
  }

  xq_destroy_hex_quantum_key(&key);

  return 1;
}
