//  A slightly simplified version of the starter tutorial for testing encryption
//  functionality. Unlike the starter tutorial, this runs without needing any
//  user input. test.c test
//
//

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xq/xq.h>

// If you do not care about testing FIPS, or do not have a FIPS enabled build
// of OpenSSL 3.x, set this flag to 0.
#define FIPS_ENABLED 1

int get_file_contents(const char *filepath, uint8_t **out) {
  if (out == 0) {
    fprintf(stderr, "[get_file_contents] out varable for storing file content "
                    "must be defined.");
    return 0;
  }
  FILE *fp = fopen(filepath, "rb");
  if (fp == 0) {
    fprintf(stderr, "[get_file_contents] Failed to open target file");
    return 0;
  }
  fseek(fp, 0, SEEK_END);
  int length = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  *out = calloc(sizeof(uint8_t), length);
  int bytes_read = fread(*out, 1, length, fp);
  fclose(fp);
  if (bytes_read < length) {
    fprintf(stderr, "[get_file_contents]File was not fully read");
    free(*out);
    return 0;
  }

  return bytes_read;
}

_Bool dataLoop(struct xq_config *cfg, const char *recipients,
                     const char *message, int algorithm) {

  struct xq_message_payload result = {0, 0};
  struct xq_error_info err = {0};
  const char *meta_content = "{\"subject\":\"My C SDK Test Message\"}";
  struct xq_metadata meta = xq_use_metadata(Metadata_Email, meta_content);
  
  struct timeval begin, end;
  gettimeofday(&begin, 0);

  if (!xq_encrypt_and_store_token(
          cfg,                // XQ Configuration object
          algorithm,          // The algorithm to use for encryption
          (uint8_t *)message, // The message to encrypt.
          strlen(message),    // The length of the message ( in bytes )
          256,                // The number entropy bytes to use.
          0,                  // Entropy pool to use ( 0 if none ).
          recipients, // The accounts that will be able to read this message.
          24,         // The number of hours this message will be available
          0,          // Prevent this message from being read more than once?
          &meta, &result, &err)) {
    fprintf(stderr, "[xq_encrypt_and_store_token] %li: %s\n", err.responseCode,
            err.content);
    return 0;
  }

  // Stop measuring time and calculate the elapsed time
  gettimeofday(&end, 0);
  long seconds = end.tv_sec - begin.tv_sec;
  long microseconds = end.tv_usec - begin.tv_usec;
  double elapsed = seconds + microseconds * 1e-6;
  printf("Encryption done. Time measured: %.3f seconds.\n\n", elapsed);
  
  
  struct xq_message_payload encoded = {0, 0};
  xq_base64_payload(&result, &encoded);
  // Display the encrypted message.
  printf("-- Encrypted Message: %s\n", encoded.data);
  // Display the XQ locator token.
  printf("-- Token: %s\n", result.token_or_key);
  xq_destroy_payload(&encoded);

  // The encrypted message should be exactly the same as
  // the one originally generated.
  struct xq_message_payload decrypted = {0, 0};
  
  gettimeofday(&begin, 0);

  if (!xq_decrypt_with_token(
          cfg, Algorithm_Autodetect,
          result.data,         // The encrypted payload
          result.length,       // The length of the encrypted payload
          result.token_or_key, // The XQ locator token
          &decrypted, &err)) {
    fprintf(stderr, "[xq_decrypt_with_token] %li: %s\n", err.responseCode,
            err.content);
    xq_destroy_payload(&result);
    return 0;
  }

    // Stop measuring time and calculate the elapsed time
  gettimeofday(&end, 0);
  seconds = end.tv_sec - begin.tv_sec;
  microseconds = end.tv_usec - begin.tv_usec;
  elapsed = seconds + microseconds * 1e-6;
  printf("Decryption done. Time measured: %.3f seconds.\n\n", elapsed);
  
  // Success. The message has been successfully encrypted.
  printf("-- Decrypted:%s\n", decrypted.data);

  // Attempt grant another user accesss
  const char *alt_recipients[] = {"fake_user@email.com"};

  if (!xq_svc_grant_access(cfg, result.token_or_key, alt_recipients, 1, &err)) {
    fprintf(stderr, "[xq_svc_grant_access] %li: %s\n", err.responseCode,
            err.content);
    xq_destroy_payload(&result);
    return 0;
  }
  printf("-- Granted alternate user access.\n");

  // Revoke the new users access.
  if (!xq_svc_revoke_access(cfg, result.token_or_key, alt_recipients, 1,
                            &err)) {
    fprintf(stderr, "[xq_svc_revoke_access] %li: %s\n", err.responseCode,
            err.content);
    xq_destroy_payload(&result);
    return 0;
  }
  printf("-- Revoked alternate user access.\n");

  // Revoke the entire message.
  if (!xq_svc_remove_key(cfg, result.token_or_key, &err)) {
    fprintf(stderr, "[xq_svc_remove_key] %li: %s\n", err.responseCode,
            err.content);
    xq_destroy_payload(&result);
    return 0;
  }
  printf("-- Revoked key.\n");

  xq_destroy_payload(&decrypted);
  xq_destroy_payload(&result);
  return 1;
}

int testFileEncryption(int argc, const char *argv[]) {

  if (argc < 3) {
    fprintf(stderr, "Usage: test CONFIG_FILE_INI USER_ALIAS\n");
    exit(EXIT_FAILURE);
  }

  // 1. SDK Initialization
  const char *config_file = argc > 1 ? argv[1] : "xq.ini";
  struct xq_config cfg = xq_init(config_file);
  if (!xq_is_valid_config(&cfg)) {
    // If something went wrong, call this to clean up
    // any memory that was possibly allocated.
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  // 2. Create Quantum Pool
  struct xq_error_info err = {0};

  // 3. Authenticate a user.
  const char *email_address = argv[2];
  
  // Test a trusted destination:
    // To test this block, enter a valid secure key for a trusted domain, along with the workspace ID.
    /*
    const char* secure_key = "YOUR_TRUSTED_RANGE_SECURE_KEY";
    if  (!xq_svc_authorize_trusted( &cfg, email_address, "TEAM_ID", secure_key, "YOUR_DEVICE_NAME", &err )) {
        fprintf(stderr, "[xq_svc_authorize_trusted] %li : %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    printf( "Trusted Account Authorized\n" );
    */

  // If a real email address was set.
  if (!xq_svc_authorize_alias(&cfg, email_address, &err)) {
    fprintf(stderr, "[xq_svc_authorize_alias] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  printf("Alias Account authorized.\n");

  // Test file encryption
  struct xq_message_payload result = {0, 0};


  const char source_file[] = "/path/to/target/file";
  const char output_file[] = "/path/to/desired/output/file";
  const char decrypted_file[] = "/path/to/desired/decrypted/file";

  unlink(decrypted_file);
  unlink(output_file);


  const int CHUNK_SIZE = 8192;

  FILE *source_fp = fopen(source_file, "rb");
  fseek(source_fp, 0, SEEK_END);
  size_t source_size = ftell(source_fp);
  fseek(source_fp, 0, SEEK_SET);
  uint8_t source_data_chunk[CHUNK_SIZE];
  memset(source_data_chunk, 0, CHUNK_SIZE);

  fprintf(stdout, "Actual file size is : %li\n", source_size);

  struct xq_file_stream info;

  info.native_handle = open(output_file, O_RDWR | O_CREAT | O_TRUNC, 0777);
  if (info.native_handle == -1) {
    perror("open");
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  fprintf(stdout, "Now encrypting, please wait...\n");

  _Bool success = xq_encrypt_file_start(
      &cfg, source_file, output_file, Algorithm_OTP, 512, 0,
      "xq.public", 12, 0, &info, &err);

  if (!success) {
    fprintf(stderr, "[xq_encrypt_file_start] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  // Write into stream
  long data_offset = 0;

  struct timeval begin, end;
  gettimeofday(&begin, 0);

  while (data_offset < source_size) {
    size_t chunk = source_size - data_offset;
    if (chunk > CHUNK_SIZE)
      chunk = CHUNK_SIZE;
    memset(source_data_chunk, 0, CHUNK_SIZE);
    chunk = fread(source_data_chunk, 1, chunk, source_fp);
    int read = xq_encrypt_file_step(&info, source_data_chunk, chunk, &err);
    data_offset += read;
  }

  fclose(source_fp);

  // Close native handle
  close(info.native_handle);

  if (info.key)
    free(info.key);

  // Close stream
  if (!xq_encrypt_file_end(&info, &err)) {
    fprintf(stderr, "[xq_encrypt_file_end] %li : %s\n", err.responseCode,
            err.content);
    return 0;
  }

  // Stop measuring time and calculate the elapsed time
  gettimeofday(&end, 0);
  long seconds = end.tv_sec - begin.tv_sec;
  long microseconds = end.tv_usec - begin.tv_usec;
  double elapsed = seconds + microseconds * 1e-6;
  printf("Encryption done. Time measured: %.3f seconds.\n\n", elapsed);

  fprintf(stdout, "Now decrypting, please wait...\n");

  gettimeofday(&begin, 0);

  // Test streaming reads
  memset(&info, 0, sizeof(info));
  if (!xq_decrypt_file_start(&cfg, output_file, &info, &err)) {
    fprintf(stderr, "[xq_decrypt_file_start] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  FILE *clone_fp = fopen(decrypted_file, "wb");
  FILE *old_fp = info.fp;
  info.native_handle = fileno(info.fp);
  info.fp = 0;

  uint8_t chunk_content[CHUNK_SIZE] = {0};
  data_offset = 0;

  int bytes_read = xq_decrypt_file_step(&info, chunk_content, CHUNK_SIZE);
  int written = 0;

  if (bytes_read > 0) {
    do {
      written += fwrite(chunk_content, 1, bytes_read, clone_fp);
      bytes_read = xq_decrypt_file_step(&info, chunk_content, CHUNK_SIZE);
    } while (bytes_read > 0);
  }
  info.fp = old_fp;
  xq_decrypt_file_end(&info);
  fclose(clone_fp);


  gettimeofday(&end, 0);
  seconds = end.tv_sec - begin.tv_sec;
  microseconds = end.tv_usec - begin.tv_usec;
  elapsed = seconds + microseconds * 1e-6;
  printf("Decryption done. Time measured: %.3f seconds.\n\n", elapsed);

  return 0;
}

int testDataEncryption(int argc, const char *argv[]) {

  if (argc < 3) {
    fprintf(stderr, "Usage: test CONFIG_FILE_INI USER_ALIAS\n");
    exit(EXIT_FAILURE);
  }

  // 1. SDK Initialization
  const char *config_file = argc > 1 ? argv[1] : "xq.ini";
  struct xq_config cfg = xq_init(config_file);
  if (!xq_is_valid_config(&cfg)) {
    // If something went wrong, call this to clean up
    // any memory that was possibly allocated.
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  struct xq_error_info err = {0};
  const char *email_address = argv[2];
  

  // 3. Authenticate an alias user.
  if (!xq_svc_authorize_alias(&cfg, email_address, &err)) {
    fprintf(stderr, "[xq_svc_authorize_alias] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  printf("Alias Account authorized.\n");

  // Retrieving your access token
  const char *access_token = xq_get_access_token(&cfg);
  if (!access_token) {
    fprintf(stderr, "[xq_get_access_token] Failed to get access token.\n");
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  char *token = strdup(access_token);

  if (!xq_set_access_token(&cfg, token)) {
    fprintf(stderr, "[xq_set_access_token] Failed to reset access token.\n");
    free(token);
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  printf("Current Access Token: %s\n", token);

  free(token);

  // Retrieve information about this user.
  struct xq_subscriber_info info = {0};
  if (!xq_svc_get_subscriber(&cfg, &info, &err)) {
    fprintf(stderr, "[xq_svc_get_subscriber] %li: %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  // 6. Test OTP a new message
  const char *message = "Hello World From John Doe";
  printf("Encrypting message: %s...\n", message);
  _Bool res;
  

  res = dataLoop(&cfg, info.mailOrPhone, message, Algorithm_OTP);
  printf("OTP Encryption: %s.\n", res ? "OK" : "Failed");
  
  if (FIPS_ENABLED) {
      // Enable super secure mode.
      if (xq_enable_fips(&cfg, NULL)){
      
        for (int x = 0; x < 10; ++ x){
            res = dataLoop(&cfg, info.mailOrPhone, message, Algorithm_AES_Strong);
            printf("AES Encryption (SHA 256, 100K Rounds FIPS): %s.\n", res ? "OK" : "Failed");
            if (!res) {
                xq_destroy_config(&cfg);
                exit(EXIT_FAILURE);
            }
        }
        xq_disable_fips(&cfg);
      }
  }
  
  else {
    res = dataLoop(&cfg, info.mailOrPhone, message, Algorithm_AES);
    printf("AES Encryption (SHA 256): %s.\n", res ? "OK" : "Failed");
    res = dataLoop(&cfg, info.mailOrPhone, message, Algorithm_AES_Strong);
    printf("AES Encryption (SHA 256, 100K Rounds): %s.\n", res ? "OK" : "Failed");
  }
  
  // Cleanup
  xq_destroy_config(&cfg);

  printf("Finished OK.\n");

  return 0;
}

int main(int argc, const char *argv[]) {
    
    testDataEncryption(argc, argv);
    //testFileEncryption(argc, argv);
  
}
