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

/// Testing options
enum test_options { test_speed = 1, test_files = 2, test_roundtrip = 4 };

/// User Options
struct user_options {
  char *config_path;
  uint16_t tests;
  int test_count;
  char *user_email;
  enum algorithm_type *algorithms;
  int algorithm_count;
  char *target_file;
  char *testing_dir;
  long file_kbps;
  _Bool fips_enabled;
};

/// Create a zero'ed out user options object.
struct user_options create_user_options() {
  struct user_options opts = {0};
  return opts;
}

/// Destroy a user options object
/// - Parameter opts: User options object.
void destroy_user_options(struct user_options *opts) {
  if (opts->config_path)
    free(opts->config_path);
  if (opts->user_email)
    free(opts->user_email);
  if (opts->algorithms)
    free(opts->algorithms);
  if (opts->testing_dir)
    free(opts->testing_dir);
  if (opts->target_file)
    free(opts->target_file);

  memset(opts, 0, sizeof(struct user_options));
}

/// Load XQ configuration file
/// - Parameters:
///   - argc: Number of user arguments
///   - argv: List of arguments
struct xq_config load_config(struct user_options *opts) {

  // Config Initialization
  struct xq_config cfg = xq_init(opts->config_path);
  if (!xq_is_valid_config(&cfg)) {
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  // 2. Create Quantum Pool
  struct xq_error_info err = {0};

  // Test a trusted destination:
  // If a real email address was set.
  if (!xq_svc_authorize_alias(&cfg, opts->user_email, &err)) {
    fprintf(stderr, "[xq_svc_authorize_alias] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }

  printf("Alias Account authorized.\n");
  return cfg;
}

/// Runs through a full encryption and decryption flow for a sample message,
/// against the XQ server specified by the users configuration.
///
/// - Parameters:
///   - cfg: The configuration object
///   - recipients: The message recipients
///   - message: The test message content
///   - algorithm: The encryption algorithm to use.
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

/// Test file encryption when streaming individual chunks
/// - Parameters:
///   - opts:User options
///   - algorithm: The desired encryption algorithm
int testStreamingFileEncryption(struct user_options *opts,
                                enum algorithm_type algorithm) {

  printf("**** TESTING STREAMING FILE ENCRYPTION (%s) ****\n",
         algorithm_to_string(algorithm));

  struct xq_config cfg = load_config(opts);
  struct xq_error_info err = {0};

  // Enable FIPS if required.
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  if (opts->fips_enabled && algorithm == Algorithm_AES)
    xq_enable_fips(&cfg, NULL);
#endif

  // Test file encryption
  struct xq_message_payload result = {0, 0};

  char source_file[255] = {0};
  char output_file[255] = {0};
  char decrypted_file[255] = {0};

  sprintf(source_file, "%s/%s", opts->testing_dir, opts->target_file);
  sprintf(output_file, "%s/%s/stream_%s.xqf", opts->testing_dir,
          algorithm_to_string(algorithm), opts->target_file);
  sprintf(decrypted_file, "%s/%s/stream_%s", opts->testing_dir,
          algorithm_to_string(algorithm), opts->target_file);

  unlink(decrypted_file);
  unlink(output_file);

  const int CHUNK_SIZE = 8192;

  FILE *source_fp = fopen(source_file, "rb");
  if (source_fp == 0) {
    perror("fopen");
    xq_destroy_config(&cfg);
    exit(EXIT_FAILURE);
  }
  fseek(source_fp, 0, SEEK_END);
  size_t source_size = ftell(source_fp);
  fseek(source_fp, 0, SEEK_SET);
  uint8_t source_data_chunk[CHUNK_SIZE];
  memset(source_data_chunk, 0, CHUNK_SIZE);

  fprintf(stdout, "Actual file size is : %li\n", source_size);

  struct xq_file_stream info = {0};

  info.native_handle = open(output_file, O_RDWR | O_CREAT | O_TRUNC, 0777);
  if (info.native_handle == -1) {
    perror("open");
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }

  fprintf(stdout, "Now encrypting, please wait...\n");

  // Write into stream
  long data_offset = 0;

  struct timeval begin, end;
  gettimeofday(&begin, 0);

  _Bool success =
      xq_encrypt_file_start(&cfg, source_file, output_file, algorithm, 512, 0,
                            "xq.public", 12, 0, &info, &err);

  if (!success) {
    fprintf(stderr, "[xq_encrypt_file_start] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }

  while (data_offset < source_size) {
    size_t chunk = source_size - data_offset;
    if (chunk > CHUNK_SIZE)
      chunk = CHUNK_SIZE;
    // memset(source_data_chunk, 0, CHUNK_SIZE);
    chunk = fread(source_data_chunk, 1, chunk, source_fp);
    int read = xq_encrypt_file_step(&info, source_data_chunk, chunk, &err);
    data_offset += read;
  }

  // Close stream
  if (!xq_encrypt_file_end(&info, &err)) {
    fprintf(stderr, "[xq_encrypt_file_end] %li : %s\n", err.responseCode,
            err.content);
    return 0;
  }

  fclose(source_fp);

  if (info.key)
    free(info.key);

  // Close native handle
  close(info.native_handle);

  // Stop measuring time and calculate the elapsed time
  gettimeofday(&end, 0);
  long seconds = end.tv_sec - begin.tv_sec;
  long microseconds = end.tv_usec - begin.tv_usec;
  double elapsed = seconds + microseconds * 1e-6;
  printf("Encryption done. Time measured: %.3f seconds.\n\n", elapsed);
  
  fprintf(stdout, "Detected real size: %li\n", xq_get_real_file_size(&cfg, output_file, &err));

  fprintf(stdout, "Now decrypting, please wait...\n");

  gettimeofday(&begin, 0);

  // Test streaming reads
  memset(&info, 0, sizeof(info));
  if (!xq_decrypt_file_start(&cfg, output_file, &info, &err)) {
    fprintf(stderr, "[xq_decrypt_file_start] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }

  FILE *clone_fp = fopen(decrypted_file, "wb");
  FILE *old_fp = info.fp;
  info.native_handle = fileno(info.fp);
  info.fp = 0;

  uint8_t chunk_content[CHUNK_SIZE] = {0};
  data_offset = 0;

  int bytes_read = xq_decrypt_file_step(&info, chunk_content, CHUNK_SIZE, &err);
  int written = 0;

  if (bytes_read > 0) {
    do {
      written += fwrite(chunk_content, 1, bytes_read, clone_fp);
      bytes_read = xq_decrypt_file_step(&info, chunk_content, CHUNK_SIZE, &err);
    } while (bytes_read > 0);
  } else {
    fprintf(stderr, "[xq_decrypt_file_step] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }
  info.fp = old_fp;
  xq_decrypt_file_end(&info, &err);
  fclose(clone_fp);

  gettimeofday(&end, 0);
  seconds = end.tv_sec - begin.tv_sec;
  microseconds = end.tv_usec - begin.tv_usec;
  elapsed = seconds + microseconds * 1e-6;
  printf("Decryption done. Time measured: %.3f seconds.\n\n", elapsed);
  
  FILE *target_fp = fopen(decrypted_file, "rb");
  fseek(target_fp, 0, SEEK_END);
  size_t target_size = ftell(target_fp);
  fclose(target_fp);
  
  assert(source_size == target_size);
  
  
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  if (opts->fips_enabled && algorithm == Algorithm_AES)
    xq_disable_fips(&cfg);
#endif

  return 0;
}

/// Test file encryption directly from disk
/// - Parameters:
///   - opts:User options
///   - algorithm: The desired encryption algorithm
int testStaticFileEncryption(struct user_options *opts,
                             enum algorithm_type algorithm) {

  fprintf(stdout, "*********** STATIC FILE ENCRYPTION (%s) ****************\n",
          algorithm_to_string(algorithm));

  struct xq_config cfg = load_config(opts);
  struct xq_error_info err = {0};

  // Enable FIPS if required.
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  if (algorithm == Algorithm_AES)
    xq_enable_fips(&cfg, NULL);
#endif

  // Test file encryption
  struct xq_message_payload result = {0, 0};

  char source_file[255] = {0};
  char output_file[255] = {0};
  char decrypted_file[255] = {0};

  sprintf(source_file, "%s/%s", opts->testing_dir, opts->target_file);
  sprintf(output_file, "%s/%s/static_%s.xqf", opts->testing_dir,
          algorithm_to_string(algorithm), opts->target_file);
  sprintf(decrypted_file, "%s/%s/static_%s", opts->testing_dir,
          algorithm_to_string(algorithm), opts->target_file);

  unlink(decrypted_file);
  unlink(output_file);

  struct xq_quantum_pool pool = {0};

  if (!xq_init_pool(&cfg, 2048, &pool, &err)) {
    fprintf(stderr, "[xq_init_pool] %li : %s\n", err.responseCode, err.content);
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }

  FILE *source_fp = fopen(source_file, "rb");
  fseek(source_fp, 0, SEEK_END);
  size_t source_size = ftell(source_fp);
  fseek(source_fp, 0, SEEK_SET);
  fclose(source_fp);
  fprintf(stdout, "Actual file size is : %li\n", source_size);

  fprintf(stdout, "Now encrypting, please wait...\n");

  struct timeval begin, end;
  gettimeofday(&begin, 0);

  if (!xq_encrypt_file_and_store_token(&cfg, algorithm, source_file,
                                       output_file, 512, &pool, "xq.public", 24,
                                       0, &err)) {
    fprintf(stderr, "[xq_encrypt_file_and_store_token] %li : %s\n",
            err.responseCode, err.content);
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }

  // Stop measuring time and calculate the elapsed time
  gettimeofday(&end, 0);
  long seconds = end.tv_sec - begin.tv_sec;
  long microseconds = end.tv_usec - begin.tv_usec;
  double elapsed = seconds + microseconds * 1e-6;
  printf("Encryption done. Time measured: %.3f seconds.\n\n", elapsed);

  fprintf(stdout, "Now decrypting, please wait...\n");

  gettimeofday(&begin, 0);

  if (!xq_decrypt_file(&cfg, output_file, decrypted_file, 0, &err)) {
    fprintf(stderr, "[xq_decrypt_file] %li : %s\n", err.responseCode,
            err.content);
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }

  gettimeofday(&end, 0);
  seconds = end.tv_sec - begin.tv_sec;
  microseconds = end.tv_usec - begin.tv_usec;
  elapsed = seconds + microseconds * 1e-6;
  printf("Decryption done. Time measured: %.3f seconds.\n\n", elapsed);
  
  FILE *target_fp = fopen(decrypted_file, "rb");
  fseek(target_fp, 0, SEEK_END);
  size_t target_size = ftell(target_fp);
  fclose(target_fp);
  
  assert(source_size == target_size);
  
  // Assert that the resulting file is the same size as the original
  
  
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  if (opts->fips_enabled && algorithm == Algorithm_AES)
    xq_disable_fips(&cfg);
#endif

  return 0;
}

/// Test encryption and decryption flow.
/// - Parameters:
///   - opts: User options
///   - algorithm: The desired encryption algorithm
int testDataEncryption(struct user_options *opts,
                       enum algorithm_type algorithm) {

  printf("\n\n**** TESTING DATA ENCRYPTION (%s) ****\n",
         algorithm_to_string(algorithm));

  struct xq_config cfg = load_config(opts);
  struct xq_error_info err = {0};

  // Enable FIPS if required.
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  if (opts->fips_enabled && algorithm == Algorithm_AES)
    xq_enable_fips(&cfg, NULL);
#endif

  // Retrieving your access token
  const char *access_token = xq_get_access_token(&cfg);
  if (!access_token) {
    fprintf(stderr, "[xq_get_access_token] Failed to get access token.\n");
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }

  char *token = strdup(access_token);

  if (!xq_set_access_token(&cfg, token)) {
    fprintf(stderr, "[xq_set_access_token] Failed to reset access token.\n");
    free(token);
    xq_destroy_config(&cfg);
    destroy_user_options(opts);
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
    destroy_user_options(opts);
    exit(EXIT_FAILURE);
  }

  // 6. Test OTP a new message
  const char *message = "Hello World From John Doe how are you doing?";
  printf("Encrypting message: %s...\n", message);
  _Bool res;

  for (int x = 0; x < 1; ++x) {
    res = dataLoop(&cfg, info.mailOrPhone, message, algorithm);
    printf("%s Encryption: %s.\n", algorithm_to_string(algorithm),
           res ? "OK" : "Failed");
  }

  // Cleanup
  xq_destroy_config(&cfg);

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  if (opts->fips_enabled && algorithm == Algorithm_AES)
    xq_disable_fips(&cfg);
#endif

  printf("Finished OK.\n");

  return 0;
}

/// Test the speed of the encryption algorithm alone
/// - Parameters:
///   - opts: User options
///   - algorithm: The desired encryption algorithm
int testEncryptionSpeed(struct user_options *opts,
                        enum algorithm_type algorithm) {

  printf("\n\n**** TESTING ENCRYPTION SPEED (%s)****\n",
         algorithm_to_string(algorithm));

  struct xq_config cfg = load_config(opts);
  struct xq_error_info err = {0};

  // 1kb message
  const char messageContent[] =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
      "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
      "veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
      "commodo consequat. Duis aute irure dolor in reprehenderit in voluptate "
      "velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint "
      "occaecat cupidatat non proident, sunt in culpa qui officia deserunt "
      "mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur "
      "adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore "
      "magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation "
      "ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute "
      "irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
      "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, "
      "sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem "
      "ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
      "tempor incididunt ut labore et dolore magna aliqua. Ut enim!";

  // Enable FIPS if required.
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  if (opts->fips_enabled && algorithm == Algorithm_AES)
    xq_enable_fips(&cfg, NULL);
#endif

  // 32 byte message
  printf("Encrypting message (%i bytes, %li rounds)...\n", (int)sizeof(messageContent), opts->file_kbps);
  _Bool res;

  // Create context.
  uint8_t key_data[] = {"ABCDEFGHIJKLMNOP1234560LMK@XYQ!!"};
  int key_data_len = sizeof(key_data);
  uint8_t salt[] = {"12345678"};

  void *my_context =
      xq_create_enc_ctx(algorithm, key_data, key_data_len, salt, &err);

  uint8_t buffer[sizeof(messageContent) << 1] = {0};
  struct xq_message_payload result = {buffer, sizeof(buffer)};
  printf("Starting %s Direct Encryption w/ Context.\n",
         algorithm_to_string(algorithm));

  struct timeval begin, end;
  gettimeofday(&begin, 0);

  int x = 0;
  long completed = sizeof(messageContent) * opts->file_kbps;
  // Attempt to encrypt 100MB
  for (x = 0; x < opts->file_kbps; ++x) {
    result.length = sizeof(buffer);
    res = xq_encrypt_with_key(algorithm, (uint8_t *)messageContent,
                                    sizeof(messageContent), (char *)key_data,
                                    &result, my_context, &err);
    if (!res) {
      destroy_user_options(opts);
      exit(EXIT_FAILURE);
    }
  }

  gettimeofday(&end, 0);
  long seconds = end.tv_sec - begin.tv_sec;
  long microseconds = end.tv_usec - begin.tv_usec;
  double elapsed = seconds + microseconds * 1e-6;
  long size = printf(
      "Encryption w/context done (%.2f MB). Time measured: %.3f seconds.\n\n",
      (double)completed / 1024000.0, elapsed);

  // Cleanup
  xq_destroy_enc_ctx(algorithm, my_context);

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
  if (opts->fips_enabled && algorithm == Algorithm_AES)
    xq_disable_fips(&cfg);
#endif

  return 0;
}

/// Main test routine
/// - Parameters:
///   - argc: Number of arguments
///   - argv: argument list
int main(int argc, const char *argv[]) {

  srand(time(0));

  // test -c /path/to/fuse.ini -t speed;files;roundtrip -d /path/to/testing/dir
  // -f two_bucks.zip -a AES;OTP

  struct user_options opts = create_user_options();

  // Number of 1024 blocks for testing encryption speed ( 1000000 = 1GB )
  opts.file_kbps = 1000000;

  char tokenized_content[255] = {0};
  // Read the program options
  int value_idx = -1;
  for (int i = 1; i < argc; i += 2) {
    value_idx = i + 1;
    if (argc > value_idx) {
      if (strncmp(argv[i], "-c", 2) == 0) {
        opts.config_path = strdup(argv[value_idx]);
      } else if (strncmp(argv[i], "-d", 2) == 0) {
        opts.testing_dir = strdup(argv[value_idx]);
      } else if (strncmp(argv[i], "-f", 2) == 0) {
        opts.target_file = strdup(argv[value_idx]);
      } else if (strncmp(argv[i], "-u", 2) == 0) {
        opts.user_email = strdup(argv[value_idx]);
      } else if (strncmp(argv[i], "-s", 2) == 0) {
        opts.file_kbps = strtol(argv[value_idx], NULL, 10);
      } else if (strncmp(argv[i], "-t", 2) == 0) {

        char *tokenized_string = strdup(argv[value_idx]);
        char *v = strtok((char *)argv[value_idx], ";");
        while (v) {
          if (strcmp(v, "speed") == 0)
            opts.tests |= test_speed;
          else if (strcmp(v, "files") == 0)
            opts.tests |= test_files;
          else if (strcmp(v, "roundtrip") == 0)
            opts.tests |= test_roundtrip;
          v = strtok(NULL, ";");
        }
      } else if (strncmp(argv[i], "-a", 2) == 0) {
        opts.algorithm_count = 0;
        int sz = 0;
        char *v = strtok((char *)argv[value_idx], ";");
        while (v) {
          if (strcmp(v, "FIPS") == 0) {
          #if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
            opts.algorithms =
                realloc(opts.algorithms,
                        sizeof(enum algorithm_type) * ++opts.algorithm_count);
            opts.algorithms[opts.algorithm_count - 1] = Algorithm_AES;
            opts.fips_enabled = 1;
        #else
            destroy_user_options(&opts);
            fprintf(stderr, "OpenSSL 3.0 or above is required for FIPS testing.\n");
            exit(EXIT_FAILURE);
        #endif
          } else if (strcmp(v, "OTP") == 0) {
            opts.algorithms =
                realloc(opts.algorithms,
                        sizeof(enum algorithm_type) * ++opts.algorithm_count);
            opts.algorithms[opts.algorithm_count - 1] = Algorithm_OTP;
          } else if (strcmp(v, "AES") == 0) {
            opts.algorithms =
                realloc(opts.algorithms,
                        sizeof(enum algorithm_type) * ++opts.algorithm_count);
            opts.algorithms[opts.algorithm_count - 1] = Algorithm_AES;
          } else {
            destroy_user_options(&opts);
            fprintf(stderr, "An invalid algorithm was specified (%s).\n", v);
            exit(EXIT_FAILURE);
          }
          v = strtok(NULL, ";");
        }
      }
    }
  }

  // Config is not required for all tests besides speed
  if (opts.config_path == 0 && opts.tests != test_speed) {
    destroy_user_options(&opts);
    fprintf(stderr,
            "Configuration (-c) required for all tests besides speed.\n");
    exit(EXIT_FAILURE);
  }

  // Testing directory and file required for file tests
  if ((opts.testing_dir == 0 || opts.target_file == 0) &&
      (opts.tests & test_files) == test_files) {
    destroy_user_options(&opts);
    fprintf(stderr,
            "Configuration (-c) required for all tests besides speed.\n");
    exit(EXIT_FAILURE);
  }

  // Test named algorithms
  for (int x = 0; x < opts.algorithm_count; ++x) {

    if (opts.tests & test_roundtrip) {
      // Test full data encryption/decryption flow against XQ backend
      testDataEncryption(&opts, opts.algorithms[x]);
    }

    if (opts.tests & test_speed) {
      // Measure raw encryption speed from memory content
      testEncryptionSpeed(&opts, opts.algorithms[x]);
    }

    if (opts.tests & test_files) {
      // Measure raw encryption speed from satic file content
      testStaticFileEncryption(&opts, opts.algorithms[x]);

      // Measure encryption speed from streamed file contents
      testStreamingFileEncryption(&opts, opts.algorithms[x]);
    }
  }

  destroy_user_options(&opts);
  fprintf(stdout, "\n---------------------\nTests Completed.\n");
}
