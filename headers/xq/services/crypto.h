//
//  encrypt.h
//  xqcsdk
//
//  Created by Ike E on 10/18/20.
//

#ifndef encrypt_h
#define encrypt_h



enum algorithm_type {
    /// This should only be used during a decryption phase. Automatically decide which algorithm to used based on its key prefix.
    Algorithm_Autodetect = 0,
    /// OTP (XOR)
    Algorithm_OTP = 1,
    /// Advanced Encryption Standard (AES)
    Algorithm_AES = 2,
    /// 5-Pass Advanced Encryption Standard (AES) with SHA-2 key encoding.
    Algorithm_FIPS = 3,
};

enum algorithm_type_indicator : uint8_t {
    Indicator_OTP = 'X',
    Indicator_AES = 'A',
    Indicator_FIPS = 'F'
};


/// Get a user friendly algorithm name based on the provided type
/// @param algorithm The algorithm type
static inline const char* algorithm_to_string(enum algorithm_type algorithm) {
    switch (algorithm) {
        case Algorithm_OTP: return "OTP";
        case Algorithm_AES: return "AES";
        case Algorithm_FIPS: return "FIPS";
        default: return "Unknown";
    }
}

/// Check whether an integer is a valid algorithm type or not.
/// @param algo The integer to check.
static inline _Bool is_valid_algorithm(int algo) {
    switch ( algo ) {
        case Algorithm_OTP:
        case Algorithm_AES:
        case Algorithm_FIPS:
            return 1;
        default:
            return 0;
    }
}

/// A  generic message payload structure.
struct xq_message_payload {
    /// The payload content.
    uint8_t* data;
    /// The size of the content in bytes.
    uint32_t length;
    /// The token or key associated with this payload.
    char* token_or_key;
};

/// A generic data  structure for storing hex-encoded quantum key.
struct xq_hex_quantum_key {
    /// The data content.
    char* data;
    /// the size of the content in bytes.
    uint32_t length;
};

struct xq_message_token;
struct xq_file_stream;


/// Extract the XQ token from an encrypted file
/// @param config The XQ configuration instance.
/// @param in_file_path Full path of the input file.
/// @param token The token registered with the encryption key
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_get_file_token(struct xq_config *config, const char *in_file_path,
                            struct xq_message_token *token,
                            struct xq_error_info *error) ;

/// Encrypts the provided data block.
///
/// This service will fetch quantum data and use that to generate a secret key. If encryption is successful, it will fill the result object with
/// the newly encrypted data, and the secret key used.
///
/// @param config The XQ configuration instance.
/// @param algorithm The algorithm to use.
/// @param data The data to encrypt.
/// @param data_len The size of the data in bytes.
/// @param entropy_size The amount of quantum entropy to use for the key.
/// @param pool  An optional quantum pool to use  for entropy.
/// @param result The user-provided result instance. The data storage may be preallocated. Otherwise, it will be allocated automatically ( the user must manually clean up after usage).
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_encrypt(   struct xq_config* config,
                    enum algorithm_type algorithm,
                    uint8_t* data, size_t data_len,
                    int entropy_size,
                    struct xq_quantum_pool* pool,
                    struct xq_message_payload* result,
                    struct xq_error_info* error   );


/// Encrypts the provided data block. The difference between this and [xq_encrypt] is that you must provide your own key here.
/// @param algorithm The algorithm to use.
/// @param data The data to encrypt
/// @param data_len The size of the data in bytes.
/// @param key Your encryption key
/// @param result The user-provided result instance. The data storage may be preallocated. Otherwise, it will be allocated automatically ( the user must manually clean up after usage).
/// @param context The optional encryption context. Not providing this for certain algorithms can reduce performance (when called repeatedly)/
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_encrypt_with_key( enum algorithm_type algorithm,
                        uint8_t* data,
                        size_t data_len,
                        char* key,
                        struct xq_message_payload* result,
                        void* context,
                        struct xq_error_info* error   );


/// Encrypts a file and store the results in another using the specified algorithm.
/// @param config The XQ configuration instance.
/// @param algorithm The algorithm to use.
/// @param in_file_path Full path of the input file.
/// @param out_fp The output file where the encrypted data will be stored.
/// @param token The token registered with the encryption key
/// @param key The encryption key
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_encrypt_file(
                     const char* in_file_path, const char* out_file_path,
                      char* token,
                      char* key,
                     struct xq_error_info* error   );
                  

/// Prepare a file encryption stream
/// @param config The XQ configuration instance.
/// @param in_file_path Full path of the input file.
/// @param out_file_path Full path of the output file.
/// @param algorithm The algorithm to use.
/// @param entropy_bytes The number of quantum entropy bytes to use for the key
/// @param pool The quantum pool where entropy bytes will be obtained from
/// @param recipients The list of message recipients
/// @param hours_to_expiration The number of hours to allow key access
/// @param delete_on_read Specifies whether the key will be deleted after the first use
/// @param stream_info The object where stream information will be stored.
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_encrypt_file_start(struct xq_config *config,  const char *in_file_path, const char *out_file_path,
                             enum algorithm_type algorithm,
                            int entropy_bytes,
                            struct xq_quantum_pool *pool, const char *recipients,
                            int hours_to_expiration, _Bool delete_on_read,
                            struct xq_file_stream *stream_info,
                            struct xq_error_info *error);


/// Encrypt a data block from a file stream.
/// @param stream_info Object containing information about the file stream
/// @param data A buffer where the encrypted data will be stored.
/// @param data_length The size of the data buffer. Determines how much data will get encrypted in this step.
/// @param error An optional, user-provided block  to store details of any error that occurs.
/// @return The number of bytes that actually got encrypted.
size_t xq_encrypt_file_step( struct xq_file_stream* stream_info, uint8_t* data, size_t data_length,struct xq_error_info *error);


/// <#Description#>
/// @param stream_info <#stream_info description#>
/// @param error <#error description#>
_Bool xq_encrypt_file_end(struct xq_file_stream* stream_info,struct xq_error_info *error );



/// Encrypts data using the specified algorithm, and save the key on XQ in return for a token.
///
/// This method will automate a few steps for you. It will :
///
/// 1. Fetch quantum data and use that to generate a secret key.
///
/// 2. Encrypt using the specified algorithm.
///
/// 3. Save the secret key to XQ in return for a token.
///
/// 4. Fill out the result instance with the encrypted content and the token ( not the secret key ).
///
/// @param config The XQ configuration instance.
/// @param algorithm The algorithm to use.
/// @param data The data to encrypt
/// @param data_len The size of the data in bytes.
/// @param entropy_size The amount of quantum entropy to use for the key.
/// @param pool  An optional quantum pool to use  for entropy.
/// @param recipients A list of the recipients.
/// @param hours_to_expiration The number of hours before this message should expire.
/// @param delete_on_read Should this key be deleted after it is read once?
/// @param metadata Optional metadata related to the content being encrypted. File and Email metadata will be viewable as communications on the users dashboard.
/// @param result The user-provided result instance. The data storage may be preallocated. Otherwise, it will be allocated automatically ( the user must manually clean up after usage).
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_encrypt_and_store_token(
                                 struct xq_config* config,
                                 enum algorithm_type algorithm,
                                 uint8_t* data, size_t data_len,
                                 int entropy_size,
                                 struct xq_quantum_pool* pool,
                                 const char* recipients,
                                 int hours_to_expiration,
                                 _Bool delete_on_read,
                                 struct xq_metadata* metadata,
                                 struct xq_message_payload* result,
                                 struct xq_error_info* error   );


/// Encrypt the data from one file and store the result in another.
/// @param config The XQ configuration instance.
/// @param algorithm The algorithm to use.
/// @param in_file_path The file containing the data to be encrypted.
/// @param out_file_path The output file where the encrypted data will be stored.
/// @param entropy_size The amount of quantum entropy to use for the key.
/// @param pool  An optional quantum pool to use  for entropy.
/// @param recipients A list of the recipients.
/// @param hours_to_expiration The number of hours before this message should expire.
/// @param delete_on_read Should the key be deleted after it is read once?
/// @param metadata Optional metadata related to the content being encrypted. File and Email metadata will be viewable as communications on the users dashboard.
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_encrypt_file_and_store_token(
                                 struct xq_config* config,
                                 enum algorithm_type algorithm,
                                 const char* in_file_path,
                                 const char* out_file_path,
                                 int entropy_bytes,
                                 struct xq_quantum_pool* pool,
                                 const char* recipients,
                                 int hours_to_expiration,
                                 _Bool delete_on_read,
                                 struct xq_error_info* error     );


enum algorithm_type algorithm_from_key(const char* key);


/// Decrypts a message using the secret key associated with the provided token.
///
/// This method will attempt to get the secret key using the token. This will only be possible if the user is a valid recipient of the message, and the key is unexpired
/// and unrevoked. Once the key is acquired, the message will be decrypted.
///
/// @param config The XQ configuration instance.
/// @param algorithm The algorithm to use.
/// @param data The raw encrypted data.
/// @param data_len The length of the encrypted data in bytes.
/// @param token The message token. This will be used to retrieve the secret key.
/// @param result The user-provided result instance. The data storage may be preallocated. Otherwise, it will be allocated automatically ( the user must manually clean up after usage).
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_decrypt_with_token(    struct xq_config* config,
                                enum algorithm_type algorithm,
                                uint8_t* data,
                                size_t data_len,
                                char* token,
                                struct xq_message_payload* result,
                                struct xq_error_info* error   );


/// Decrypts a message using the provided secret key.
///
/// @param config The XQ configuration instance.
/// @param algorithm The algorithm to use.
/// @param data The raw encrypted data.
/// @param data_len The length of the encrypted data in bytes.
/// @param key The secret key.
/// @param result The user-provided result instance. The data storage may be preallocated. Otherwise, it will be allocated automatically ( the user must manually clean up after usage).
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_decrypt_with_key(  struct xq_config* config,
                            enum algorithm_type algorithm,
                            uint8_t* data,
                            size_t data_len,
                            char* key,
                            struct xq_message_payload* result,
                            struct xq_error_info* error   );


/// Decrypts an encrypted file
/// @param config The XQ configuration instance.
/// @param in_file_path The path to file containing the data to be decrypted.
/// @param out_file_dir The path to the directory (or full path to file) where the decrypted file will be stored
/// @param resulting_file_path  An optional buffer where the full output path can be stored. Useful if out_file_dir is a directory.
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_decrypt_file(struct xq_config* config,
                        const char* in_file_path,
                        const char* out_file_dir,
                        struct xq_message_payload* resulting_file_path,
                        struct xq_error_info* error  );


/// Prepare a stream for file decryption.
/// @param config The XQ configuration instance.
/// @param in_file_path The path to file containing the data to be decrypted.
/// @param stream_info Object for storing information about the file stream
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_decrypt_file_start(struct xq_config* config, const char* in_file_path,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   );


/// Decrypt a data block from a file stream.
/// @param stream_info Object containing information about the file stream
/// @param data A buffer where the decrypted data will be stored.
/// @param data_length The size of the data buffer. Determines how much data will get decrypted in this step.
/// @param error An optional, user-provided block  to store details of any error that occurs.
size_t xq_decrypt_file_step( struct xq_file_stream* stream_info, uint8_t* data, size_t data_length,  struct xq_error_info *error );


/// Cleans up a stream after decryption.
/// @param stream_info Object containing information about the file stream
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_decrypt_file_end(struct xq_file_stream* stream_info,struct xq_error_info *error  );



/// Gets the real (unencrypted) size of an XQ encrypted file.
/// @param config The XQ configuration instance.
/// @param in_file_path  The path to file.
/// @param error An optional, user-provided block  to store details of any error that occurs.
long xq_get_real_file_size( struct xq_config* config, const char* in_file_path,  struct xq_error_info *error  );


/// Expands the length of a key.
///
/// In some instances it will be inefficient or impossible to get the number of quantum bits to create a key of a desired length. As an alternative, you may fetch a smaller number of keys, and
/// generate a longer key from those using smart shuffling.
/// @param in_key The original key.
/// @param out_key A pointer to a buffer where the expanded key will be stored.
/// @param new_len The size of the expanded key buffer ( in bytes ). If the method is successful, the buffer will be filled by this number of bytes.
_Bool xq_expand_key( char* in_key, char* out_key, int new_len );


/// Converts a sequence of character bits to bytes.
///
/// @param bits_in The bit sequence
/// @param in_len the length of the bit sequence.
/// @param hex_out A pointer to a buffer that will contain the hex sequence.
/// @param out_len The length of the hex buffer.
void xq_bits_to_hex( char* bits_in, int in_len, char* hex_out, int out_len );




/// Convert a string of character encoded bit key to hex format.
/// @param key_in The key to convert
/// @param hex_out The object where the output will be stored.
/// @param prefix A prefix to attach to the key after conversion. This can be used to store the type of encryption that the key will be used for.
_Bool xq_key_to_hex( struct xq_quantum_key* key_in, struct xq_hex_quantum_key* hex_out, char prefix );


/// Destroy a quantum key object.
/// @param obj The object to destroy.
void xq_destroy_quantum_key(struct xq_quantum_key* obj);


/// Destroy a hex quantum object.
/// @param obj The object to destroy.
void xq_destroy_hex_quantum_key(struct xq_hex_quantum_key* obj);


/// Destroy a message payload  object.
/// @param obj The object to destroy.
void xq_destroy_payload(struct xq_message_payload* obj);


/// Convert a raw payload to a base64 one (usually for display or textual transfer ).
/// @param in The payload to convert.
/// @param out The resulting payload.
_Bool xq_base64_payload(struct xq_message_payload* in, struct xq_message_payload* out);


/// Create a new context for the specified algorithm.
/// - Parameters:
///   - algorithm: The algorithm to use.
///   - key_data: The encryption secret key
///   - key_data_len: The secret key length
///   - salt: An 8 byte string to use as the salt
///   - error: An optional, user-provided block  to store details of any error that occurs.
void* xq_create_ctx(enum algorithm_type algorithm, unsigned char *key_data, int key_data_len, uint8_t* salt, struct xq_error_info *error);


/// Destroy the encryption context
/// - Parameters:
///   - algorithm: The algorithm to use.
///   - ctx: The encryption context to destroy
void xq_destroy_ctx(enum algorithm_type algorithm, void* ctx);


/// Typedef for file decryption start method
typedef _Bool (*decrypt_file_start_type)(char* key,const char* in_file_path,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   );
                     
/// Typedef for file decryption step method
typedef size_t (*decrypt_file_step_type)( struct xq_file_stream* stream_info, uint8_t* data, size_t data_length,struct xq_error_info* error );

/// Typedef for file decryption finish method
typedef _Bool (*decrypt_file_end_type)(struct xq_file_stream* stream_info,struct xq_error_info *error  );


/// Typedef for file encryption start method
typedef _Bool (*encrypt_file_start_type)(const char* in_file_path,
                      const char* out_file_path,
                      char* token,
                      char* key,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   );

/// Typedef for file encryption step method
typedef size_t (*encrypt_file_step_type)( struct xq_file_stream* stream_info, uint8_t* data, size_t data_length,struct xq_error_info *error);

/// Typedef for file encryption start method
typedef _Bool (*encrypt_file_end_type)(struct xq_file_stream* stream_info,struct xq_error_info *error );



#endif /* encrypt_h */
