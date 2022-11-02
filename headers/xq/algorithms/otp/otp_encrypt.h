//
//  otp_encrypt.h
//  xqcsdk
//
//  Created by Ike E on 10/19/20.
//

#ifndef otp_encrypt_h
#define otp_encrypt_h

#ifndef OTP_STREAM_CHUNK_SIZE
#define OTP_STREAM_CHUNK_SIZE 8192
#endif


/// Encrypts the provided data using the OTP algorithm (XOR).
///
/// @param data The data to encrypt.
/// @param data_len The number of bytes of data.
/// @param key The secret encryption key. Ideally (although not required), the key should be at least as long as the data.
/// @param result A reference to the message block where the encryption result will be stored.
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_otp_encrypt(   uint8_t* data,
                        size_t data_len,
                        char* key,
                        struct xq_message_payload* result,
                        void* context,
                        struct xq_error_info* error   );
  
/// Prepare a file encryption stream
/// @param in_file_path Path of the input file.
/// @param out_file_path Full path of the output file.
/// @param token The XQ token
/// @param key The secret encryption key
/// @param stream_info The object where stream information will be stored.
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_otp_encrypt_file_start( const char* in_file_path,
                      const char* out_file_path,
                      char* token,
                      char* key,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   );
       
/// Encrypt a data block from a file stream.
/// @param stream_info Object containing information about the file stream
/// @param data A buffer where the encrypted data will be stored.
/// @param data_length The size of the data buffer. Determines how much data will get encrypted in this step.
/// @param error An optional, user-provided block  to store details of any error that occurs.
/// @return The number of bytes that actually got encrypted.
size_t xq_otp_encrypt_file_step(struct xq_file_stream *stream_info, uint8_t *data,
                           size_t data_length, struct xq_error_info *error);
                     
/// Cleans up a stream after encryption.
/// @param stream_info Object containing information about the file stream
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_otp_encrypt_file_end(struct xq_file_stream *stream_info, struct xq_error_info *error);


/// Create a new context for the specified algorithm.
/// @param key_data The encryption secret key
/// @param key_data_len The secret key length
/// @param salt An 8 byte string to use as the salt
/// @param error An optional, user-provided block  to store details of any error that occurs.
void* xq_otp_create_enc_ctx(unsigned char *key_data, int key_data_len, uint8_t* salt, struct xq_error_info *error);


/// Destroy the encryption context
/// @param ctx The encryption context to destroy
void xq_otp_destroy_enc_ctx(void* ctx);

#endif /* otp_encrypt_h */
