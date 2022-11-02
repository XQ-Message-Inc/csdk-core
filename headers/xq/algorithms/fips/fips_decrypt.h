//
//  fips_decrypt.h
//  xqcsdk
//
//  Created by Ike E on 10/28/22.
//

#ifndef fips_decrypt_h
#define fips_decrypt_h



/// Decrypts the provided data using the FIPS complilant AES algorithm.
///
/// @param data The data to decrypt.
/// @param data_len The number of bytes of data.
/// @param key The secret encryption key.
/// @param result A reference to the message block where the decryption result will be stored.
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_fips_decrypt(   uint8_t* data,
                        size_t data_len,
                        char* key,
                        struct xq_message_payload* result,
                        void* context,
                        struct xq_error_info* error   );

/// Prepare a stream for file decryption.
/// @param key The encryption key
/// @param in_file_path The path to file containing the data to be decrypted.
/// @param stream_info Object for storing information about the file stream
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_fips_decrypt_file_start( char* key,
                                const char* in_file_path,
                                struct xq_file_stream* stream_info,
                                struct xq_error_info* error   );
                                
/// Decrypt a data block from a file stream.
/// @param stream_info Object containing information about the file stream
/// @param data A buffer where the decrypted data will be stored.
/// @param data_length The size of the data buffer. Determines how much data will get decrypted in this step.
/// @param error An optional, user-provided block  to store details of any error that occurs.
size_t xq_fips_decrypt_file_step( struct xq_file_stream* stream_info, uint8_t* data, size_t data_length,struct xq_error_info *error);
              
/// Cleans up a stream after decryption.
/// @param stream_info Object containing information about the file stream
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_fips_decrypt_file_end(struct xq_file_stream* stream_info,struct xq_error_info *error  );

void* xq_fips_create_dec_ctx(unsigned char *key_data, int key_data_len, uint8_t* salt, struct xq_error_info *error);

void* xq_fips_reset_enc_ctx(void* ctx, unsigned char *key_data, int key_data_len,  uint8_t* salt,   struct xq_error_info *error);

void xq_fips_destroy_dec_ctx(void* ctx);

#endif /* fips_decrypt_h */
