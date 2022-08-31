//
//  otp_encrypt.h
//  xqcsdk
//
//  Created by Ike E on 10/19/20.
//

#ifndef otp_encrypt_h
#define otp_encrypt_h

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
                        struct xq_error_info* error   );
                        
                        
_Bool xq_otp_encrypt_file(
                     const char* in_file_path, const char* out_file_path,
                     char* token,
                     char* key,
                     struct xq_error_info* error  ) ;
                     
_Bool xq_otp_encrypt_file_start(const char* out_file_path,
                      char* token,
                      char* key,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   );
                     
int xq_otp_encrypt_file_step(struct xq_file_stream *stream_info, uint8_t *data,
                           int data_length,struct xq_error_info *error);
                     
_Bool xq_otp_encrypt_file_end(struct xq_file_stream *stream_info, struct xq_error_info *error);

#endif /* otp_encrypt_h */
