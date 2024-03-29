//
//  otp_decrypt.h
//  xqcsdk
//
//  Created by Ike E on 10/19/20.
//

#ifndef otp_decrypt_h
#define otp_decrypt_h

/// Decrypts the provided data using the OTP algorithm (XOR).
///
/// @param data The data to decrypt.
/// @param data_len The number of bytes of data.
/// @param key The secret encryption key..
/// @param result A reference to the message block where the encryption result will be stored.
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_otp_decrypt(   uint8_t* data,
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
_Bool xq_otp_decrypt_file_start(char* key,const char* in_file_path,
                      struct xq_file_stream* stream_info,
                     struct xq_error_info* error   );


/// Decrypt a data block from a file stream.
/// @param stream_info Object containing information about the file stream
/// @param data A buffer where the decrypted data will be stored.
/// @param data_length The size of the data buffer. Determines how much data will get decrypted in this step.
/// @param error An optional, user-provided block  to store details of any error that occurs.
size_t xq_otp_decrypt_file_step( struct xq_file_stream* stream_info, uint8_t* data, size_t data_length,struct xq_error_info* error );


/// Cleans up a stream after decryption.
/// @param stream_info Object containing information about the file stream
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_otp_decrypt_file_end(struct xq_file_stream* stream_info,struct xq_error_info *error  );

#endif /* otp_decrypt_h */
