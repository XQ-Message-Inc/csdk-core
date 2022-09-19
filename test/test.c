//  A slightly simplified version of the starter tutorial for testing encryption functionality.
//  Unlike the starter tutorial, this runs without needing any user input.
//  test.c
//  test
//
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
 #include <unistd.h>
 #include <errno.h>
#include <xq/xq.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>


int get_file_contents(const char* filepath, uint8_t** out)  {
    if (out == 0) {
        fprintf(stderr, "[get_file_contents] out varable for storing file content must be defined.");
        return 0;
    }
    FILE* fp = fopen(filepath, "rb");
    if (fp == 0) {
        fprintf(stderr, "[get_file_contents] Failed to open target file");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    int length = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    *out = calloc(sizeof(uint8_t),length);
    int bytes_read = fread(*out, 1, length, fp);
    fclose(fp);
    if (bytes_read < length) {
        fprintf(stderr, "[get_file_contents]File was not fully read");
        free(*out);
        return 0;
    }
    
    return bytes_read;
    
}

_Bool testEncryption(struct xq_config *cfg, const char* recipients, const char* message, int algorithm) {
    
    struct xq_message_payload result = { 0,0 };
    struct xq_error_info err = {0};
    const char* meta_content = "{\"subject\":\"My C SDK Test Message\"}";
    struct xq_metadata meta = xq_use_metadata( Metadata_Email, meta_content );
    
    if (!xq_encrypt_and_store_token(
                                    cfg, // XQ Configuration object
                                    algorithm, // The algorithm to use for encryption
                                    (uint8_t*)message,  // The message to encrypt.
                                    strlen(message), // The length of the message ( in bytes )
                                    256,  // The number entropy bytes to use.
                                    0, // Entropy pool to use ( 0 if none ).
                                    recipients, // The accounts that will be able to read this message.
                                    24, // The number of hours this message will be available
                                    0, // Prevent this message from being read more than once?
                                    &meta,
                                    &result,
                                    &err)) {
        fprintf(stderr, "[xq_encrypt_and_store_token] %li: %s\n", err.responseCode, err.content );
        return 0;
    }
    
    struct xq_message_payload encoded = { 0, 0 };
    xq_base64_payload(&result, &encoded);
    // Display the encrypted message.
    printf( "-- Encrypted Message: %s\n", encoded.data );
    // Display the XQ locator token.
    printf( "-- Token: %s\n", result.token_or_key);
    xq_destroy_payload(&encoded);
    
    // The encrypted message should be exactly the same as
    // the one originally generated.
    struct xq_message_payload decrypted = { 0,0 };
    
    if (!xq_decrypt_with_token(
                               cfg,
                               Algorithm_Autodetect,
                               result.data,  // The encrypted payload
                               result.length,  // The length of the encrypted payload
                               result.token_or_key, // The XQ locator token
                               &decrypted,
                               &err)){
        fprintf(stderr, "[xq_decrypt_with_token] %li: %s\n", err.responseCode, err.content );
        xq_destroy_payload(&result);
        return 0;
    }
    
    // Success. The message has been successfully encrypted.
    printf( "-- Decrypted:%s\n", decrypted.data );
    
    // Attempt grant another user accesss
    const char *alt_recipients[] = {"fake_user@email.com"};
    
    if ( !xq_svc_grant_access(cfg, result.token_or_key, alt_recipients,1, &err)) {
        fprintf(stderr, "[xq_svc_grant_access] %li: %s\n", err.responseCode, err.content );
        xq_destroy_payload(&result);
        return 0;
    }
    printf("-- Granted alternate user access.\n");
    
    // Revoke the new users access.
    if ( !xq_svc_revoke_access(cfg, result.token_or_key, alt_recipients,1, &err)) {
        fprintf(stderr, "[xq_svc_revoke_access] %li: %s\n", err.responseCode, err.content );
        xq_destroy_payload(&result);
        return 0;
    }
    printf("-- Revoked alternate user access.\n");
        
    
    // Revoke the entire message.
    if ( !xq_svc_remove_key(cfg, result.token_or_key, &err)) {
        fprintf(stderr, "[xq_svc_remove_key] %li: %s\n", err.responseCode, err.content );
        xq_destroy_payload(&result);
        return 0;
    }
    printf("-- Revoked key.\n");
    
    xq_destroy_payload(&decrypted);
    xq_destroy_payload(&result);
    return 1;
}


int testFiles(int argc, const char * argv[]) {
        
    if ( argc < 3 ) {
        fprintf(stderr, "Usage: test CONFIG_FILE_INI USER_ALIAS\n");
        exit(EXIT_FAILURE);
    }
    
    // 1. SDK Initialization
    const char *config_file = argc > 1 ? argv[1] : "xq.ini";
    struct xq_config cfg = xq_init( config_file );
    if (!xq_is_valid_config(&cfg) ) {
        // If something went wrong, call this to clean up
        // any memory that was possibly allocated.
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    // 2. Create Quantum Pool
    struct xq_error_info err = {0};
    
    // 3. Authenticate a user.
    const char* email_address = argv[2];
    

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
    if  (!xq_svc_authorize_alias( &cfg, email_address, &err )) {
        fprintf(stderr, "[xq_svc_authorize_alias] %li : %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    printf( "Alias Account authorized.\n");
    
    // Retrieving your access token
    const char* access_token = xq_get_access_token(&cfg);
    if ( !access_token ){
        fprintf(stderr, "[xq_get_access_token] Failed to get access token.\n");
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    char* token = strdup(access_token);
    
    if (!xq_set_access_token(&cfg, token)) {
        fprintf(stderr, "[xq_set_access_token] Failed to reset access token.\n");
        free(token);
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    printf( "Current Access Token: %s\n", token );
    
    free(token);
    
    // Retrieve information about this user.
    struct xq_subscriber_info info = {0};
    if (!xq_svc_get_subscriber(&cfg, &info, &err)) {
        fprintf(stderr, "[xq_svc_get_subscriber] %li: %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    // 6. Test OTP a new message
    /*
    const char* message = "Hello World From John Doe";
    printf( "Encrypting message: %s...\n", message);
    _Bool res = testEncryption( &cfg, info.mailOrPhone, message, Algorithm_OTP );
    printf("OTP Encryption: %s.\n", res ? "OK" : "Failed" );
    res = testEncryption( &cfg, info.mailOrPhone, message, Algorithm_AES );
    printf("AES Encryption (SHA 256): %s.\n", res ? "OK" : "Failed" );
    res = testEncryption( &cfg, info.mailOrPhone, message, Algorithm_AES_Strong );
    printf("AES Encryption (SHA 512, 100K Rounds): %s.\n", res ? "OK" : "Failed" );
    */
    
    // Test file encryption
    struct xq_message_payload result = {0,0};
    
    const char test_dir[] = "/Users/ikechie/Content/xqdisk";
    
    //const char test_file[] = "/Users/ikechie/Downloads/buck_bunny.mp4";
    //const char test_file[] = "/Users/ikechie/Content/xqdisk/fish.txt";
    char test_file[512] = {0};
    sprintf(test_file, "%s/test_file.txt", test_dir);
    
    char test_out_file[512]={0};
    sprintf(test_out_file, "%s/test_file.xqf",test_dir);

    // FILE* out_fp = fopen(test_out_file,"wb");
    /*
    if (!out_fp){
        fprintf(stderr, "Failed to open file for writing: %s\n", test_out_file);
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    } */
    
    // Write the initial test contents.
    FILE* test_file_fp = fopen(test_file,"wb");
    char test_file_content_1[]="Hello world from Test 1!";
    char test_file_content_2[]="Goodbye world from Test 2!";
    fwrite(test_file_content_1, 1, sizeof(test_file_content_1), test_file_fp);
    fclose(test_file_fp);
    
    _Bool success = xq_encrypt_file_and_store_token(
    &cfg,
    Algorithm_OTP,
    //"/Users/ikechie/Content/xqdisk/fish.txt",
    test_file,
    test_out_file,
    512, // entropy bytes
    0,
    "nero-127.0.0.1@3905.trusted.local,ike@xqmsg.com",
     12, // Hours before expiration
     0, // One time encryption? 0 = false
     &err);
    
    if (!success){
        fprintf(stderr, "[xq_encrypt_file_and_store_token] %li: %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    // Attempt to get the token from the encrypted file
    char token_content[64] = {0};
    struct xq_message_token out_token = {token_content,sizeof(token_content)};
    if (!xq_get_file_token(&cfg, test_out_file, &out_token, &err)) {
        fprintf(stderr, "[xq_get_file_token] %li: %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    
    printf("File Token: %s\n", out_token.data);
    
    
    // Attempt to decrypt the file
    char output_dir[]="/Users/ikechie/Content/xqdisk/decrypted/maya.txt";
    
    if (xq_make_path(output_dir,  0777) != 0){
        fprintf(stderr, "Failed to create demo output directory %s\n", output_dir );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    uint8_t filename_content[1024]= {0};
    struct xq_message_payload out_file_path = {filename_content, sizeof(filename_content)};
    
    if (!xq_decrypt_file(&cfg, test_out_file, output_dir, &out_file_path, &err)){
        fprintf(stderr, "[xq_get_file_token] %li: %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    // Ensure that file content is the same.
    uint8_t* original, *decrypted;
        
    int sz1 = 0 , sz2 = 0;
    if ((sz1 = get_file_contents(test_file, &original)) == 0){
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    if ((sz2 =get_file_contents((char*)filename_content, &decrypted) )== 0){
        free(original);
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    assert(sz1 == sz2);
    assert(memcmp(original, decrypted, sz1) == 0);
    
    

    // Cleanup
    free(original);
    free(decrypted);
    xq_destroy_config(&cfg);
    unlink(test_file);
    unlink(test_out_file);
    printf("Finished.\n");
    
    return 0;
    
}





int current_main(int argc, const char * argv[]) {
        
    if ( argc < 3 ) {
        fprintf(stderr, "Usage: test CONFIG_FILE_INI USER_ALIAS\n");
        exit(EXIT_FAILURE);
    }
    
    // 1. SDK Initialization
    const char *config_file = argc > 1 ? argv[1] : "xq.ini";
    struct xq_config cfg = xq_init( config_file );
    if (!xq_is_valid_config(&cfg) ) {
        // If something went wrong, call this to clean up
        // any memory that was possibly allocated.
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    // 2. Create Quantum Pool
    struct xq_error_info err = {0};
    
    // 3. Authenticate a user.
    const char* email_address = argv[2];
    
    
    // If a real email address was set.
    if  (!xq_svc_authorize_alias( &cfg, email_address, &err )) {
        fprintf(stderr, "[xq_svc_authorize_alias] %li : %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    printf( "Alias Account authorized.\n");
    
    
    // Test file encryption
    struct xq_message_payload result = {0,0};
    
    /*
    const char source_file[] = "/Users/ikechie/Downloads/test-long-report.pdf";
    const char output_file[] = "/Users/ikechie/Downloads/test-long-report-encrypted.pdf.xqf";
    const char decrypted_file[] = "/Users/ikechie/Downloads/test-long-report-stream-decrypted.pdf";
    const char clone_file[] = "/Users/ikechie/Downloads/test-long-report-clone-decrypted.pdf";
    */
    
    const char source_file[] = "/Users/ikechie/Downloads/sumpi.txt";
    const char output_file[] = "/Users/ikechie/Downloads/sumpi-encrypted.txt.xqf";
    const char decrypted_file[] = "/Users/ikechie/Downloads/sumpi-decrypted.txt";
    const char clone_file[] = "/Users/ikechie/Downloads/sumpi-clone.txt";
    
    FILE* source_fp = fopen(source_file, "rb");
    fseek(source_fp,0, SEEK_END);
    long source_size = ftell(source_fp);
    fseek(source_fp, 0, SEEK_SET);
    uint8_t* source_data = calloc(source_size, 1);
    fread(source_data, 1, source_size, source_fp);
    fclose(source_fp);
    
    struct xq_file_stream info;
    
    
    info.native_handle = open(output_file, O_RDWR | O_CREAT | O_TRUNC, 0777 );
    if (info.native_handle == -1) {
        perror("open");
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
 
    _Bool success = xq_encrypt_file_start(&cfg, source_file, output_file, Algorithm_OTP, 512, 0,  "nero-127.0.0.1@3905.trusted.local,ike@xqmsg.com", 12, 0, &info, &err);
    
    if (!success) {
        fprintf(stderr, "[xq_encrypt_file_start] %li : %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    //info.native_handle = fileno(info.fp);
    
    
    // Write into stream
    long data_offset = 0;
    while (data_offset < source_size) {
        int chunk = source_size > 4096 ? 4096 : source_size;
        int read = xq_encrypt_file_step(&info, source_data + data_offset, chunk, &err);
        data_offset += read;
    }
    
    //info.native_handle = 0;

    // Close stream
    xq_encrypt_file_end(&info, &err);
    
    // Close native handle
    close(info.native_handle);
    
    if (info.key) free(info.key);
    
    // Test streaming reads
    memset(&info, 0, sizeof(info));
    if (!xq_decrypt_file_start(&cfg, output_file, &info, &err)){
        fprintf(stderr, "[xq_decrypt_file_start] %li : %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    // Write into stream
    /*
    FILE* out_fp = fopen(decrypted_file, "wb");

    uint8_t chunk_content[4096] = {0};
    data_offset = 0;
    
     int bytes_read =xq_decrypt_file_step(&info, chunk_content, 4096);
     
     if (bytes_read > 0) {
         do {
            fwrite(chunk_content, 1, bytes_read, out_fp);
            bytes_read =xq_decrypt_file_step(&info, chunk_content, 4096);
         } while (bytes_read > 0);
     }
     xq_decrypt_file_end(&info);
     fclose(out_fp);
     // */
     
     //*
    FILE* clone_fp = fopen(clone_file, "wb");
    FILE* old_fp = info.fp;
    info.native_handle = fileno(info.fp);
    info.fp = 0;
    
    uint8_t chunk_content[4096] = {0};
    data_offset = 0;
    
     int bytes_read =xq_decrypt_file_step(&info, chunk_content, 4096);
     
     if (bytes_read > 0) {
         do {
            fwrite(chunk_content, 1, bytes_read, clone_fp);
            bytes_read =xq_decrypt_file_step(&info, chunk_content, 4096);
         } while (bytes_read > 0);
     }
     info.fp = old_fp;
     xq_decrypt_file_end(&info);
     fclose(clone_fp);
     //*/

    
    return 0;
    
}



int main(int argc, const char * argv[]) {

    if ( argc < 3 ) {
        fprintf(stderr, "Usage: test CONFIG_FILE_INI USER_ALIAS\n");
        exit(EXIT_FAILURE);
    }
    
    // 1. SDK Initialization
    const char *config_file = argc > 1 ? argv[1] : "xq.ini";
    struct xq_config cfg = xq_init( config_file );
    if (!xq_is_valid_config(&cfg) ) {
        // If something went wrong, call this to clean up
        // any memory that was possibly allocated.
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    
    // 2. Create Quantum Pool
    struct xq_error_info err = {0};
    
    // 3. Authenticate a user.
    const char* email_address = argv[2];
    
    
    // If a real email address was set.
    if  (!xq_svc_authorize_alias( &cfg, email_address, &err )) {
        fprintf(stderr, "[xq_svc_authorize_alias] %li : %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }
    

    if  (!xq_svc_authorize_trusted(
        &cfg,
        cfg.monitor_team_id,
        cfg.monitor_key,
        "Nero", 1, &err )) {
        fprintf(stderr, "[xq_svc_authorize_trusted] %li : %s\n", err.responseCode, err.content );
        return 0;
    }

    
    printf( "Trusted Account authorized.\n");
    
    const char source_file[] = "/Users/ikechie/Downloads/delta.txt.xqf";
    const char clone_file[] = "/Users/ikechie/Downloads/delta-decrypted.txt";
    struct xq_file_stream info;
    
    int actual_file_size = xq_get_real_file_size(&cfg, source_file, &err);
    if (actual_file_size > 0) {
        fprintf(stdout, "Actual file size is : %i\n", actual_file_size);
    }
    
     // Test streaming reads
    memset(&info, 0, sizeof(info));
    if (!xq_decrypt_file_start(&cfg, source_file, &info, &err)){
        fprintf(stderr, "[xq_decrypt_file_start] %li : %s\n", err.responseCode, err.content );
        xq_destroy_config(&cfg);
        exit(EXIT_FAILURE);
    }

    FILE* clone_fp = fopen(clone_file, "wb");
    FILE* old_fp = info.fp;
    info.native_handle = fileno(info.fp);
    info.fp = 0;
    
    uint8_t chunk_content[1024] = {0};
    int data_offset = 0;
    
     int bytes_read =xq_decrypt_file_step(&info, chunk_content, 1024);
     
     if (bytes_read > 0) {
         do {
            fwrite(chunk_content, 1, bytes_read, clone_fp);
            bytes_read =xq_decrypt_file_step(&info, chunk_content, 1024);
         } while (bytes_read > 0);
     }
     info.fp = old_fp;
     xq_decrypt_file_end(&info);
     fclose(clone_fp);
}
