//
//  authorize_test.h
//  xqcsdk
//
//  Created by Ike E on 3/4/20.
//

#ifndef authorize_trusted_h
#define authorize_trusted_h


/// Authorizes an XQ user against a specific team. Unlike the standard authorize method, this comprises
/// of the detected source IP, and the encryption key ( used to protect the returned access token).
///
/// @param config The XQ configuration instance.
/// @param security_key The encryption key used to protect the access token. Retrievable from the dashboard.
/// @param device_name The name under which your device will be added on the team dashboard. Ignored if already registered.
/// @param is_roaming Specifies if the resulting key be tied to the client IP.
/// @param error An optional, user-provided block  to store details of any error that occurs.
_Bool xq_svc_authorize_trusted( struct xq_config* config,
                               int team_id,
                               const char* security_key,
                               const char* device_name,
                               _Bool is_roaming,
                               struct xq_error_info* error );


#endif /* authorize_trusted_h */
