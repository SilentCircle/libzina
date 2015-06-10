#ifndef AXO_CONSTANTS_H
#define AXO_CONSTANTS_H

/**
 * @file Constants.h
 * @brief 
 * @ingroup Axolotl++
 * @{
 * 
 * This file contains constants like error codes, return codes, fixed strings
 * and global C macros. This file should no have any dependcies on other includes
 * or modules other then system includes.
 * 
 */

#include <string>
namespace axolotl {
    static const int MAX_KEY_BYTES         = 128;     //!< This would cover a EC with a prime of 1024 bits
    static const int MAX_KEY_BYTES_ENCODED = 130;     //!< Max two bytes for encoding information per key
    static const int SYMMETRIC_KEY_LENGTH  = 32;      //!< Use 256 bit keys for symmetric crypto

    static const int MK_STORE_TIME      = 2*86400;    //!< cleanup stored MKs after two days

    static const std::string SILENT_RATCHET_DERIVE("SilentCircleRKCKDerive");
    static const std::string SILENT_MSG_DERIVE("SilentCircleMessageKeyDerive");
    static const std::string SILENT_MESSAGE("SilentCircleMessage");

    static const int32_t SUCCESS           = 0;       //!< Success, same as SQLITE SUCCESS
    static const int32_t OK = 1;                      //!< Is @c true 

    // Error codes for message processing, between -10 and -99, code -1 used for other purposes already
    static const int32_t GENERIC_ERROR     = -10;     //!< Generic error code, unspecified error
    static const int32_t VERSION_NO_SUPPORTED = -11;  //!< Unspported protocol version
    static const int32_t BUFFER_TOO_SMALL  = -12;     //!< Buffer too small to store some data
    static const int32_t NOT_DECRYPTABLE = -13;       //!< Could not decrypt received message
    static const int32_t NO_OWN_ID  = -14;            //!< Found no own identity for registration
    static const int32_t JS_FIELD_MISSING  = -15;     //!< Missing a required JSON field
    static const int32_t NO_DEVS_FOUND  = -16;        //!< No registered Axolotl devices found for a user
    static const int32_t NO_PRE_KEY_FOUND  = -17;     //!< No more pre-keys for user's devices
    static const int32_t NO_SESSION_USER  = -18;      //!< No session for this user found
    static const int32_t SESSION_NOT_INITED  = -19;   //!< Session not initialized
    static const int32_t OLD_MESSAGE  = -20;          //!< Old message received (already processed)


    // Error codes for public key modules, between -100 and -199
    static const int32_t NO_SUCH_CURVE     = -100;    //!< Curve not supported
    static const int32_t KEY_TYPE_MISMATCH = -101;    //!< Private and public key use different curves
    static const int32_t SIGNING_FAILED    = -102;    //!< curve25519_sign call failed
    static const int32_t VERIFICATION_FAILED = -103;  //!< Signatur verification of a signed pre-key failed

    // Error codes for Ratcheting Session
    static const int32_t IDENTY_KEY_TYPE_MISMATCH = -200;  //!< Their identity key and out identity key use different curve types

    // Error codes for encryption/decryption, HMAC
    static const int32_t WRONG_BLK_SIZE = -300;         //!< The IV or other data length did not match the cipher's blocksize
    static const int32_t UNSUPPORTED_KEY_SIZE = -301;   //!< Key size not supported for this cipher

}  // namespace

/**
 * @}
 */

#endif