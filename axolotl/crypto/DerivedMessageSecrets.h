#ifndef DERIVEDMESSAGESECRETS_H
#define DERIVEDMESSAGESECRETS_H


/**
 * @file DerivedMessageSecrets.h
 * @brief Split an array of input key material into several parts.
 * @ingroup Axolotl++
 * @{
 * 
 * The Accessors don't return a key class but the raw key material derived from
 * the input to the constructor.
 */

#include <stdint.h>
#include <string>

namespace axolotl {
class DerivedMessageSecrets
{
public:
    static const int32_t SIZE = 80;

    /**
     * @brief The constructor
     * 
     * @param okm The raw data input array, usually the output of a HKDF call
     * @param length the length of the array.
     */
    DerivedMessageSecrets(uint8_t* okm, int32_t length);
    DerivedMessageSecrets (const DerivedMessageSecrets& other);
    ~DerivedMessageSecrets();
    DerivedMessageSecrets& operator= ( const DerivedMessageSecrets& other );
//    bool operator== ( const DerivedMessageSecrets& other ) const;

    /**
     * @brief Get raw key bytes of the cipher key.
     * 
     * @return the raw cipher key bytes
     */
    const std::string& getCipherKeyBytes() const { return cipherKey_; }

    /**
     * @brief Get raw key bytes of the MAC key.
     * 
     * @return the raw MAC key bytes
     */
    const std::string& getMacKeyBytes() const { return macKey_; }

    /**
     * @brief Get raw key bytes of the initialization vector (IV).
     * 
     * @return the raw IV bytes
     */
    const std::string& getIvBytes() const { return iv_;}

private:
   static const int32_t CIPHER_KEY_LENGTH = 32;
   static const int32_t MAC_KEY_LENGTH    = 32;
   static const int32_t IV_LENGTH         = 16;

   std::string cipherKey_;
   std::string macKey_;
   std::string iv_;

};
} // namespace

/**
 * @}
 */

#endif // DERIVEDMESSAGESECRETS_H
