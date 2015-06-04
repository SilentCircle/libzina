#ifndef DERIVEDROOTSECRETS_H
#define DERIVEDROOTSECRETS_H

/**
 * @file DerivedRootSecrets.h
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
class DerivedRootSecrets
{
public:
    static const int32_t SIZE = 64;

    /**
     * @brief The constructor
     * 
     * @param okm The raw data input array, usually the output of a HKDF call
     * @param length the length of the array.
     */
    DerivedRootSecrets(uint8_t* okm, int32_t length);
    DerivedRootSecrets (const DerivedRootSecrets& other);
    ~DerivedRootSecrets();
    DerivedRootSecrets& operator= ( const DerivedRootSecrets& other );
//    bool operator== ( const DerivedRootSecrets& other ) const;

    /**
     * @brief Get raw key bytes of the root key.
     * 
     * @return the raw root key bytes
     */
    const std::string& getRootKeyBytes() const { return rootKey_; }

    /**
     * @brief Get raw key bytes of the chain key.
     * 
     * @return the raw chain key bytes.
     */
    const std::string& getChainKeyBytes() const { return chainKey_; }

private:
      std::string rootKey_;
      std::string chainKey_;
};
} // namespace

/**
 * @}
 */

#endif // DERIVEDROOTSECRETS_H
