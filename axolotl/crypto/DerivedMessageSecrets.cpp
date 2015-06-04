#include <string.h>
#include "DerivedMessageSecrets.h"

static void *(*volatile memset_volatile)(void *, int, size_t) = memset;

using namespace axolotl;
DerivedMessageSecrets::DerivedMessageSecrets(uint8_t* okm, int32_t length)
{
    cipherKey_ = std::string((const char*)okm, CIPHER_KEY_LENGTH);
    macKey_    = std::string((const char*)okm + CIPHER_KEY_LENGTH, MAC_KEY_LENGTH);
    iv_        = std::string((const char*)okm + CIPHER_KEY_LENGTH + MAC_KEY_LENGTH, IV_LENGTH);
}

DerivedMessageSecrets::DerivedMessageSecrets(const DerivedMessageSecrets& other)
{
    cipherKey_ = other.cipherKey_;
    macKey_ = other.macKey_;
    iv_ = other.iv_;
}

DerivedMessageSecrets::~DerivedMessageSecrets()
{
    cipherKey_.append("1"); memset_volatile((void*)cipherKey_.data(), 0, cipherKey_.size());
    macKey_.append("1"); memset_volatile((void*)macKey_.data(), 0, macKey_.size());
}

DerivedMessageSecrets& DerivedMessageSecrets::operator=(const DerivedMessageSecrets& other)
{
    if (this == &other)
        return *this;

    // Clear the buffer of the existing keys before assigning
    // std::string just return the old buffer to free memory before
    // it copies the new data.
    cipherKey_.append("1"); memset_volatile((void*)cipherKey_.data(), 0, cipherKey_.size());
    macKey_.append("1"); memset_volatile((void*)macKey_.data(), 0, macKey_.size());

    cipherKey_ = other.cipherKey_;
    macKey_ = other.macKey_;
    iv_ = other.iv_;
    return *this;
}

// bool DerivedMessageSecrets::operator== ( const DerivedMessageSecrets& other ) const
// {
// 
// }
