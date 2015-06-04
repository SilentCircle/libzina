#include <string.h>
#include "DerivedRootSecrets.h"

static void *(*volatile memset_volatile)(void *, int, size_t) = memset;

using namespace axolotl;
DerivedRootSecrets::DerivedRootSecrets(uint8_t* okm, int32_t length) :
    rootKey_(std::string((const char*)okm, 32)), chainKey_(std::string((const char*)okm + 32, 32)) {}

DerivedRootSecrets::DerivedRootSecrets (const DerivedRootSecrets& other)
{
    rootKey_ = other.rootKey_;
    chainKey_ = other.chainKey_;
}

DerivedRootSecrets::~DerivedRootSecrets()
{
     rootKey_.append("1"); memset_volatile((void*)rootKey_.data(), 0, rootKey_.size());
     chainKey_.append("1"); memset_volatile((void*)chainKey_.data(), 0, chainKey_.size());
}

DerivedRootSecrets& DerivedRootSecrets::operator= ( const DerivedRootSecrets& other )
{
    if (this == &other)
        return *this;

    // Clear the buffer of the existing keys before assigning
    // std::string just return the old buffer to free memory before
    // it copies the new data.
    rootKey_.append("1"); memset_volatile((void*)rootKey_.data(), 0, rootKey_.size());
    chainKey_.append("1"); memset_volatile((void*)chainKey_.data(), 0, chainKey_.size());

    rootKey_ = other.rootKey_;
    chainKey_ = other.chainKey_;
}

// bool DerivedRootSecrets::operator== ( const DerivedRootSecrets& other ) const
// {
// 
// }
