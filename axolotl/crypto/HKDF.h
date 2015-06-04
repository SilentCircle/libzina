#ifndef HKDF_H
#define HKDF_H

/**
 * @file HKDF.h
 * @brief Implementation of HKDF
 * @ingroup Axolotl++
 * @{
 */

#include <stdint.h>
#include <stddef.h>

namespace axolotl {
class HKDF
{
public:
    HKDF();
    ~HKDF();

    static void deriveSecrets(uint8_t* inputKeyMaterial, size_t ikmLength, 
                              uint8_t* info, size_t infoLength, 
                              uint8_t* output, size_t outputLength);

    static void deriveSecrets(uint8_t* inputKeyMaterial, size_t ikmLength, 
                              uint8_t* salt, size_t saltLen, 
                              uint8_t* info, size_t infoLength, 
                              uint8_t* output, size_t outputLength);

private:
    static const int HASH_OUTPUT_SIZE  = 32;
    static const int OFFSET = 1;

    static void extract(uint8_t* salt, size_t saltLen, uint8_t* inputKeyMaterial, size_t ikmLength, uint8_t* prkOut);

    static void expand(uint8_t* prk, size_t prkLen, uint8_t* info, size_t infoLen, uint8_t* output, size_t L);
};
} // namespace
/**
 * @}
 */

#endif // HKDF_H
