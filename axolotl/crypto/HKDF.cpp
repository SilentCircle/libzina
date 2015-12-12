#include <zrtp/crypto/hmac256.h>
#include <string.h>
#include "../../logging/AxoLogging.h"


#include "HKDF.h"
using namespace axolotl;

void HKDF::deriveSecrets(uint8_t* inputKeyMaterial, size_t ikmLength, 
                         uint8_t* info, size_t infoLength, 
                         uint8_t* output, size_t outputLength)
{
    LOGGER(INFO, __func__, " -->");
    uint8_t emptySalt[HASH_OUTPUT_SIZE] = {0};
    deriveSecrets(inputKeyMaterial, ikmLength, emptySalt, HASH_OUTPUT_SIZE, info, infoLength, output, outputLength);
    LOGGER(INFO, __func__, " <--");
}


void HKDF::deriveSecrets(uint8_t* inputKeyMaterial, size_t ikmLength, 
                         uint8_t* salt, size_t saltLen, 
                         uint8_t* info, size_t infoLength, 
                         uint8_t* output, size_t outputLength)
{
    LOGGER(INFO, __func__, " -->");
    uint8_t prk[HASH_OUTPUT_SIZE] = {0};
    extract(salt, saltLen, inputKeyMaterial, ikmLength, prk);
    expand(prk, HASH_OUTPUT_SIZE, info, infoLength, output, outputLength);
    LOGGER(INFO, __func__, " <--");
}

// Extract function according to RFC 5869
void HKDF::extract(uint8_t* salt, size_t saltLen, uint8_t* inputKeyMaterial, size_t ikmLength, uint8_t* prkOut)
{
    uint32_t len;
    hmac_sha256(salt, static_cast<uint32_t>(saltLen), inputKeyMaterial, static_cast<int32_t>(ikmLength), prkOut, &len);
}

void* createSha256HmacContext(uint8_t* key, int32_t keyLength);
void freeSha256HmacContext(void* ctx);
void hmacSha256Ctx(void* ctx, const uint8_t* data[], uint32_t dataLength[], uint8_t* mac, int32_t* macLength );

// Expand funtion according to RFC 5869
void HKDF::expand(uint8_t* prk, size_t prkLen, uint8_t* info, size_t infoLen, uint8_t* output, size_t L)
{
    LOGGER(INFO, __func__, " -->");
    size_t iterations = (L + (HASH_OUTPUT_SIZE-1)) / HASH_OUTPUT_SIZE;

    void* hmacCtx;
    uint8_t *T;

    const uint8_t* data[4];      // 3 data pointers for HMAC data plus terminating NULL
    uint32_t dataLen[4];
    size_t dataIdx = 0;

    uint8_t counter;
    int32_t macLength;

    hmacCtx = createSha256HmacContext(prk,  static_cast<int32_t>(prkLen));

    // T points to buffer that holds concatenated T(1) || T(2) || ... T(N))
    T = new uint8_t[(iterations * HASH_OUTPUT_SIZE)];

    // Prepare first HMAC. T(0) has zero length, thus we ignore it in first run.
    // After first run use its output (T(1)) as first data in next HMAC run.
    for (size_t i = OFFSET; i <= iterations; i++) {
        if (infoLen > 0 && info != NULL) {
            data[dataIdx] = info;
            dataLen[dataIdx++] = static_cast<uint32_t>(infoLen);
        }
        counter = static_cast<uint8_t>(i & 0xff);
        data[dataIdx] = &counter;
        dataLen[dataIdx++] = 1;

        data[dataIdx] = NULL;
        dataLen[dataIdx] = 0;

        hmacSha256Ctx(hmacCtx, data, dataLen, T + ((i-1) * HASH_OUTPUT_SIZE), &macLength);

        // Use output of previous hash run as first input of next hash run
        dataIdx = 0;
        data[dataIdx] = T + ((i-1) * HASH_OUTPUT_SIZE);
        dataLen[dataIdx++] = HASH_OUTPUT_SIZE;
    }
    freeSha256HmacContext(hmacCtx);
    memcpy(output, T, L);
    delete[] T;
    LOGGER(INFO, __func__, " <--");
}
