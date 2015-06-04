#include <libzrtpcpp/zrtpB64Encode.h>
#include <libzrtpcpp/zrtpB64Decode.h>

int b64Encode(const uint8_t *binData, int32_t binLength, char *b64Data)
{
    if (binLength == 0)
        return 0;
    base64_encodestate _state;
    int codelength;

    base64_init_encodestate(&_state, 0);
    codelength = base64_encode_block(binData, binLength, b64Data, &_state);
    codelength += base64_encode_blockend(b64Data+codelength, &_state);

    return codelength;
}

int b64Decode(const char *b64Data, int32_t b64length, uint8_t *binData)
{
    if (b64length == 0)
        return 0;

    base64_decodestate _state;
    int codelength;

    base64_init_decodestate(&_state);
    codelength = base64_decode_block(b64Data, b64length, binData, &_state);
    return codelength;
}
