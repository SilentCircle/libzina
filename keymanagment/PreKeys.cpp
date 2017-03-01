/*
Copyright 2016 Silent Circle, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "PreKeys.h"

#include "../ratchet/crypto/EcCurve.h"
#include "../util/cJSON.h"
#include "../util/b64helper.h"
#include "../logging/ZinaLogging.h"

#include <cryptcommon/ZrtpRandom.h>

using namespace zina;

static string* preKeyJson(const DhKeyPair &preKeyPair)
{
    LOGGER(INFO, __func__, " -->");
    cJSON *root;
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    root = cJSON_CreateObject();

    b64Encode(preKeyPair.getPrivateKey().privateData(), preKeyPair.getPrivateKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    cJSON_AddStringToObject(root, "private", b64Buffer);

    b64Encode((const uint8_t*)preKeyPair.getPublicKey().serialize().data(), preKeyPair.getPublicKey().getEncodedSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    cJSON_AddStringToObject(root, "public", b64Buffer);

    char *out = cJSON_Print(root);
    string* data = new string(out);
    cJSON_Delete(root); free(out);

    LOGGER(DEBUGGING, __func__, " <--");
    return data;
}

pair<int32_t, const DhKeyPair*> PreKeys::generatePreKey(SQLiteStoreConv* store)
{
    LOGGER(DEBUGGING, __func__, " -->");

    int32_t keyId = 0;
    for (bool ok = false; !ok; ) {
        ZrtpRandom::getRandomData((uint8_t*)&keyId, sizeof(int32_t));
        keyId &= 0x7fffffff;      // always a positive value
        ok = !store->containsPreKey(keyId);
    }
    const DhKeyPair* preKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);

    // Create storage format (JSON) of pre-key and store it. Storage encrypts the JSON data
    const string* pk = preKeyJson(*preKeyPair);
    store->storePreKey(keyId, *pk);
    delete pk;

    pair <int32_t, const DhKeyPair*> prePair(keyId, preKeyPair);

    LOGGER(DEBUGGING, __func__, " <--");
    return prePair;
}

list<pair<int32_t, const DhKeyPair*> >* PreKeys::generatePreKeys(SQLiteStoreConv* store, int32_t num)
{
    LOGGER(DEBUGGING, __func__, " -->");

    std::list<pair<int32_t, const DhKeyPair*> >* pkrList = new std::list<pair<int32_t, const DhKeyPair*> >;

    for (int32_t i = 0; i < num; i++) {
        pair<int32_t, const DhKeyPair*> pkPair = generatePreKey(store);
        pkrList->push_back(pkPair);
    }
    LOGGER(DEBUGGING, __func__, " <--");
    return pkrList;
}

DhKeyPair* PreKeys::parsePreKeyData(const string& data)
{
    LOGGER(DEBUGGING, __func__, " -->");

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5
    uint8_t binBuffer[MAX_KEY_BYTES_ENCODED];

    cJSON* root = cJSON_Parse(data.c_str());
    strncpy(b64Buffer, cJSON_GetObjectItem(root, "public")->valuestring, MAX_KEY_BYTES_ENCODED*2-1);
    size_t b64Length = strlen(b64Buffer);
    b64Decode(b64Buffer, b64Length, binBuffer, MAX_KEY_BYTES_ENCODED);
    const DhPublicKey* pubKey = EcCurve::decodePoint(binBuffer);

    // Here we may check the public curve type and do some code to support different curves and
    // create to correct private key. The serialized public key data contains a curve type id. For
    // the time being use Ec255 (DJB's curve 25519).
    strncpy(b64Buffer, cJSON_GetObjectItem(root, "private")->valuestring, MAX_KEY_BYTES_ENCODED*2-1);
    size_t binLength = b64Decode(b64Buffer, strlen(b64Buffer), binBuffer, MAX_KEY_BYTES_ENCODED);
    const DhPrivateKey* privKey = EcCurve::decodePrivatePoint(binBuffer, binLength);

    cJSON_Delete(root);

    DhKeyPair* keyPair = new DhKeyPair(*pubKey, *privKey);
    delete pubKey;
    delete privKey;

    LOGGER(DEBUGGING, __func__, " <--");
    return keyPair;
}
