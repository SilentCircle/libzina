#include "ScProvisioning.h"

#include "../util/cJSON.h"
#include "../util/b64helper.h"
#include "../axolotl/Constants.h"
#include "../axolotl/crypto/EcCurve.h"
#include "../axolotl/crypto/DhKeyPair.h"
#include "../keymanagment/PreKeys.h"

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <utility>
using namespace axolotl;

static std::string Empty;

int32_t (*ScProvisioning::httpHelper_)(const std::string&, const std::string&, const std::string&, std::string*) = NULL;

void ScProvisioning::setHttpHelper(int32_t (*httpHelper)( const std::string&, const std::string&, const std::string&, std::string* ))
{
    httpHelper_ = httpHelper;
}

// Implementation of the Provisioning API: Register a device, re-used to set 
// new signed pre-key and to add pre-keys.
// /v1/me/device/<device_id>/axolotl/keys/?api_key=<API_key>
// Method: PUT

static const char* registerRequest = "/v1/me/device/%s/axolotl/keys/?api_key=%s";

int32_t Provisioning::registerAxoDevice(const std::string& request, const std::string& authorization, const std::string& scClientDevId, std::string* result)
{
    char temp[1000];
    snprintf(temp, 990, registerRequest, scClientDevId.c_str(), authorization.c_str());

    std::string requestUri(temp);

    return  ScProvisioning::httpHelper_(requestUri, PUT, request, result);
}

// Implementation of the Provisioning API: Get Pre-Key
// Request URL: /v1/user/<user>/devices/<devid>/?api_key=<apikey>
// Method: GET
/*
 {
    "version" :        <int32_t>,        # Version of JSON get pre-key, 1 for the first implementation
    "username" :       <string>,         # the user name for this account, enables mapping from optional E.164 number to name
    "scClientDevId"  : <string>,         # optional, the same string as used to register the device (v1/me/device/{device_id}/)
    "registrationId" : <int32_t>,        # the client's Axolotl registration id
    "identityKey" :    <string>,         # public part encoded base64 data
    "deviceId" :       <int32_t>,        # the TextSecure (Axolotl) device id if available, default 1
    "domain":          <string>,         # optional, domain identifier, in set then 'scClientDevId' my be missing (federation support)
    "preKey" : 
    {
        "keyId" :     <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    }
 }
*/
static const char* getPreKeyRequest = "/v1/user/%s/devices/%s/?api_key=%s";
int32_t Provisioning::getPreKeyBundle(const std::string& name, const std::string& longDevId, const std::string& authorization, pair<const DhPublicKey*, const DhPublicKey*>* preIdKeys)
{
    char temp[1000];
    snprintf(temp, 990, getPreKeyRequest, name.c_str(), longDevId.c_str(), authorization.c_str());
    std::string requestUri(temp);

    std::string response;
    int32_t code = ScProvisioning::httpHelper_(requestUri, GET, Empty, &response);

    if (code > 400)
        return 0;

    uint8_t pubKeyBuffer[MAX_KEY_BYTES_ENCODED];

    cJSON* root = cJSON_Parse(response.c_str());

    if (root == NULL)
        return 0;

    // username is required in SC implementation
    cJSON* cjTemp = cJSON_GetObjectItem(root, "username");
    char* jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
    if (jsString == NULL) {
        return 0;
    }
    std::string username(jsString);

    // Silent Circle device id is required in SC implementation
    cjTemp = cJSON_GetObjectItem(root, "scClientDevId");
    jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
    if (jsString == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    std::string scClientDevId(jsString);

    cjTemp = cJSON_GetObjectItem(root, "identityKey");
    jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
    if (jsString == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    std::string identity(jsString);

    cJSON* pky = cJSON_GetObjectItem(root, "preKey");
    int32_t pkyId = cJSON_GetObjectItem(pky, "keyId")->valueint;
    std::string pkyPub(cJSON_GetObjectItem(pky, "key")->valuestring);

    int32_t len = b64Decode(pkyPub.data(), pkyPub.size(), pubKeyBuffer);
    const DhPublicKey* prePublic = EcCurve::decodePoint(pubKeyBuffer);

    len = b64Decode(identity.data(), identity.size(), pubKeyBuffer);
    const DhPublicKey *identityKey = EcCurve::decodePoint(pubKeyBuffer);

    // Clear JSON buffer and context
    cJSON_Delete(root);
    preIdKeys->first = identityKey;
    preIdKeys->second = prePublic;
    return pkyId;
}

// Implementation of the Provisioning API: Available pre-keys
// Request URL: /v1/me/axolotl/prekeys/?api_key=<API_key>
// Method: GET
/*
 {
    "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
    "scClientDevId"  : <string>,         # the same string as used to register the device (v1/me/device/{device_id}/)
    "registrationId" : <int32_t>,        # the client's Axolotl registration id
    "availablePreKeys" : <int32_t>       # number of available pre-keys on the server
 }
 */
int32_t Provisioning::getNumPreKeys(const std::string& authorization)
{
    std::string requestUri(uriVersion);
    requestUri.append(uriMe).append(uriAxolotl).append(uriPreKeys).append(uriApiKey).append(authorization);

    std::string response;
    int32_t code = ScProvisioning::httpHelper_(requestUri, GET, Empty, &response);

    if (code > 400)
        return -1;

    cJSON* root = cJSON_Parse(response.c_str());
    int32_t availableKeys = cJSON_GetObjectItem(root, "availablePreKeys")->valueint;

    // Clear JSON buffer and context
    cJSON_Delete(root);

    return availableKeys;
}


// Implementation of the Provisioning API: Get Available Axolotl registered devices of a user
// Request URL: /v1/user/wernerd/devices/?filter=axolotl&api_key=<apikey>
// Method: GET
/*
 {
    "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
    "scClientDevIds" : [<string>, ..., <string>]   # array of known Axolotl ScClientDevIds for this user/account
 }
 */
static const char* getUserDevicesRequest = "/v1/user/%s/devices/?filter=axolotl&api_key=%s";

std::list<std::string>* Provisioning::getAxoDeviceIds(const std::string& name, const std::string& authorization)
{
    char temp[1000];
    snprintf(temp, 990, getUserDevicesRequest, name.c_str(), authorization.c_str());

    std::string requestUri(temp);

    std::string response;
    int32_t code = ScProvisioning::httpHelper_(requestUri, GET, Empty, &response);

    if (code > 400)
        return NULL;

    std::list<std::string>* deviceIds = new std::list<std::string>;

    cJSON* root = cJSON_Parse(response.c_str());
    if (root == NULL)
        return NULL;

    cJSON* devIds = cJSON_GetObjectItem(root, "scClientDevIds");
    if (devIds == NULL || devIds->type != cJSON_Array) {
        cJSON_Delete(root);
        delete deviceIds;
        return NULL;
    }
    int32_t numIds = cJSON_GetArraySize(devIds);
    for (int32_t i = 0; i < numIds; i++) {
        std::string id(cJSON_GetArrayItem(devIds, i)->valuestring);
        deviceIds->push_back(id);
    }
    // Clear JSON buffer and context
    cJSON_Delete(root);

    return deviceIds;
}


// Implementation of the Provisioning API: Set new pre-keys
// /v1/me/device/<device_id>/axolotl/keys/?api_key=<API_key>
// Method: PUT
/*
 {
    "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
    "scClientDevId"  : <string>,         # the same string as used to register the device (v1/me/device/{device_id}/)
    "registrationId" : <int32_t>,        # this client's Axolotl registration id
    "preKeys" : [{
        "keyId" :     <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    },
....
    {
        "keyId" :     <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    }]
 }
*/
int32_t Provisioning::newPreKeys(SQLiteStoreConv* store, const string& longDevId, const string& authorization, string* result )
{
    char temp[1000];
    snprintf(temp, 990, registerRequest, longDevId.c_str(), authorization.c_str());
    std::string requestUri(temp);

    cJSON *root;
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON_AddStringToObject(root, "scClientDevId", longDevId.c_str());
//    cJSON_AddNumberToObject(root, "registrationId", store->getLocalRegistrationId());

    cJSON* jsonPkrArray;
    cJSON_AddItemToObject(root, "preKeys", jsonPkrArray = cJSON_CreateArray());

    list<pair<int32_t, const DhKeyPair*> >* preList = PreKeys::generatePreKeys(store);
    if (preList == NULL) {
        cJSON_Delete(root);
        return REG_PRE_KEY;
    }
    int32_t size = preList->size();
    for (int32_t i = 0; i < size; i++) {
        pair<int32_t, const DhKeyPair*> prePair = preList->front();
        preList->pop_front();

        cJSON* pkrObject;
        cJSON_AddItemToArray(jsonPkrArray, pkrObject = cJSON_CreateObject());
        cJSON_AddNumberToObject(pkrObject, "keyId", prePair.first);

        // Get pre-key's public key data, serialized
        const DhKeyPair* ecPair = prePair.second;
        const std::string data = ecPair->getPublicKey().serialize();

        int32_t b64Len = b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer);
        b64Buffer[b64Len] = 0;
        cJSON_AddStringToObject(pkrObject, "key", b64Buffer);
        delete ecPair;
    }
    delete preList;

    char *out = cJSON_PrintUnformatted(root);
    std::string registerRequest(out);
    cJSON_Delete(root); free(out);

    return ScProvisioning::httpHelper_(requestUri, PUT, registerRequest, result);

}
