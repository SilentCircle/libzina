//
// Test cases to check group invitation
// Created by werner on 02.06.16.
//

#include "gtest/gtest.h"

#include <iostream>

#include "../axolotl/state/AxoConversation.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../axolotl/crypto/EcCurve.h"
#include "../logging/AxoLogging.h"
#include "../interfaceApp/AppInterfaceImpl.h"
#include "../interfaceTransport/sip/SipTransport.h"

#include "../Constants.h"
#include "../provisioning/ScProvisioning.h"
#include "../util/b64helper.h"
#include "../keymanagment/PreKeys.h"


static const uint8_t keyInData[] = {0,1,2,3,4,5,6,7,8,9,19,18,17,16,15,14,13,12,11,10,20,21,22,23,24,25,26,27,28,20,31,30};
using namespace axolotl;

static string groupDescription("This is a description");
static string groupName_1("group1");

static string memberId_1("uAGroupMember1");
static string longDevId_1("longDevId_1");
static const DhKeyPair* member_1_IdKeyPair;
static pair<int32_t, const DhKeyPair*> member_1_PreKey;

static SQLiteStoreConv* store;

static void sendDataTestFunction(uint8_t* [], uint8_t* [], uint8_t* [], size_t [], uint64_t []) {
    LOGGER(ERROR, __func__, " -->");
    LOGGER(ERROR, __func__, " <--");
}

class GroupInviteFixture: public ::testing::Test {
public:

    GroupInviteFixture( ) {
        // initialization code here
    }

    void SetUp() {
        // code here will execute just before the test ensues

        // Open the store with some key
        LOGGER_INSTANCE setLogLevel(ERROR);
        store = SQLiteStoreConv::getStore();
        store->setKey(std::string((const char*)keyInData, 32));
        store->openStore(std::string());

        // Create an AppInterfaceImpl
        string name("wernerd");
        string devId("myDev-id");
        appInterface = new AppInterfaceImpl(store, name, string("myAPI-key"), devId);
        Transport* sipTransport = new SipTransport(appInterface);
        sipTransport->setSendDataFunction(sendDataTestFunction);
        appInterface->setTransport(sipTransport);

        // Create an 'own' conversation and set it up
        AxoConversation* ownAxoConv = new AxoConversation(name, name, Empty);
        const DhKeyPair* idKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);
        ownAxoConv->setDHIs(idKeyPair);
        ownAxoConv->storeConversation();
        delete(ownAxoConv);

        member_1_IdKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);
        groupId = appInterface->createNewGroup(groupName_1, groupDescription);
        ASSERT_FALSE(groupId.empty());
    }

    void TearDown( ) {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        SQLiteStoreConv::closeStore();
    }

    static SQLiteStoreConv* getStore() { return store; }

    ~GroupInviteFixture( )  {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    // put in any custom data members that you need
    AppInterfaceImpl* appInterface;
    string groupId;
};

// This simulates an answer from the provisioning server responding 400
//
static int32_t respond400(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
    LOGGER(INFO, __func__, " --> ", method, ", ", requestUrl);
    return 400;
}

// This simulates an answer from the provisioning server repsoning to a get pre key request
//
//  {"axolotl": {
//      "prekey": {"id": 560544384, "key": "AcmSyjsgM6q7dhD1qMAp4chKYJEK3U/B6XYSfdrefsr"},
//      "identity_key": "AUIXDEamRULpGsdG1spm9uFdSgi2V+iUjhszedfhsafjd"
//      }
//  }
static int32_t requestPreKey(const std::string& requestUrl, const std::string& method, const std::string& reqData, std::string* response)
{
    LOGGER(INFO, __func__, " --> ", method, ", ", requestUrl);

    cJSON *root;
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    root = cJSON_CreateObject();
    cJSON* axolotl;
    cJSON_AddItemToObject(root, "axolotl", axolotl = cJSON_CreateObject());

    std::string data = member_1_IdKeyPair->getPublicKey().serialize();
    size_t b64Len = b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    cJSON_AddStringToObject(axolotl, "identity_key", b64Buffer);

    member_1_PreKey = PreKeys::generatePreKey(GroupInviteFixture::getStore());

    cJSON* jsonPkr;
    cJSON_AddItemToObject(axolotl, "preKey", jsonPkr = cJSON_CreateObject());
    cJSON_AddNumberToObject(jsonPkr, "id", member_1_PreKey.first);

    // Get pre-key's public key data, serialized and add it to JSON
    const DhKeyPair* ecPair = member_1_PreKey.second;
    data = ecPair->getPublicKey().serialize();
    b64Len = b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    cJSON_AddStringToObject(jsonPkr, "key", b64Buffer);
    delete ecPair;

    char* out = cJSON_Print(root);
    response->append(out);
    cJSON_Delete(root); free(out);
    LOGGER(INFO, __func__, " <-- ", *response);
    return 200;
}

/*
 * {
   "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
   {"devices": [{"version": 1, "id": <string>, "device_name": <string>}]}  # array of known Axolotl ScClientDevIds for this user/account
   }
 */
static int32_t respondDevIds(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
    LOGGER(INFO, __func__, " --> ", method, ", ", requestUrl);

    size_t idx = requestUrl.find(longDevId_1);
    if (idx != string::npos) {
        return requestPreKey(requestUrl, method, data, response);
    }
    cJSON *root;

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);

    cJSON* devArray;
    cJSON_AddItemToObject(root, "devices", devArray = cJSON_CreateArray());

    cJSON* device = cJSON_CreateObject();
    cJSON_AddItemToObject(device, "id", cJSON_CreateString(longDevId_1.c_str()));
    cJSON_AddItemToObject(device, "device_name", cJSON_CreateString("Device_1"));

    cJSON_AddItemToArray(devArray, device);

    char* out = cJSON_Print(root);
    response->append(out);
    cJSON_Delete(root); free(out);

    LOGGER(INFO, __func__, " <-- ", *response);
    return 200;
}

TEST_F(GroupInviteFixture, GroupInvite) {
    ScProvisioning::setHttpHelper(respond400);

    int32_t result = appInterface->inviteUser(groupId, memberId_1);
    ASSERT_EQ(NETWORK_ERROR, result);

    ScProvisioning::setHttpHelper(respondDevIds);
    result = appInterface->inviteUser(groupId, memberId_1);
    ASSERT_EQ(SUCCESS, result);

}