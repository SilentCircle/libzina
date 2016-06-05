//
// Test cases to check group invitation
// Created by werner on 02.06.16.
//

#include "gtest/gtest.h"

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

using namespace axolotl;

static const uint8_t keyInData[] = {0,1,2,3,4,5,6,7,8,9,19,18,17,16,15,14,13,12,11,10,20,21,22,23,24,25,26,27,28,20,31,30};

static string groupDescription("This is a description");
static string groupName_1("group1");
static string groupId;


static string memberId_1("uAGroupMember1");
static string longDevId_1("def11fed");
static const DhKeyPair* member_1_IdKeyPair;
static string apiKey_1("api_key_1");
static string memberDb_1("member_1.db");
// static pair<int32_t, const DhKeyPair*> member_1_PreKey;
AppInterfaceImpl* appInterface_1;
static SQLiteStoreConv* store_1;


static string memberId_2("uAGroupMember2");
static string longDevId_2("def22fed");
static const DhKeyPair* member_2_IdKeyPair;
static pair<int32_t, const DhKeyPair*> member_2_PreKey;
static string apiKey_2("api_key_2");
static string memberDb_2("member_2.db");
AppInterfaceImpl* appInterface_2;
static SQLiteStoreConv* store_2;

const string* messageEnvelope;

// Callback to send data via the transport. This function stores the first message envelope
// before it returns
// names, devIds, envelopes, sizes, msgIds
static void sendDataTestFunction(uint8_t* names[] , uint8_t* devIds[], uint8_t* envelopes[], size_t sizes[], uint64_t msgIds[])
{
    LOGGER(INFO, __func__, " -->");
    messageEnvelope = new string((const char*)envelopes[0], sizes[0]);
    LOGGER(INFO, __func__, " <--");
}


// Setup the global environment for group testing/simulatio, actually following Gtest structures
// to setup global and per test data and tear them down afterwards. However, because this
// test/simulation requires a controlled sequence we run it manually

/* The setup is:
 * - create a database for the inviting user, all variable/names end with _1
 * - create necessary keys and ratchet state for member 1
 * - prepare the interface class and callbacks
 * - add a empty group
 *
 * - create a second data base for the the invited party
 * - create necessary keys and ratchet state for member 2
 * - prepare the interface class and callbacks
 *
 * Because the data base is a singleton the test simulation needs to close the database
 * of member 1 and open the database of member 2 if it switches between the two parties.
 * For this we use the test fixture of Gtest, however this requires that the test cases
 * run in a particular order - which is usually not allowed in unit tests ;-) .
 */
class GroupEnvironment {
public:
    void SetUp() {
        LOGGER_INSTANCE setLogLevel(ERROR);
        LOGGER(INFO, __func__, " -->");
        unlink(memberDb_1.c_str());
        unlink(memberDb_2.c_str());

        // ********** Create the environment for member 1
        // create/open store for member 1
        store_1 = SQLiteStoreConv::getStore();
        store_1->setKey(std::string((const char*)keyInData, 32));
        store_1->openStore(memberDb_1);

        // AppInterfaceImpl
        appInterface_1 = new AppInterfaceImpl(store_1, memberId_1, apiKey_1, longDevId_1);
        member_1_IdKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);

        // Create an 'own' conversation and set it up
        AxoConversation* ownAxoConv = new AxoConversation(memberId_1, memberId_1, Empty);
        ownAxoConv->setDHIs(new DhKeyPair(*member_1_IdKeyPair));
        ownAxoConv->storeConversation();
        delete(ownAxoConv);

        Transport* sipTransport = new SipTransport(appInterface_1);
        sipTransport->setSendDataFunction(sendDataTestFunction);
        appInterface_1->setTransport(sipTransport);

        groupId = appInterface_1->createNewGroup(groupName_1, groupDescription);

        SQLiteStoreConv::closeStore();


        // ********** Create the environment for member 2
        // create/open store for member 1
        store_2 = SQLiteStoreConv::getStore();
        store_2->setKey(std::string((const char*)keyInData, 32));
        store_2->openStore(memberDb_2);

        // AppInterfaceImpl
        appInterface_2 = new AppInterfaceImpl(store_2, memberId_2, apiKey_2, longDevId_2);
        member_2_IdKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);

        member_2_PreKey = PreKeys::generatePreKey(store_2);

        // Create an 'own' conversation and set it up
        ownAxoConv = new AxoConversation(memberId_2, memberId_2, Empty);
        ownAxoConv->setDHIs(new DhKeyPair(*member_2_IdKeyPair));
        ownAxoConv->storeConversation();
        delete(ownAxoConv);

        sipTransport = new SipTransport(appInterface_2);
        sipTransport->setSendDataFunction(sendDataTestFunction);
        appInterface_2->setTransport(sipTransport);

        SQLiteStoreConv::closeStore();

        LOGGER(INFO, __func__, " <--");
    }

    void TearDown() {
        LOGGER(INFO, __func__, " -->");
        LOGGER(INFO, __func__, " <--");
    }
};

GroupEnvironment* environment;

class GroupInviteSendFixture {
public:

    GroupInviteSendFixture( ) {
        // initialization code here
    }

    void SetUp() {
        // code here will execute just before the test ensues

        // Open the store with some key
        LOGGER_INSTANCE setLogLevel(ERROR);
        store_1 = SQLiteStoreConv::getStore();
        store_1->setKey(std::string((const char*)keyInData, 32));
        store_1->openStore(memberDb_1);

        appInterface = appInterface_1;
        appInterface->setStore(store_1);
    }

    void TearDown( ) {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        SQLiteStoreConv::closeStore();
        appInterface = NULL;            // don't delete the global environment
    }

    ~GroupInviteSendFixture( )  {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    AppInterfaceImpl* appInterface;
};

class GroupInviteReceiveFixture {
public:

    GroupInviteReceiveFixture( ) {
        // initialization code here
    }

    void SetUp() {
        // code here will execute just before the test ensues

        // Open the store with some key
        LOGGER_INSTANCE setLogLevel(ERROR);
        store_2 = SQLiteStoreConv::getStore();
        store_2->setKey(std::string((const char*)keyInData, 32));
        store_2->openStore(memberDb_2);

        appInterface = appInterface_2;
        appInterface->setStore(store_2);
    }

    void TearDown( ) {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        SQLiteStoreConv::closeStore();
        appInterface = NULL;            // don't delete the global environment
    }

    ~GroupInviteReceiveFixture( )  {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    AppInterfaceImpl* appInterface;
};

// This simulates an answer from the provisioning server responding 400
//
static int32_t respond400(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
    LOGGER(INFO, __func__, " --> ", method, ", ", requestUrl);
    return 400;
}

// This simulates an answer from the provisioning server responding to a get pre key request
// Returns a pre-key bundle for member 2, also initializes its long term id key if not yet available.
//
//  {"axolotl": {
//      "prekey": {"id": 560544384, "key": "AcmSyjsgM6q7dhD1qMAp4chKYJEK3U/B6XYSfdrefsr"},
//      "identity_key": "AUIXDEamRULpGsdG1spm9uFdSgi2V+iUjhszedfhsafjd"
//      }
//  }
static int32_t requestPreKey_M2(const std::string& requestUrl, const std::string& method, const std::string& reqData, std::string* response)
{
    LOGGER(INFO, __func__, " --> ", method, ", ", requestUrl);

    cJSON *root;
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    root = cJSON_CreateObject();
    cJSON* axolotl;
    cJSON_AddItemToObject(root, "axolotl", axolotl = cJSON_CreateObject());

    std::string data = member_2_IdKeyPair->getPublicKey().serialize();
    size_t b64Len = b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    cJSON_AddStringToObject(axolotl, "identity_key", b64Buffer);

    cJSON* jsonPkr;
    cJSON_AddItemToObject(axolotl, "preKey", jsonPkr = cJSON_CreateObject());
    cJSON_AddNumberToObject(jsonPkr, "id", member_2_PreKey.first);

    // Get pre-key's public key data, serialized and add it to JSON
    const DhKeyPair* ecPair = member_2_PreKey.second;
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
 * Returns the device ids for member 2.
 * {
   "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
   {"devices": [{"version": 1, "id": <string>, "device_name": <string>}]}  # array of known Axolotl ScClientDevIds for this user/account
   }
 */
static int32_t respondDevIds_M2(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
    LOGGER(INFO, __func__, " --> ", method, ", ", requestUrl);

    size_t idx = requestUrl.find(longDevId_2);
    if (idx != string::npos) {
        return requestPreKey_M2(requestUrl, method, data, response);
    }
    cJSON *root;

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);

    cJSON* devArray;
    cJSON_AddItemToObject(root, "devices", devArray = cJSON_CreateArray());

    cJSON* device = cJSON_CreateObject();
    cJSON_AddItemToObject(device, "id", cJSON_CreateString(longDevId_2.c_str()));
    cJSON_AddItemToObject(device, "device_name", cJSON_CreateString("Device_2"));

    cJSON_AddItemToArray(devArray, device);

    char* out = cJSON_Print(root);
    response->append(out);
    cJSON_Delete(root); free(out);

    LOGGER(INFO, __func__, " <-- ", *response);
    return 200;
}

class GroupInviteSend: public GroupInviteSendFixture
{
public:
    bool runInvite() {
        ScProvisioning::setHttpHelper(respond400);

        LOGGER(INFO, __func__, " -->");
        int32_t result = appInterface->inviteUser(groupId, memberId_2);

        ScProvisioning::setHttpHelper(respondDevIds_M2);
        result = appInterface->inviteUser(groupId, memberId_2);
        LOGGER(INFO, __func__, " <--");
    }

    bool receiverAnswer() {
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        appInterface->receiveMessage(*messageEnvelope);
    }
};

static string callbackCommand;

int32_t groupCmdCallback(const string& command)
{
    LOGGER(ERROR, __func__, " -->");
    callbackCommand = command;
    LOGGER(ERROR, command);
    LOGGER(ERROR, __func__, " <--");
}

class GroupInviteReceive : public GroupInviteReceiveFixture {
public:
    bool runDecline() {
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        LOGGER(INFO, __func__, " -->");
        appInterface->setGroupCmdCallback(groupCmdCallback);
        callbackCommand.clear();
        appInterface->receiveMessage(*messageEnvelope);

        if (callbackCommand.empty()) {
            LOGGER(ERROR, __func__, "No INVITE command available.")
            return false;
        }
        appInterface->answerInvitation(callbackCommand, false, string("Some obvious reason."));
        LOGGER(INFO, __func__, " <--");
        return true;
    }
};


static void inviteAndDecline()
{
    GroupEnvironment environment;
    environment.SetUp();

    GroupInviteSend send;
    GroupInviteReceive receive;

    send.SetUp(); send.runInvite(); send.TearDown();
    receive.SetUp(); receive.runDecline(); receive.TearDown();
    send.SetUp(); send.receiverAnswer(); send.TearDown();

    environment.TearDown();
}

int main(int argc, char** argv)
{
    inviteAndDecline();
}
