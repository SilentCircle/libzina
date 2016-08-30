//
// Test cases to check group invitation
// Created by werner on 02.06.16.
//

#include "gtest/gtest.h"

#include "../ratchet/state/ZinaConversation.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../ratchet/crypto/EcCurve.h"
#include "../logging/AxoLogging.h"
#include "../interfaceApp/AppInterfaceImpl.h"
#include "../interfaceTransport/sip/SipTransport.h"

#include "../Constants.h"
#include "../provisioning/ScProvisioning.h"
#include "../util/b64helper.h"
#include "../keymanagment/PreKeys.h"
#include "../interfaceApp/JsonStrings.h"
#include "../util/Utilities.h"

using namespace axolotl;

static const uint8_t keyInData[] = {0,1,2,3,4,5,6,7,8,9,19,18,17,16,15,14,13,12,11,10,20,21,22,23,24,25,26,27,28,20,31,30};

static string groupDescription("This is a description");
static string groupName_1("group1");
static string groupId;


static string memberId_1("uAGroupMember1");
static string longDevId_1("def11fed");
static string apiKey_1("api_key_1");
static string memberDb_1("member_1.db");

// static pair<int32_t, const DhKeyPair*> member_1_PreKey;
static const DhKeyPair* member_1_IdKeyPair;
AppInterfaceImpl* appInterface_1;
static SQLiteStoreConv* store_1;


static string memberId_2("uAGroupMember2");
static string longDevId_2("def22fed");
static string apiKey_2("api_key_2");
static string memberDb_2("member_2.db");

static const DhKeyPair* member_2_IdKeyPair;
static pair<int32_t, const DhKeyPair*> member_2_PreKey;
AppInterfaceImpl* appInterface_2;
static SQLiteStoreConv* store_2;

static string otherMemberId_1("uAnOtherGroupMember1");
static string otherLongDevId_1("def11fed1");

static string otherMemberId_2("uAnOtherGroupMember2");
static string otherLongDevId_2("def11fed2");

const string* messageEnvelope;

extern void setTestIfObj_(AppInterfaceImpl* obj);

// Callback to send data via the transport. This function stores the first message envelope
// before it returns
// names, devIds, envelopes, sizes, msgIds
static bool sendDataTestFunction(uint8_t* names , uint8_t* devIds, uint8_t* envelopes, size_t sizes, uint64_t msgIds)
{
    LOGGER(INFO, __func__, " -->");
    messageEnvelope = new string((const char*)envelopes, sizes);
    LOGGER(INFO, __func__, " <-- ");
    return true;
}

// This simulates an answer from the provisioning server responding 400
//
static int32_t respond400(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
    LOGGER(INFO, __func__, " --> ", method, ", ", requestUrl);
    return 400;
}


// Setup the global environment for group testing/simulation, actually following Gtest structures
// to setup global and per test data and tear them down afterwards. However, because this
// test/simulation requires a controlled sequence we run it manually

/* The global setup is:
 * - for inviting user all variable/names end with _1
 * - create a database for the inviting user
 * - create necessary keys and ratchet state for member 1
 * - prepare the interface class and callbacks
 * - add an empty group
 *
 * - for invited user all variable/names end with _2
 * - create a second data base for the the invited party
 * - create necessary keys and ratchet state for member 2
 * - prepare the interface class and callbacks
 *
 * Because the data base is a singleton the test simulation needs to close the database
 * of member 1 and open the database of member 2 if it switches between the two parties.
 * For this we use a test fixture similar to Gtest .
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
        appInterface_1->setHttpHelper(respond400);

        groupId = appInterface_1->createNewGroup(groupName_1, groupDescription, 10);

        SQLiteStoreConv::closeStore();


        // ********** Create the environment for member 2
        // create/open store for member 2
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
        delete appInterface_1; delete appInterface_2;
        delete member_1_IdKeyPair;
        delete member_2_IdKeyPair;

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
        setTestIfObj_(appInterface);
        appInterface->setStore(store_1);
    }

    const SQLiteStoreConv& getStore() {return *store_1; }

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
        setTestIfObj_(appInterface);
        appInterface->setStore(store_2);
    }

    const SQLiteStoreConv& getStore() {return *store_2; }

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

static string createMessageDescriptor(const string& groupId, AppInterfaceImpl* appInterface)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();

    cJSON_AddStringToObject(root, MSG_RECIPIENT, groupId.c_str());
    cJSON_AddStringToObject(root, MSG_ID, appInterface->generateMsgIdTime().c_str());
    cJSON_AddStringToObject(root, MSG_MESSAGE, "Group test message.");

    char* out = cJSON_Print(root);
    string response(out);
    free(out);
    return response;
}

/*
 * Returns the device ids for member 2.
 * {
   "version" :        <int32_t>,        # Version of JSON new pre-keys, 1 for the first implementation
   {"devices": [{"id": <string>, "device_name": <string>}]}  # array of known Axolotl ScClientDevIds for this user/account
   }
 */
static int32_t respondDevIds_M2(const std::string& requestUrl, const std::string& method, const std::string& data, std::string* response)
{
    LOGGER(INFO, __func__, " --> ", method, ", ", requestUrl);

    size_t idx = requestUrl.find(longDevId_2);
    size_t idxMember = requestUrl.find(memberId_2);
    if (idx != string::npos && idxMember != string::npos) {
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
static string callbackCommand;

static int32_t groupCmdCallback(const string& command)
{
    LOGGER(ERROR, __func__, " -->");
    callbackCommand = command;
    LOGGER(ERROR, command);
    LOGGER(ERROR, __func__, " <--");
    return OK;
}

static string callbackMessage;

static int groupMsgCallback(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes)
{
    LOGGER(ERROR, __func__, " -->");
    callbackMessage = messageDescriptor;
    LOGGER(ERROR, messageDescriptor);
    LOGGER(ERROR, messageAttributes);
    LOGGER(ERROR, __func__, " <--");
    return OK;
}

static bool checkMembersInDb(SQLiteStoreConv& store, bool member2Only = false)
{
    if (!store.isMemberOfGroup(groupId, memberId_1)) {
        LOGGER(ERROR, __func__, " Member_1 missing after member list answer processing");
        if (!member2Only)
            return false;
    }
    if (!store.isMemberOfGroup(groupId, memberId_2)) {
        LOGGER(ERROR, __func__, " Member_2 missing after member list answer processing");
        return false;
    }
    return true;
}

static void waitForEnvelope()
{
    LOGGER(INFO, __func__, " -->");
    while (messageEnvelope == nullptr)
        sleep(1);
    LOGGER(INFO, __func__, " <--");
}

static void waitForCommand(const string pattern)
{
    LOGGER(INFO, __func__, " -->");
    size_t pos;
    while (callbackCommand.empty() || (pos = callbackCommand.find(pattern)) == std::string::npos) {
        string tmp(callbackCommand);
        sleep(1);
    }
    LOGGER(INFO, __func__, " <--");
}

class GroupInviteSend: public GroupInviteSendFixture
{
public:
    bool runSendInvite() {
        LOGGER_INSTANCE setLogLevel(ERROR);
//        ScProvisioning::setHttpHelper(respond400);

//        LOGGER(INFO, __func__, " -->");
//        int32_t result = appInterface->inviteUser(groupId, memberId_2);

        ScProvisioning::setHttpHelper(respondDevIds_M2);
        int32_t result = appInterface->inviteUser(groupId, memberId_2);
        waitForEnvelope();                  // inviteUser sends command, sync with send command callback
        LOGGER(INFO, __func__, " <--");
        return true;
    }

    bool runReceiveAnswer() {
        LOGGER_INSTANCE setLogLevel(ERROR);
        LOGGER(INFO, __func__, " -->");
        appInterface->setGroupCmdCallback(groupCmdCallback);
        callbackCommand.clear();
        appInterface->receiveMessage(*messageEnvelope, Empty, Empty);
        waitForCommand("acc"); sleep(1);
        LOGGER(INFO, __func__, " <--");
        return checkMembersInDb(*store_1);
    }

    bool runSendMessage() {
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        LOGGER(INFO, __func__, " -->");
        string message = createMessageDescriptor(groupId, appInterface);
        appInterface->sendGroupMessage(message, Empty, Empty);
        waitForEnvelope(); sleep(1);
        LOGGER(INFO, __func__, " <--");
        return true;
    }

    bool runLeaveGroup() {
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        LOGGER(INFO, __func__, " -->");
        appInterface->setOwnChecked(false);
        appInterface->leaveGroup(groupId);
        waitForEnvelope(); sleep(1);                 // leaveGroup sends data
        LOGGER(INFO, __func__, " <--");
        return true;
    }
};


static bool checkGroupInDb(const SQLiteStoreConv& store, const string& command)
{
    shared_ptr<cJSON> sharedRoot(cJSON_Parse(command.c_str()), cJSON_deleter);
    string groupId(Utilities::getJsonString(sharedRoot.get(), GROUP_ID, ""));
    int32_t result;
    pair<int32_t, time_t> attrib_time = store.getGroupAttribute(groupId, &result);
    if (attrib_time.first == ACTIVE) {
        LOGGER(INFO, __func__, " Invited user: Group ACTIVE after accepting invite");
        return true;
    }
    LOGGER(ERROR, __func__, " Invited user: No ACTIVE group after accepting invite");
    return false;
}


class GroupInviteReceive : public GroupInviteReceiveFixture {
public:
    bool runDecline() {
        LOGGER_INSTANCE setLogLevel(ERROR);
        LOGGER(INFO, __func__, " -->");
        appInterface->setGroupCmdCallback(groupCmdCallback);
        callbackCommand.clear();
        appInterface->receiveMessage(*messageEnvelope, Empty, Empty);
        waitForCommand(":");

        if (callbackCommand.empty()) {
            LOGGER(ERROR, __func__, "No INVITE answer command available.")
            return false;
        }
        appInterface->answerInvitation(callbackCommand, false, string("Some obvious reason."));
        waitForCommand("acc");                  // answerInvitation sends data
        LOGGER(INFO, __func__, " <--");
        return true;
    }

    bool runAccept() {
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        LOGGER(INFO, __func__, " -->");
        appInterface->setGroupCmdCallback(groupCmdCallback);
        appInterface->setGroupMsgCallback(groupMsgCallback);
        callbackCommand.clear();
        appInterface->receiveMessage(*messageEnvelope, Empty, Empty);
        string tmp(callbackCommand);
        waitForCommand(":");

        if (callbackCommand.empty()) {
            LOGGER(ERROR, __func__, "No INVITE answer command available.")
            return false;
        }
        string cmd(callbackCommand);
        messageEnvelope = nullptr;
        appInterface->answerInvitation(cmd, true, string("Accepted."));
        waitForEnvelope(); sleep(1);        // additional sleep to cover the second send (first sync, then to member)
        bool result = checkGroupInDb(*store_2, cmd);
        LOGGER(INFO, __func__, " <--");
        return result;
    }


    bool runReceive() {
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        LOGGER(INFO, __func__, " -->");
        appInterface->receiveMessage(*messageEnvelope, Empty, Empty);
        waitForCommand(":"); sleep(1);
        bool result = checkMembersInDb(*store_2);
        assert(result);

        LOGGER(INFO, __func__, " <--");
        return result;
    }

    bool runReceiveAfterLeave() {
        LOGGER_INSTANCE setLogLevel(VERBOSE);
        LOGGER(INFO, __func__, " -->");
        appInterface->receiveMessage(*messageEnvelope, Empty, Empty);
        sleep(1);
        bool result = checkMembersInDb(*store_2, true);
        assert(result);

        LOGGER(INFO, __func__, " <--");
        return result;
    }

};

static void inviteAndDecline()
{
    GroupEnvironment environment;
    environment.SetUp();

    GroupInviteSend send;
    GroupInviteReceive receive;

    send.SetUp();
    send.runSendInvite(); send.TearDown();
    receive.SetUp(); receive.runDecline(); receive.TearDown();
    send.SetUp();
    send.runReceiveAnswer(); send.TearDown();

    environment.TearDown();
}

static void inviteAndAcceptSendMessage()
{
    GroupEnvironment environment;
    environment.SetUp();

    GroupInviteSend send;
    GroupInviteReceive receive;

    send.SetUp();
    assert(send.runSendInvite());
    send.TearDown();

    receive.SetUp();
    assert(receive.runAccept());
    receive.TearDown();

    send.SetUp();
    send.runReceiveAnswer();
    send.TearDown();

    receive.SetUp();
    assert(receive.runReceive());
    receive.TearDown();

    send.SetUp();
    send.runSendMessage();
    send.TearDown();

    receive.SetUp();
    receive.runReceive();
    receive.TearDown();

    send.SetUp();
    send.runLeaveGroup();
    send.TearDown();

    receive.SetUp();
    receive.runReceiveAfterLeave();
    receive.TearDown();

    send.SetUp();
    send.runSendMessage();
    send.TearDown();

    receive.SetUp();
    receive.runReceiveAfterLeave();
    receive.TearDown();

    environment.TearDown();
}

int main(int argc, char** argv)
{
//    inviteAndDecline();
    inviteAndAcceptSendMessage();
    return 0;
}
