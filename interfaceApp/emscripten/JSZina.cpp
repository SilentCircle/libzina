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

#include <stdio.h>
#include <codecvt>

#include "../AppInterfaceImpl.h"
#include "../../provisioning/Provisioning.h"
#include "../../appRepository/AppRepository.h"
#include "../../interfaceTransport/sip/SipTransport.h"
#include "../../ratchet/crypto/EcCurve.h"
#include "../../attachments/fileHandler/scloud.h"
#include "../../storage/NameLookup.h"
#include "../../util/UUID.h"
#include "../../util/b64helper.h"
#include "../../util/Utilities.h"
#include <cryptcommon/ZrtpRandom.h>
#include <zrtp/crypto/sha256.h>

#include <emscripten.h>
#include <emscripten/bind.h>
#include <iostream>
#include <fstream>
#include <iterator>
using namespace emscripten;
using namespace zina;
using namespace std;

extern "C" {
  // Implemented in JavaScript
  extern char* httpRequest(const char* requestUri, const char* method, const char* requestData, int32_t* code);
  extern char* makeReadNotificationJSON();
  extern void mountFilesystem();
}

static string toUTF8(const wstring& s) {
  wstring_convert<codecvt_utf8_utf16<wchar_t>, wchar_t> convertor;
  return convertor.to_bytes(s);
}

static wstring toUTF16(const string& s) {
  wstring_convert<codecvt_utf8_utf16<wchar_t>, wchar_t> convertor;
  return convertor.from_bytes(s);
}


static int32_t debugLevel = -1;
void Log(char const *format, ...) {
    va_list arg;
    va_start(arg, format);
    if (debugLevel >= DEBUGGING) {
      vfprintf(stderr, format, arg);
      fprintf(stderr, "\n");
    }
    va_end(arg);
}

class JSZina {
private:
    AppInterfaceImpl* zinaAppInterface_;
    string scClientDeviceId_;
    string provisionUrl_;
    int sendCallback_;
    int receiveCallback_;
    int notifyCallback_;
    int messageStateCallback_;
    int groupCommandCallback_;
    int groupMessageCallback_;
    int groupStateCallback_;

private:
    shared_ptr<list<shared_ptr<PreparedMessageData> > > prepareMessage(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes, bool normal, int code[]);
    int doSendMessageInternal(uint64_t ids[], int n);
    void sendSyncOutgoing(string const& username, string const& displayName, string const& message, string const& attributes, shared_ptr<std::list<std::shared_ptr<PreparedMessageData> > > &preparedMessageData);
    void sendSyncBurn(string const& username, string const& message_json, string const& attributes);
    void sendSyncReadNotification(string const& username, string const& message_json, string const& attributes);
    string makeMessageJSON(const string& username, const string& message, const string& deviceId, const string& messageId);
    string makeAttributeJSON(bool readReceipt, long burnSeconds);

    // Return a string containing the hex characters of a transport Id
    string transportIdHex(int64_t transportId);

    // Request AccountsWeb to delete the device
    bool deleteDevice(const string& device);

public:
    bool sendData(uint8_t* names, uint8_t* devIds, uint8_t* envelope, size_t size, uint64_t msgIds);
    int32_t receiveMessage(const string& messageDescriptor, const string& attachmentDescriptor, const string& msgAttributes);
    void callNotify(int msgId, string actionCode, string actionInfo);
    void callMessageState(int64_t msgId, int32_t stateCode, string stateinfo);
    int callGroupCommand(string command);
    int callGroupMessage(const string& messageDescriptor, const string& attachmentDescriptor, const string& msgAttributes);
    void callGroupState(int32_t errorCode, const string& stateInformation);
    string httpRequest(const string& requestUri, const string& method, const string& requestData, int32_t* code);

public:
    JSZina() : zinaAppInterface_(nullptr), sendCallback_(0), receiveCallback_(0), notifyCallback_(0), messageStateCallback_(0), groupCommandCallback_(0), groupMessageCallback_(0), groupStateCallback_(0) { }
    // TODO: Should be string& parms.
    int doInit(int flags, const wstring& provisionUrl, const wstring& hash, const wstring& dbPassphrase, const wstring& userName, const wstring& authorization, const wstring& scClientDeviceId);
    int registerZinaDevice();
    void registerSendCallback(int n) { sendCallback_ = n; }
    void registerReceiveCallback(int n) { receiveCallback_ = n; }
    void registerNotifyCallback(int n) { notifyCallback_ = n; }
    void registerMessageStateCallback(int n) { messageStateCallback_ = n; }
    void registerGroupCommandCallback(int n) { groupCommandCallback_ = n; }
    void registerGroupMessageCallback(int n) { groupMessageCallback_ = n; }
    void registerGroupStateCallback(int n) { groupStateCallback_ = n; }

    // Prepare a message to the user. Returns the message UUID of the message.
    // Stores an array of JSON strings in 'deviceMessages'. Each item
    // in the array is a JSON object containing:
    //   transportId: string => transport id of the message sent to a specific device in hex format.
    //   receiverInfo: string => Information about the receiver of the message.
    // This data in 'deviceMessages' can be used to map error messages to messages on the JS side.
    // To actually send the message call 'doSendMessage' after this function is called.
    string prepareSimpleMessage(const wstring& user, const wstring& displayName, const wstring& message, long burnSeconds, vector<string>& deviceMessageData);

    // Send previously prepared messages. Expects an array of strings containing the hex version
    // of the transport id. This is the same transportId returned in the 'deviceMessageData'
    // parameter of 'prepareSimpleMessage'. Returns >=0 on success.
    int doSendMessage(const vector<string>& transportIds);

    string resendMessage(const wstring& messageId, const wstring& username, const wstring& displayName, const wstring& message, long burnSeconds);
    bool sendBurnMessage(const wstring& user, const wstring& messageId);
    bool sendBurnConfirmation(const wstring& username, const wstring& messageId);
    bool sendReadNotification(const wstring& username, const wstring& messageId);
    bool sendEmptySyncToSiblings(const wstring& username);

    // TODO: Implement return value
    void removeZinaDevice(const wstring& deviceId);
    void receiveSipMessage(const wstring& msg);
    void receiveSipNotify(const wstring& msg);

    // Functions for browser clients to initialize/sync file system
    static void initializeFS();
    static string getStoredApiKey(const wstring& hash);
    static void setStoredApiKey(const wstring& hash, const wstring& key);
    static string getStoredDeviceId(const wstring& hash);
    static void setStoredDeviceId(const wstring& hash, const wstring& device);
    static void syncFS();

    // Erase all information about the device stored in browser storage
    // and delete our current device.
    bool wipe(const wstring& hash);

    // Scan for new sibling devices
    void rescanSiblingDevices(const wstring& username);

    // Resync conversation
    void resyncConversation(const wstring& username, const wstring& deviceId);

    // Request a user's ZINA device names.
    string getZinaDevicesUser(const wstring& username);

    // Request names of known trusted ZINA user identities.
    string getKnownUsers();

    // Get public part of own identity key
    string getOwnIdentityKey();

    // Get a list of all identity keys of a remote party.
    void getIdentityKeys(const wstring& user, vector<string>& result);

    // Generate and register a set of new pre-keys.
    int newPreKeys(int number);

    // Get number of pre-keys available on the server.
    int getNumPreKeys();

    // Create a new group and assign ownership to the creator
    string createNewGroup(const wstring& groupName, const wstring& groupDescription);

    // Modify number maximum group member.
    bool modifyGroupSize(const wstring& uuid, int newSize);

    // Set a group's new name.
    int setGroupName(const wstring& uuid, const wstring& name);

    // Set a group's new burn time and mode.
    int setGroupBurnTime(const wstring& uuid, long burnTime, int mode);

    // Set a group's new avatar data.
    int setGroupAvatar(const wstring& uuid, string avatar);

    // Get data of all known groups.
    int listAllGroups(vector<string>& groups);

    // Get data of all known groups which have certain user as participant.
    int listAllGroupsWithMember(const wstring& participantUuid, vector<string>& groups);

    // Get data of a single group.
    string getGroup(const wstring& uuid);

    // Get all members of a specified group.
    int getAllGroupMembers(const wstring& uuid, vector<string>& members);

    // Get a member of a specified group.
    string getGroupMember(const wstring& uuid, string memberUuid);

    // Add a user to a group (same as invite)
    int addUser(const wstring& uuid, const wstring& userId);

    // Remove a user's name from the add member update change set.
    int removeUserFromAddUpdate(const wstring& uuid, const wstring& userId);

    // Cancel group's current change set.
    int cancelGroupChangeSet(const wstring& uuid);

    // Apply group's current change set.
    int applyGroupChangeSet(const wstring& uuid);

    // Leave a group.
    int leaveGroup(const wstring& uuid);

    // Remove another member (not myself) from a group.
    int removeUser(const wstring& uuid, const wstring& userId);

    // Remove a user's name from the remove member update change set.
    int removeUserFromRemoveUpdate(const wstring& uuid, const wstring& userId);

    // Send a group message
    wstring sendGroupMessage(const wstring& uuid, const wstring& message, long burnSeconds);

    // Set level for debug logging
    void setZinaLogLevel(int level);

    // Manually burn a group message
    int burnGroupMessage(const wstring& uuid, const wstring& msgId);

    // Get the canonical name (Uid) for the user.
    wstring getUid(const wstring& userid16, const wstring& auth16);
};

// TODO: Find a way around using a global
static JSZina* g_axo = nullptr;

int32_t httpHelper(const string& requestUri, const string& method, const string& requestData, string* response)
{
    int32_t code = 0;
    if (g_axo) {
        *response = g_axo->httpRequest(requestUri, method, requestData, &code);
    }
    return code;
}

bool g_sendDataFuncAxoNew(uint8_t* names, uint8_t* devId, uint8_t* envelope, size_t size, uint64_t msgIds)
{
    return g_axo->sendData(names, devId, envelope, size, msgIds);
}

typedef int32_t (*RECV_FUNC)(const string&, const string&, const string&);
typedef void (*STATE_FUNC)(int64_t, int32_t, const string&);
typedef void (*NOTIFY_FUNC)(int32_t, const string&, const string&);

typedef int32_t (*GROUP_CMD_RECV_FUNC)(const string& commandMessage);
typedef int32_t (*GROUP_MSG_RECV_FUNC)(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes);
typedef void (*GROUP_STATE_FUNC)(int32_t errorCode, const string& stateInformation);

static int32_t recv_func(const string& msgDescriptor, const string& attachmentDescriptor, const string& msgAttributes) {
    return g_axo->receiveMessage(msgDescriptor, attachmentDescriptor, msgAttributes);
}

static void state_func(int64_t msgId, int32_t stateCode, const string& stateInfo) {
  Log("state_func: %lld %d [%s]", msgId, stateCode, stateInfo.c_str());
  g_axo->callMessageState(msgId, stateCode, stateInfo);
}

static void notify_func(int32_t msgId, const string& actionCode, const string& actionInfo) {
  Log("notify_func: %d %s [%s]", msgId, actionCode.c_str(), actionInfo.c_str());
  if (msgId == AppInterface::DEVICE_SCAN && actionCode.size() > 0) {
    // actionCode is username, actionInfo is list of devices
    g_axo->rescanSiblingDevices(toUTF16(actionCode));
  }
  g_axo->callNotify(msgId, actionCode, actionInfo);
}

static int32_t receive_group_command_func(const string& commandMessage) {
    return g_axo->callGroupCommand(commandMessage);
}

static int32_t receive_group_message_func(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes) {
    return g_axo->callGroupMessage(messageDescriptor, attachmentDescriptor, messageAttributes);
}

static void group_state_report_func(int32_t errorCode, const string& stateInformation) {
    g_axo->callGroupState(errorCode, stateInformation);
}

string JSZina::httpRequest(const string& requestUri, const string& method, const string& requestData, int32_t* code)
{
    Log("httpRequest called: [%s%s] [%s]", provisionUrl_.c_str(), requestUri.c_str(), method.c_str());
    char* buffer = ::httpRequest((provisionUrl_ + requestUri).c_str(), method.c_str(), requestData.c_str(), code);
    string r(buffer);
    free(buffer);
    return r;
}

int JSZina::doInit(int flags, const wstring& provisionUrl, const wstring& hash16, const wstring& dbPassphrase16, const wstring& userName16, const wstring& authorization16, const wstring& scClientDeviceId16)
{
    string hash = toUTF8(hash16);
    string dbPassphrase = toUTF8(dbPassphrase16);
    string userName = toUTF8(userName16);
    string authorization = toUTF8(authorization16);
    string scClientDeviceId = toUTF8(scClientDeviceId16);
    provisionUrl_ = toUTF8(provisionUrl);

    debugLevel = flags & 0xf;
    void setZinaLogLevel(int32_t level);
    ::setZinaLogLevel(debugLevel);

    string dbName = "/axolotl/" + hash + "_db.db";
    if (dbPassphrase.size() != 32)
        return -15;

    g_axo = this;

    mountFilesystem();
    // initialize and open the persistent store singleton instance
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    store->setKey(dbPassphrase);
    store->openStore(dbName);

    Utilities::wipeMemory((void*)dbPassphrase.data(), dbPassphrase.size());

    int32_t retVal = 1;
    auto ownZinaConv = ZinaConversation::loadLocalConversation(userName, *store);
    if (!ownZinaConv->isValid()) {  // no yet available, create one. An own conversation has the same local and remote name, empty device id
        KeyPairUnique idKeyPair = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);
        ownZinaConv->setDHIs(move(idKeyPair));
        ownZinaConv->storeConversation(*store);
        retVal = 2;
    }

    zinaAppInterface_ = new AppInterfaceImpl(userName, authorization, scClientDeviceId, recv_func, state_func, notify_func,
                                            receive_group_message_func, receive_group_command_func, group_state_report_func);
    // No data retention implemented at this point
    string retentionFlags = "{\"lrmr\":false,\"lrmp\":false,\"lrap\":false,\"bldr\":false,\"blmr\":false,\"brdr\":false,\"brmr\":false}";
    zinaAppInterface_->setDataRetentionFlags(retentionFlags);
    scClientDeviceId_ = scClientDeviceId;
    Transport* sipTransport = new SipTransport(zinaAppInterface_);

    /* ***********************************************************************************
     * Initialize pointers/callback to the send/receive SIP data functions (network layer)
     */
#if defined(EMBEDDED)
    // Functions defined in t_a_main module of silentphone library, this sends the data
    // via SIP message
//    void g_sendDataFuncAxo(uint8_t* names[], uint8_t* devIds[], uint8_t* envelopes[], size_t sizes[], uint64_t msgIds[]);
    bool g_sendDataFuncAxoNew(uint8_t* names, uint8_t* devId, uint8_t* envelope, size_t size, uint64_t msgIds);

    sipTransport->setSendDataFunction(g_sendDataFuncAxoNew);

#else
#error "***** Missing initialization."
#endif
    /* *********************************************************************************
     * set sipTransport class to SIP network handler, sipTransport contains callback
     * functions 'receiveAxoData' and 'stateReportAxo'
     *********************************************************************************** */
    zinaAppInterface_->setHttpHelper(httpHelper);
    zinaAppInterface_->setTransport(sipTransport);

    return retVal;
}

int JSZina::registerZinaDevice()
{
    string info;
    int32_t result = zinaAppInterface_->registerZinaDevice(&info);
    return result;
}

shared_ptr<list<shared_ptr<PreparedMessageData> > > JSZina::prepareMessage(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes, bool normal, int code[])
{
    if (/* code == NULL || env->GetArrayLength(code) < 1 ||*/ messageDescriptor.empty() || zinaAppInterface_ == NULL)
        return NULL;

    //LOG("prepareMessage - message: '%s' - length: %d", messageDescriptor.c_str(), messageDescriptor.size());

    // TODO: Implement attachment handling and attributes. Ignore for now.
   // LOG("prepareMessage - attributes: '%s' - length: %d", messageAttributes.c_str(), messageAttributes.size());

    int32_t error;
    auto prepMessageData = zinaAppInterface_->prepareMessage(messageDescriptor, attachmentDescriptor, messageAttributes, true, &error);
    if (error != SUCCESS) {
        //TODO: setReturnCode(env, code, error);
        return NULL;
    }

    return prepMessageData;
}

int JSZina::doSendMessage(const vector<string>& transportIds)
{
    if (transportIds.size() == 0)
        return DATA_MISSING;

    auto idVector = make_shared<vector<uint64_t> >();
    for (string transportId : transportIds) {
        if (transportId.size() != sizeof(uint64_t) * 2)
            return GENERIC_ERROR;

        uint64_t id = 0;
        size_t r = hex2bin(transportId.c_str(), (uint8_t*)&id);
        if (r == (size_t)-1)
            return GENERIC_ERROR;
        idVector->push_back(id);
    }

    return zinaAppInterface_->doSendMessages(idVector);
}

int JSZina::doSendMessageInternal(uint64_t ids[], int dataLen)
{

    if (dataLen < 1)
        return DATA_MISSING;

    auto idVector = make_shared<vector<uint64_t> >();

    for (size_t i = 0; i < dataLen; i++) {
        idVector->push_back(ids[i]);
     }

    return zinaAppInterface_->doSendMessages(idVector);
}

string JSZina::prepareSimpleMessage(const wstring& username16, const wstring& displayName16, const wstring& message16, long burnSeconds, vector<string>& deviceMessageData)
{
    string username = toUTF8(username16);
    string displayName = toUTF8(displayName16);
    string message = toUTF8(message16);

    if (username.empty() || message.empty())
        return "";

    uuid_t pingUuid = {0};
    uuid_string_t uuidString = {0};

    uuid_generate_time(pingUuid);
    uuid_unparse(pingUuid, uuidString);
    string messageId(uuidString);

    string json = makeMessageJSON(username, message, scClientDeviceId_, messageId);
    string attributes = makeAttributeJSON(true, burnSeconds);

    Log("sendSimpleMessage: [%s] [%s]", json.c_str(), attributes.c_str());
    int code[1];
    auto preparedMessageData = prepareMessage(json, "", attributes, true, code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code[0], "unknown");
        return "";
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
        JsonUnique sharedRoot(cJSON_CreateObject());
        cJSON* root = sharedRoot.get();
        cJSON_AddStringToObject(root, "transportId", transportIdHex(msgD->transportId).c_str());
        cJSON_AddStringToObject(root, "receiverInfo", msgD->receiverInfo.c_str());
        CharUnique out(cJSON_PrintUnformatted(root));
        deviceMessageData.push_back(out.get());
    }

    sendSyncOutgoing(username, displayName, json, attributes, preparedMessageData);

    return messageId;
}

string JSZina::resendMessage(const wstring& messageId16, const wstring& username16, const wstring& displayName16, const wstring& message16, long burnSeconds)
{
    string messageId = toUTF8(messageId16);
    string username = toUTF8(username16);
    string displayName = toUTF8(displayName16);
    string message = toUTF8(message16);

    if (username.empty() || message.empty() || messageId.empty())
        return "";

    string json = makeMessageJSON(username, message, scClientDeviceId_, messageId);
    string attributes = makeAttributeJSON(true, burnSeconds);

    Log("resendMessage: [%s] [%s]", json.c_str(), attributes.c_str());
    int code[1];
    auto preparedMessageData = prepareMessage(json, "", attributes, true, code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code[0], "unknown");
        return "";
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
    }

    doSendMessageInternal(transportIds, size);

    return messageId;
}


bool JSZina::sendBurnMessage(const wstring& username16, const wstring& messageId16)
{
    string username = toUTF8(username16);
    string messageId = toUTF8(messageId16);

    if (username.empty() || messageId.empty())
        return false;

    string json = makeMessageJSON(username, "", scClientDeviceId_, messageId);
    const char* attributes = "{\"cmd\":\"bn\"}";

    Log("sendBurnMessage: [%s] [%s]", json.c_str(), attributes);

    int code[1];
    auto preparedMessageData = prepareMessage(json, "", attributes, false, code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code[0], "unknown");
        return false;
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
    }

    doSendMessageInternal(transportIds, size);

    sendSyncBurn(username, json, attributes);

    return true;
}

bool JSZina::sendBurnConfirmation(const wstring& username16, const wstring& messageId16)
{
    string username = toUTF8(username16);
    string messageId = toUTF8(messageId16);

    if (username.empty() || messageId.empty())
        return false;

    string json = makeMessageJSON(username, "", scClientDeviceId_, messageId);
    const char* attributes = "{\"cmd\":\"bnc\"}";

    Log("sendBurnNotification: [%s] [%s]", json.c_str(), attributes);

    int code[1];
    auto preparedMessageData = prepareMessage(json, "", attributes, false, code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code[0], "unknown");
        return false;
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
    }

    doSendMessageInternal(transportIds, size);

    return true;
}

bool JSZina::sendReadNotification(const wstring& username16, const wstring& messageId16)
{
    string username = toUTF8(username16);
    string messageId = toUTF8(messageId16);

    if (username.empty() || messageId.empty())
        return false;

    string json = makeMessageJSON(username, "", scClientDeviceId_, messageId);
    char* attributes = makeReadNotificationJSON();

    Log("sendReadNotification: [%s] [%s]", json.c_str(), attributes);

    int code[1];
    auto preparedMessageData = prepareMessage(json, "", attributes, false, code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code[0], "unknown");
        free(attributes);
        return false;
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
    }

    doSendMessageInternal(transportIds, size);

    sendSyncReadNotification(username, json, attributes);

    free(attributes);
    return true;
}

bool JSZina::sendEmptySyncToSiblings(const wstring& username16)
{
    string username = toUTF8(username16);

    if (username.empty())
        return false;

    uuid_t pingUuid = {0};
    uuid_string_t uuidString = {0};

    uuid_generate_time(pingUuid);
    uuid_unparse(pingUuid, uuidString);
    string messageId(uuidString);

    string json = makeMessageJSON(username, "", scClientDeviceId_, messageId);
    const char* attributes = "{\"cmd\":\"sye\"}";

    Log("sendEmptySyncToSiblings: [%s] [%s]", json.c_str(), attributes);

    int code[1];
    auto preparedMessageData = zinaAppInterface_->prepareMessageToSiblings(json, "", attributes, true, code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code[0], "unknown");
        return false;
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
    }

    doSendMessageInternal(transportIds, size);
    return true;
}


void JSZina::sendSyncOutgoing(string const& username, string const& displayName, string const& message_json, string const& attributes, shared_ptr<std::list<std::shared_ptr<PreparedMessageData> > > &siblingMessageData) {
    JsonUnique sharedRoot(cJSON_Parse(attributes.c_str()));
    if (!sharedRoot.get()) {
      sharedRoot.reset(cJSON_CreateObject());
    }

    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, "syc", "om");
    cJSON_AddStringToObject(root, "or", username.c_str());
    cJSON_AddStringToObject(root, "dpn",  displayName.c_str());
    cJSON* ids = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "rcvInfo", ids);
    for (auto& msgD : *siblingMessageData) {
      cJSON_AddItemToArray(ids, cJSON_CreateString(msgD->receiverInfo.c_str()));
    }

    CharUnique out(cJSON_PrintUnformatted(root));
    string attr(out.get());

    Log("sendSyncOutgoing: [%s] [%s]", message_json.c_str(), attr.c_str());
    int32_t code;
    auto preparedMessageData = zinaAppInterface_->prepareMessageToSiblings(message_json, "", attr, false, &code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code, "unknown");
        return;
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
    }

    doSendMessageInternal(transportIds, size);
}

void JSZina::sendSyncBurn(string const& username, string const& message_json, string const& attributes) {
    JsonUnique sharedRoot(cJSON_Parse(attributes.c_str()));
    if (!sharedRoot.get()) {
      sharedRoot.reset(cJSON_CreateObject());
    }

    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, "syc", "bn");
    cJSON_AddStringToObject(root, "or", username.c_str());

    CharUnique out(cJSON_PrintUnformatted(root));
    string attr(out.get());

    Log("sendSyncBurn: [%s] [%s]", message_json.c_str(), attr.c_str());
    int32_t code;
    auto preparedMessageData = zinaAppInterface_->prepareMessageToSiblings(message_json, "", attr, false, &code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code, "unknown");
        return;
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
    }

    doSendMessageInternal(transportIds, size);
}

void JSZina::sendSyncReadNotification(string const& username, string const& message_json, string const& attributes) {
    JsonUnique sharedRoot(cJSON_Parse(attributes.c_str()));
    if (!sharedRoot.get()) {
      sharedRoot.reset(cJSON_CreateObject());
    }

    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, "syc", "rr");
    cJSON_AddStringToObject(root, "or", username.c_str());

    CharUnique out(cJSON_PrintUnformatted(root));
    string attr(out.get());

    Log("sendSyncReadNotification: [%s] [%s]", message_json.c_str(), attr.c_str());
    int32_t code;
    auto preparedMessageData = zinaAppInterface_->prepareMessageToSiblings(message_json, "", attr, false, &code);

    if (!preparedMessageData) {
        Log("Message to '%s' could not be sent, code: %d, info: %s", username.c_str(), code, "unknown");
        return;
    }

    size_t size = preparedMessageData->size();
    uint64_t transportIds[size];

    int idx = 0;
    for (auto& msgD : *preparedMessageData) {
        transportIds[idx++] = msgD->transportId;
    }

    doSendMessageInternal(transportIds, size);
}

string JSZina::makeMessageJSON(const string& username, const string& message, const string& deviceId, const string& messageId)
{
    JsonUnique root(cJSON_CreateObject());
    cJSON_AddItemToObject(root.get(), "version", cJSON_CreateNumber(1));
    cJSON_AddStringToObject(root.get(), "recipient", username.c_str());
    cJSON_AddStringToObject(root.get(), "scClientDevId", deviceId.c_str());
    cJSON_AddStringToObject(root.get(), "msgId", messageId.c_str());
    cJSON_AddStringToObject(root.get(), "message", message.c_str());

    CharUnique out(cJSON_PrintUnformatted(root.get()));
    string json(out.get());
    return json;
}

string JSZina::makeAttributeJSON(bool readReceipt, long burnSeconds)
{
    JsonUnique root(cJSON_CreateObject());
    cJSON_AddBoolToObject(root.get(), "r", readReceipt);
    if (burnSeconds >= 0) {
      cJSON_AddNumberToObject(root.get(), "s", burnSeconds);
    }

    CharUnique out(cJSON_PrintUnformatted(root.get()));
    string json(out.get());
    return json;
}

string JSZina::transportIdHex(int64_t transportId)
{
    char hex[32];
    memset(hex, '\0', sizeof(hex));
    size_t hex_len = 0;
    bin2hex((unsigned char *)&transportId, sizeof(transportId), hex, &hex_len);
    return string(hex, hex_len);
}

bool JSZina::sendData(uint8_t* name, uint8_t* devId, uint8_t* envelope, size_t size, uint64_t msgId)
{
    if (!name || !devId || !envelope || !size || !sendCallback_)
        return false;

    typedef void (*Sender)(const char* name, const char* devId, const char* envelope, const char* msg_id, size_t size);
    Sender sender = reinterpret_cast<Sender>(sendCallback_);
    sender((char*)name, (char*)devId, (char*)envelope, transportIdHex(msgId).c_str(), size);
    return true;
}

int32_t JSZina::receiveMessage(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes)
{
    if (receiveCallback_) {
      typedef void (*Receiver)(const char* messageDescriptor, char const* attachmentDescriptor, const char* messageAttributes);
      Receiver receiver = reinterpret_cast<Receiver>(receiveCallback_);
      receiver(messageDescriptor.c_str(), attachmentDescriptor.c_str(), messageAttributes.c_str());
    }
    return 1;
}

void JSZina::callNotify(int msgId, string actionCode, string actionInfo)
{
    if (notifyCallback_) {
      typedef void (*Notifier)(int msgId, char const* actionCode, const char* actionInfo);
      Notifier notifier = reinterpret_cast<Notifier>(notifyCallback_);
      notifier(msgId, actionCode.c_str(), actionInfo.c_str());
    }
}

void JSZina::callMessageState(int64_t msgId, int32_t stateCode, string stateInfo)
{
    Log("callMessageState: %lld, %d, %s", msgId, stateCode, stateInfo.c_str());
    if (messageStateCallback_) {
      typedef void (*StateFunc)(int msgId, int stateCode, const char* stateInfo);
      StateFunc statefunc = reinterpret_cast<StateFunc>(messageStateCallback_);
      statefunc(msgId, stateCode, stateInfo.c_str());
    }
}

int JSZina::callGroupCommand(string command)
{
    if (groupCommandCallback_) {
      typedef int (*Func)(const char* command);
      Func func = reinterpret_cast<Func>(groupCommandCallback_);
      return func(command.c_str());
    }

    return 0;
}

int32_t JSZina::callGroupMessage(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes)
{
    if (groupMessageCallback_) {
      typedef int (*Func)(const char* messageDescriptor, char const* attachmentDescriptor, const char* messageAttributes);
      Func func = reinterpret_cast<Func>(groupMessageCallback_);
      return func(messageDescriptor.c_str(), attachmentDescriptor.c_str(), messageAttributes.c_str());
    }
    return 1;
}

void JSZina::callGroupState(int32_t errorCode, const string& stateInformation)
{
    if (groupStateCallback_) {
      typedef void (*Func)(int errorCode, char const* stateInformation);
      Func func = reinterpret_cast<Func>(groupStateCallback_);
      return func(errorCode, stateInformation.c_str());
    }
}

void JSZina::removeZinaDevice(const wstring& deviceId16)
{
    string deviceId = toUTF8(deviceId16);

    if (deviceId.empty())
        return;

    string info;
    int32_t result = zinaAppInterface_->removeZinaDevice(deviceId, &info);
    Log("result: %d info: %s", result, info.c_str());
}

void JSZina::receiveSipMessage(const wstring& msg16)
{
    string msg = toUTF8(msg16);
    zinaAppInterface_->getTransport()->receiveAxoMessage((uint8_t*)msg.c_str(), msg.size());
}

void JSZina::receiveSipNotify(const wstring& msg16)
{
    string msg = toUTF8(msg16);
    zinaAppInterface_->getTransport()->notifyAxo((uint8_t*)msg.c_str(), msg.size());
}

bool JSZina::deleteDevice(const string& deviceId) {
    string info;
    string url = "/v1/me/device/" + deviceId + "/?api_key=" + zinaAppInterface_->getOwnAuthrization();
    int32_t result = httpHelper(url, "DELETE", "", &info);
    return result == 200;
}

bool JSZina::wipe(const wstring& hash16)
{
    string hash = toUTF8(hash16);

    Log("libzina: wipe %s", hash.c_str());
    bool result = deleteDevice(scClientDeviceId_);
    if (result) {
      SQLiteStoreConv* store = SQLiteStoreConv::getStore();
      store->closeStore();

      EM_ASM_({
        var hash = Module.Pointer_stringify($0);

        console.log("unlinking " + "/axolotl/" + hash +"_key");
        FS.unlink("/axolotl/" + hash +"_key");
        console.log("unlinking " + "/axolotl/" + hash +"_db.db");
        FS.unlink("/axolotl/" + hash + "_db.db");
      }, hash.c_str());
      syncFS();
    }
    Log("device %s wipe %s", scClientDeviceId_.c_str(), result ? "success" : "failed");
    return result;
}

void JSZina::rescanSiblingDevices(const wstring& username16)
{
    string username = toUTF8(username16);
    Log("rescanSiblingDevices: scanning for new devices for %s", username.c_str());
    zinaAppInterface_->rescanUserDevices(username);
}


void JSZina::resyncConversation(const wstring& username16, const wstring& deviceId16)
{
    string username = toUTF8(username16);
    string deviceId = toUTF8(deviceId16);

    Log("resyncConversation: %s - %s", username.c_str(), deviceId.c_str());
    zinaAppInterface_->reKeyDevice(username, deviceId);
    Log("resyncConversation completed");
}

void JSZina::initializeFS()
{
    EM_ASM(
      FS.mkdir('/axolotl');
      FS.mount(IDBFS, {}, '/axolotl');

      FS.syncfs(true, function(err) {
        if (!err) {
          console.log("Initializing FS");
          Module.runWithFS();
        }
        else {
          console.log("FS initialization error");
        }
      });
    );
}

string JSZina::getStoredApiKey(const wstring& hash)
{
    ifstream file("/axolotl/" + toUTF8(hash) + "_key");
    string str((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return str;
}

void JSZina::setStoredApiKey(const wstring& hash, const wstring& key)
{
    ofstream file("/axolotl/" + toUTF8(hash) + "_key");
    file << toUTF8(key);
}

string JSZina::getStoredDeviceId(const wstring& hash)
{
    ifstream file("/axolotl/" + toUTF8(hash) +"_device");
    string str((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return str;
}

void JSZina::setStoredDeviceId(const wstring& hash, const wstring& device)
{
    ofstream file("/axolotl/" + toUTF8(hash) + "_device");
    file << toUTF8(device);
}

void JSZina::syncFS()
{
    EM_ASM(
      FS.syncfs(false, function(err) {
      });
    );
}

string JSZina::getZinaDevicesUser(const wstring& username16)
{
    string username = toUTF8(username16);

    if (zinaAppInterface_ == nullptr) {
        return "";
    }

    list<pair<string, string> > devices;
    Provisioning::getZinaDeviceIds(username, zinaAppInterface_->getOwnAuthrization(), devices);

    if (devices.empty()) {
        return "";
    }

    cJSON *root,*devArray, *devInfo;
    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "version", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(root, "devices", devArray = cJSON_CreateArray());

    for (auto &idName : devices) {
        devInfo = cJSON_CreateObject();
        cJSON_AddStringToObject(devInfo, "id", idName.first.c_str());
        cJSON_AddStringToObject(devInfo, "device_name", idName.second.c_str());
        cJSON_AddItemToArray(devArray, devInfo);
    }

    char *out = cJSON_Print(root);
    string json(out);
    cJSON_Delete(root); free(out);
    return json;
}

string JSZina::getKnownUsers()
{
    if (zinaAppInterface_ == nullptr) {
        return "";
    }

    string* jsonNames = zinaAppInterface_->getKnownUsers();
    if (jsonNames == nullptr)
        return "";

    string result(*jsonNames);
    delete jsonNames;
    return result;
}

string JSZina::getOwnIdentityKey()
{
    if (zinaAppInterface_ == nullptr) {
        return "";
    }
    return zinaAppInterface_->getOwnIdentityKey();
}

void JSZina::getIdentityKeys(const wstring& user16, vector<string>& result)
{
    string user = toUTF8(user16);

    if (zinaAppInterface_ == nullptr) {
        return;
    }
    shared_ptr<list<string> > idKeys = zinaAppInterface_->getIdentityKeys(user);
    result.insert(result.end(), idKeys->begin(), idKeys->end());
}

int JSZina::newPreKeys(int num)
{
    if (zinaAppInterface_ == nullptr) {
        return -1;
    }
    return zinaAppInterface_->newPreKeys(num);
}

int JSZina::getNumPreKeys()
{
    if (zinaAppInterface_ == nullptr) {
        return -1;
    }
    return zinaAppInterface_->getNumPreKeys();
}

string JSZina::createNewGroup(const wstring& groupName16, const wstring& groupDescription16)
{
    string groupName = toUTF8(groupName16);
    string groupDescription = toUTF8(groupDescription16);

    if (zinaAppInterface_ == nullptr) {
        return "";
    }

    return zinaAppInterface_->createNewGroup(groupName, groupDescription);
}

bool JSZina::modifyGroupSize(const wstring& uuid16, int newSize)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr || uuid.empty()) {
        return false;
    }

    return zinaAppInterface_->modifyGroupSize(uuid, newSize);
}

int JSZina::setGroupName(const wstring& uuid16, const wstring& name16)
{
    string uuid = toUTF8(uuid16);
    string name = toUTF8(name16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->setGroupName(uuid, &name);
}

int JSZina::setGroupBurnTime(const wstring& uuid16, long burnTime, int mode)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->setGroupBurnTime(uuid, static_cast<uint64_t>(burnTime), mode);
}

int JSZina::setGroupAvatar(const wstring& uuid16, string avatar)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }

    return zinaAppInterface_->setGroupAvatar(uuid, avatar.empty() ? nullptr : &avatar);
}

int JSZina::listAllGroups(vector<string>& groups)
{
    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    list<JsonUnique> groupsJson;
    int32_t result = zinaAppInterface_->getStore()->listAllGroups(groupsJson);
    if (groupsJson.size() == 0) {
      return result;
    }

    int32_t index = 0;
    for (auto& group : groupsJson) {
        CharUnique out(cJSON_PrintUnformatted(group.get()));
        groups.push_back(out.get());
    }

    return result;
}

int JSZina::listAllGroupsWithMember(const wstring& participantUuid16, vector<string>& groups)
{
    string participantUuid = toUTF8(participantUuid16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (participantUuid.empty()) {
        return DATA_MISSING;
    }
    list<JsonUnique> groupsJson;
    int32_t result = zinaAppInterface_->getStore()->listAllGroupsWithMember(participantUuid, groupsJson);
    if (groupsJson.size() == 0) {
      return result;
    }

    for (auto& group : groupsJson) {
        CharUnique out(cJSON_PrintUnformatted(group.get()));
        groups.push_back(out.get());
    }

    return result;
}

string JSZina::getGroup(const wstring& uuid16)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr) {
        return ""; //GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return ""; //DATA_MISSING;
    }
    int32_t result;
    shared_ptr<cJSON> groupJson = zinaAppInterface_->getStore()->listGroup(uuid, &result);

//    setReturnCode(env, code, result);
    CharUnique out(cJSON_PrintUnformatted(groupJson.get()));
    return out.get();
}

int JSZina::getAllGroupMembers(const wstring& uuid16, vector<string>& members)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    list<JsonUnique> membersJson;
    int32_t result = zinaAppInterface_->getStore()->getAllGroupMembers(uuid, membersJson);
    if (membersJson.size() == 0) {
      return result;
    }

    for (auto& member : membersJson) {
        CharUnique out(cJSON_PrintUnformatted(member.get()));
        members.push_back(out.get());
    }

    return result;
}

string JSZina::getGroupMember(const wstring& uuid16, string memberUuid)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr) {
        return ""; //GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return ""; //DATA_MISSING;
    }
    if (memberUuid.empty()) {
        return ""; //DATA_MISSING;
    }
    int32_t result;
    shared_ptr<cJSON> memberJson = zinaAppInterface_->getStore()->getGroupMember(uuid, memberUuid, &result);

//    setReturnCode(env, code, result);
    CharUnique out(cJSON_PrintUnformatted(memberJson.get()));
    return out.get();
}

int JSZina::addUser(const wstring& uuid16, const wstring& userId16)
{
    string uuid = toUTF8(uuid16);
    string userId = toUTF8(userId16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    if (userId.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->addUser(uuid, userId);
}

int JSZina::removeUserFromAddUpdate(const wstring& uuid16, const wstring& userId16)
{
    string uuid = toUTF8(uuid16);
    string userId = toUTF8(userId16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    if (userId.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->removeUserFromAddUpdate(uuid, userId);
}

int JSZina::cancelGroupChangeSet(const wstring& uuid16)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->cancelGroupChangeSet(uuid);
}

int JSZina::applyGroupChangeSet(const wstring& uuid16)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->applyGroupChangeSet(uuid);
}

int JSZina::leaveGroup(const wstring& uuid16)
{
    string uuid = toUTF8(uuid16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->leaveGroup(uuid);
}

int JSZina::removeUser(const wstring& uuid16, const wstring& userId16)
{
    string uuid = toUTF8(uuid16);
    string userId = toUTF8(userId16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    if (userId.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->removeUser(uuid, userId);
}

int JSZina::removeUserFromRemoveUpdate(const wstring& uuid16, const wstring& userId16)
{
    string uuid = toUTF8(uuid16);
    string userId = toUTF8(userId16);

    if (zinaAppInterface_ == nullptr) {
        return GENERIC_ERROR;
    }
    if (uuid.empty()) {
        return DATA_MISSING;
    }
    if (userId.empty()) {
        return DATA_MISSING;
    }
    return zinaAppInterface_->removeUserFromRemoveUpdate(uuid, userId);
}

wstring JSZina::sendGroupMessage(const wstring& groupUuid16, const wstring& message16, long burnSeconds)
{
    string groupUuid = toUTF8(groupUuid16);
    string message = toUTF8(message16);

    if (groupUuid.empty() || message.empty() || zinaAppInterface_ == nullptr)
        return toUTF16("");

    uuid_t pingUuid = {0};
    uuid_string_t uuidString = {0};

    uuid_generate_time(pingUuid);
    uuid_unparse(pingUuid, uuidString);
    string messageId(uuidString);

    string json = makeMessageJSON(groupUuid, message, scClientDeviceId_, messageId);
    string attributes = makeAttributeJSON(true, burnSeconds);

    int r = zinaAppInterface_->sendGroupMessage(json, "", attributes);
    return r == OK ? toUTF16(messageId) : toUTF16("");
}

void JSZina::setZinaLogLevel(int level)
{
    void setZinaLogLevel(int32_t level);
    ::setZinaLogLevel(level);
}

int JSZina::burnGroupMessage(const wstring& uuid16, const wstring& msgId16)
{
    string groupUuid = toUTF8(uuid16);
    string msgId = toUTF8(msgId16);

    if (groupUuid.empty() || msgId.empty() || zinaAppInterface_ == nullptr)
        return DATA_MISSING;

    vector<string> msgIds;
    msgIds.push_back(msgId);
    int32_t result = zinaAppInterface_->burnGroupMessage(groupUuid, msgIds);
    return result == SUCCESS ? OK : result;
}

wstring JSZina::getUid(const wstring& userid16, const wstring& auth16)
{
    string userid = toUTF8(userid16);
    string auth = toUTF8(auth16);

    if (userid16.empty()) {
      return toUTF16("");
    }

    if (auth.empty()) {
        auth = zinaAppInterface_->getOwnAuthrization();
    }

    NameLookup* nameCache = NameLookup::getInstance();
    string uid = nameCache->getUid(userid, auth);

    if (uid.empty()) {
        return toUTF16("");
    }

    return toUTF16(uid);
}

EMSCRIPTEN_BINDINGS(js_axolotl) {
    register_vector<std::string>("VectorString");
    class_<JSZina>("JSZina")
      .constructor<>()
      .function("doInit", &JSZina::doInit)
      .function("registerSendCallback", &JSZina::registerSendCallback)
      .function("registerReceiveCallback", &JSZina::registerReceiveCallback)
      .function("registerNotifyCallback", &JSZina::registerNotifyCallback)
      .function("registerMessageStateCallback", &JSZina::registerMessageStateCallback)
      .function("registerGroupCommandCallback", &JSZina::registerGroupCommandCallback)
      .function("registerGroupMessageCallback", &JSZina::registerGroupMessageCallback)
      .function("registerGroupStateCallback", &JSZina::registerGroupStateCallback)
      .function("registerZinaDevice", &JSZina::registerZinaDevice)
      .function("prepareSimpleMessage", &JSZina::prepareSimpleMessage)
      .function("doSendMessage", &JSZina::doSendMessage)
      .function("resendMessage", &JSZina::resendMessage)
      .function("sendBurnMessage", &JSZina::sendBurnMessage)
      .function("sendBurnConfirmation", &JSZina::sendBurnConfirmation)
      .function("sendReadNotification", &JSZina::sendReadNotification)
      .function("sendEmptySyncToSiblings", &JSZina::sendEmptySyncToSiblings)
      .function("removeZinaDevice", &JSZina::removeZinaDevice)
      .function("receiveSipMessage", &JSZina::receiveSipMessage)
      .function("receiveSipNotify", &JSZina::receiveSipNotify)
      .function("wipe", &JSZina::wipe)
      .function("rescanSiblingDevices", &JSZina::rescanSiblingDevices)
      .function("resyncConversation", &JSZina::resyncConversation)
      .function("getZinaDevicesUser", &JSZina::getZinaDevicesUser)
      .function("getKnownUsers", &JSZina::getKnownUsers)
      .function("getOwnIdentityKey", &JSZina::getOwnIdentityKey)
      .function("getIdentityKeys", &JSZina::getIdentityKeys)
      .function("newPreKeys", &JSZina::newPreKeys)
      .function("getNumPreKeys", &JSZina::getNumPreKeys)
      .function("createNewGroup", &JSZina::createNewGroup)
      .function("modifyGroupSize", &JSZina::modifyGroupSize)
      .function("setGroupName", &JSZina::setGroupName)
      .function("setGroupBurnTime", &JSZina::setGroupBurnTime)
      .function("setGroupAvatar", &JSZina::setGroupAvatar)
      .function("listAllGroups", &JSZina::listAllGroups)
      .function("listAllGroupsWithMember", &JSZina::listAllGroupsWithMember)
      .function("getGroup", &JSZina::getGroup)
      .function("getAllGroupMembers", &JSZina::getAllGroupMembers)
      .function("getGroupMember", &JSZina::getGroupMember)
      .function("addUser", &JSZina::addUser)
      .function("removeUserFromAddUpdate", &JSZina::removeUserFromAddUpdate)
      .function("cancelGroupChangeSet", &JSZina::cancelGroupChangeSet)
      .function("applyGroupChangeSet", &JSZina::applyGroupChangeSet)
      .function("leaveGroup", &JSZina::leaveGroup)
      .function("removeUser", &JSZina::removeUser)
      .function("removeUserFromRemoveUpdate", &JSZina::removeUserFromRemoveUpdate)
      .function("sendGroupMessage", &JSZina::sendGroupMessage)
      .function("setZinaLogLevel", &JSZina::setZinaLogLevel)
      .function("burnGroupMessage", &JSZina::burnGroupMessage)
      .function("getUid", &JSZina::getUid)
      .class_function("initializeFS", &JSZina::initializeFS)
      .class_function("getStoredApiKey", &JSZina::getStoredApiKey)
      .class_function("setStoredApiKey", &JSZina::setStoredApiKey)
      .class_function("getStoredDeviceId", &JSZina::getStoredDeviceId)
      .class_function("setStoredDeviceId", &JSZina::setStoredDeviceId)
      .class_function("syncFS", &JSZina::syncFS)
      ;
}
