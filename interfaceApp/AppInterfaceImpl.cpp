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

#include "AppInterfaceImpl.h"

#include "../keymanagment/PreKeys.h"
#include "../util/b64helper.h"
#include "../provisioning/Provisioning.h"
#include "../provisioning/ScProvisioning.h"
#include "../dataRetention/ScDataRetention.h"
#include "../logging/ZinaLogging.h"
#include "../storage/MessageCapture.h"
#include "MessageEnvelope.pb.h"
#include "JsonStrings.h"
#include "../util/Utilities.h"

#include <cryptcommon/ZrtpRandom.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCDFAInspection"
static mutex convLock;

using namespace zina;

AppInterfaceImpl::AppInterfaceImpl(const string& ownUser, const string& authorization, const string& scClientDevId,
                                   RECV_FUNC receiveCallback, STATE_FUNC stateReportCallback, NOTIFY_FUNC notifyCallback,
                                   GROUP_MSG_RECV_FUNC groupMsgCallback, GROUP_CMD_RECV_FUNC groupCmdCallback,  GROUP_STATE_FUNC groupStateCallback):
        AppInterface(receiveCallback, stateReportCallback, notifyCallback, groupMsgCallback, groupCmdCallback, groupStateCallback),
        tempBuffer_(NULL), tempBufferSize_(0), ownUser_(ownUser), authorization_(authorization), scClientDevId_(scClientDevId),
        errorCode_(0), transport_(NULL), flags_(0), siblingDevicesScanned_(false), drLrmm_(false), drLrmp_(false), drLrap_(false),
        drBldr_(false), drBlmr_(false), drBrdr_(false), drBrmr_(false)
{
    store_ = SQLiteStoreConv::getStore();
    ScDataRetention::setAuthorization(authorization);
}

AppInterfaceImpl::~AppInterfaceImpl()
{
    LOGGER(INFO, __func__, " -->");
    tempBufferSize_ = 0; delete tempBuffer_; tempBuffer_ = NULL;
    delete transport_; transport_ = NULL;
    LOGGER(INFO, __func__, " <--");
}

string AppInterfaceImpl::createSupplementString(const string& attachmentDesc, const string& messageAttrib)
{
    LOGGER(INFO, __func__, " -->");
    string supplement;
    if (!attachmentDesc.empty() || !messageAttrib.empty()) {
        cJSON* msgSupplement = cJSON_CreateObject();

        if (!attachmentDesc.empty()) {
            LOGGER(DEBUGGING, "Adding an attachment descriptor supplement");
            cJSON_AddStringToObject(msgSupplement, "a", attachmentDesc.c_str());
        }

        if (!messageAttrib.empty()) {
            LOGGER(DEBUGGING, "Adding an message attribute supplement");
            cJSON_AddStringToObject(msgSupplement, "m", messageAttrib.c_str());
        }
        char *out = cJSON_PrintUnformatted(msgSupplement);

        supplement = out;
        cJSON_Delete(msgSupplement); free(out);
    }
    LOGGER(INFO, __func__, " <--");
    return supplement;
}


string* AppInterfaceImpl::getKnownUsers()
{
    int32_t sqlCode;

    LOGGER(INFO, __func__, " -->");
    if (!store_->isReady()) {
        LOGGER(ERROR, __func__, " Axolotl conversation DB not ready.");
        return NULL;
    }

    shared_ptr<list<string> > names = store_->getKnownConversations(ownUser_, &sqlCode);

    if (SQL_FAIL(sqlCode) || !names) {
        LOGGER(INFO, __func__, " No known Axolotl conversations.");
        return NULL;
    }
    size_t size = names->size();
    if (size == 0)
        return NULL;

    cJSON *root,*nameArray;
    root=cJSON_CreateObject();
    cJSON_AddItemToObject(root, "version", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(root, "users", nameArray = cJSON_CreateArray());

    for (int32_t i = 0; i < size; i++) {
        string name = names->front();
        cJSON_AddItemToArray(nameArray, cJSON_CreateString(name.c_str()));
        names->pop_front();
    }
    char *out = cJSON_PrintUnformatted(root);
    string* retVal = new string(out);
    cJSON_Delete(root); free(out);

    LOGGER(INFO, __func__, " <--");
    return retVal;
}

/*
 * JSON data for a registration request:
{
    "version" :        <int32_t>,        # Version of JSON registration, 1 for the first implementation
    "identity_key" :    <string>,         # public part encoded base64 data 
    "prekeys" : [{
        "id" :     <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    },
    ....
    {
        "id" :     <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
    }]
}
 */
int32_t AppInterfaceImpl::registerZinaDevice(string* result)
{
    cJSON *root;
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    LOGGER(INFO, __func__, " -->");

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
//    cJSON_AddStringToObject(root, "scClientDevId", scClientDevId_.c_str());

    shared_ptr<ZinaConversation> ownConv = ZinaConversation::loadLocalConversation(ownUser_);
    if (!ownConv->isValid()) {
        cJSON_Delete(root);
        LOGGER(ERROR, __func__, " No own conversation in database.");
        return NO_OWN_ID;
    }
    const DhKeyPair* myIdPair = ownConv->getDHIs();
    if (myIdPair == NULL) {
        cJSON_Delete(root);
        LOGGER(ERROR, __func__, " Own conversation not correctly initialized.");
        return NO_OWN_ID;
    }

    string data = myIdPair->getPublicKey().serialize();

    b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);
    cJSON_AddStringToObject(root, "identity_key", b64Buffer);

    cJSON* jsonPkrArray;
    cJSON_AddItemToObject(root, "prekeys", jsonPkrArray = cJSON_CreateArray());

    list<pair<int32_t, const DhKeyPair* > >* preList = PreKeys::generatePreKeys(store_);

    int32_t size = static_cast<int32_t>(preList->size());

    for (int32_t i = 0; i < size; i++) {
        pair< int32_t, const DhKeyPair* >pkPair = preList->front();
        preList->pop_front();

        cJSON* pkrObject;
        cJSON_AddItemToArray(jsonPkrArray, pkrObject = cJSON_CreateObject());
        cJSON_AddNumberToObject(pkrObject, "id", pkPair.first);

        // Get pre-key's public key data, serialized
        const DhKeyPair* ecPair = pkPair.second;
        const string keyData = ecPair->getPublicKey().serialize();

        b64Encode((const uint8_t*) keyData.data(), keyData.size(), b64Buffer, MAX_KEY_BYTES_ENCODED * 2);
        cJSON_AddStringToObject(pkrObject, "key", b64Buffer);
        delete ecPair;
    }
    delete preList;

    char *out = cJSON_PrintUnformatted(root);
    string registerRequest(out);
    cJSON_Delete(root); free(out);

    int32_t code = Provisioning::registerZinaDevice(registerRequest, authorization_, scClientDevId_, result);

    LOGGER(INFO, __func__, " <-- ", code);
    return code;
}

int32_t AppInterfaceImpl::removeZinaDevice(string& devId, string* result)
{
    LOGGER(INFO, __func__, " <-->");
    return ScProvisioning::removeZinaDevice(devId, authorization_, result);
}

int32_t AppInterfaceImpl::newPreKeys(int32_t number)
{
    LOGGER(INFO, __func__, " -->");
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    string result;
    return ScProvisioning::newPreKeys(store, scClientDevId_, authorization_, number, &result);
}

int32_t AppInterfaceImpl::getNumPreKeys() const
{
    LOGGER(INFO, __func__, " <-->");
    return Provisioning::getNumPreKeys(scClientDevId_, authorization_);
}

// Get known Axolotl device from provisioning server, check if we have a new one
// and if yes send a "ping" message to the new devices to create an Axolotl conversation
// for the new devices.

void AppInterfaceImpl::rescanUserDevices(string& userName)
{
    LOGGER(INFO, __func__, " -->");
    shared_ptr<list<pair<string, string> > > devices = Provisioning::getZinaDeviceIds(userName, authorization_);
    if (!devices|| devices->empty()) {
        return;
    }

    // Get known devices from DB, compare with devices from provisioning server
    // and remove old devices in DB, i.e. devices not longer known to provisioning server
    //
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();

    shared_ptr<list<string> > devicesDb = store_->getLongDeviceIds(userName, ownUser_);

    if (devicesDb) {
        while (!devicesDb->empty()) {
            string devIdDb = devicesDb->front();
            devicesDb->pop_front();
            bool found = false;

            for (list<pair<string, string> >::iterator devIterator = devices->begin();
                 devIterator != devices->end(); ++devIterator) {
                string devId = (*devIterator).first;
                if (devIdDb == devId) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                store->deleteConversation(userName, devIdDb, ownUser_);
                LOGGER(DEBUGGING, "Remove device from database: ", devIdDb);
            }
        }
    }

    // Prepare and send this to the new learned device:
    // - an Empty message
    // - a message command attribute with a ping command
    // For each Ping message the code generates a new UUID

    // Prepare the messages for all known new devices of this user

    int64_t transportMsgId;
    ZrtpRandom::getRandomData(reinterpret_cast<uint8_t*>(&transportMsgId), 8);
    uint64_t counter = 0;

    // The transport id is structured: bits 0..3 are status/type bits, bits 4..7 is a counter, bits 8..63 random data
    transportMsgId &= ~0xff;

    unique_lock<mutex> lck(convLock);
    while (!devices->empty()) {
        string deviceId = devices->front().first;
        string deviceName = devices->front().second;
        devices->pop_front();

        // Don't re-scan own device, just check if name changed
        bool toSibling = userName == ownUser_;
        if (toSibling && scClientDevId_ == deviceId) {
            shared_ptr<ZinaConversation> conv = ZinaConversation::loadLocalConversation(ownUser_);
            if (conv->isValid()) {
                const string &convDevName = conv->getDeviceName();
                if (deviceName.compare(convDevName) != 0) {
                    conv->setDeviceName(deviceName);
                    conv->storeConversation();
                }
            }
            continue;
        }

        // If we already have a conversation for this device skip further processing
        // after storing a user defined device name. The user may change a device's name
        // using the Web interface of the provisioning server
        if (store->hasConversation(userName, deviceId, ownUser_)) {
            shared_ptr<ZinaConversation> conv = ZinaConversation::loadConversation(ownUser_, userName, deviceId);
            if (conv->isValid()) {
                const string &convDevName = conv->getDeviceName();
                if (deviceName.compare(convDevName) != 0) {
                    conv->setDeviceName(deviceName);
                    conv->storeConversation();
                }
            }
            continue;
        }

        LOGGER(DEBUGGING, "Send Ping to new found device: ", deviceId);
        auto msgInfo = make_shared<CmdQueueInfo>();
        msgInfo->command = SendMessage;
        msgInfo->queueInfo_recipient = userName;
        msgInfo->queueInfo_deviceName = deviceName;
        msgInfo->queueInfo_deviceId = deviceId;
        msgInfo->queueInfo_msgId = generateMsgIdTime();
        msgInfo->queueInfo_message = Empty;
        msgInfo->queueInfo_attachment = Empty;
        msgInfo->queueInfo_attributes = ping;
        msgInfo->queueInfo_transportMsgId = transportMsgId | (counter << 4) | MSG_NORMAL;
        msgInfo->queueInfo_toSibling = toSibling;
        msgInfo->queueInfo_newUserDevice = true;
        counter++;
        queuePreparedMessage(msgInfo);
        doSendSingleMessage(msgInfo->queueInfo_transportMsgId);  // Process it immediately, usually only one new device at a time
        LOGGER(DEBUGGING, "Queued message to ping a new device.");
    }
    LOGGER(INFO, __func__, " <--");
    return;
}

void AppInterfaceImpl::setHttpHelper(HTTP_FUNC httpHelper)
{
    ScProvisioning::setHttpHelper(httpHelper);
    ScDataRetention::setHttpHelper(httpHelper);
}

void AppInterfaceImpl::setS3Helper(S3_FUNC s3Helper)
{
    ScDataRetention::setS3Helper(s3Helper);
}

// ***** Private functions 
// *******************************

int32_t AppInterfaceImpl::parseMsgDescriptor(const string& messageDescriptor, string* recipient, string* msgId, string* message, bool receivedMsg)
{
    LOGGER(INFO, __func__, " -->");
    cJSON* cjTemp;
    char* jsString;

    // wrap the cJSON root into a shared pointer with custom cJSON deleter, this
    // will always free the cJSON root when we leave the function :-) .
    shared_ptr<cJSON> sharedRoot(cJSON_Parse(messageDescriptor.c_str()), cJSON_deleter);
    cJSON* root = sharedRoot.get();

    if (root == NULL) {
        errorInfo_ = "root";
        return GENERIC_ERROR;
    }
    const char* recipientSender = receivedMsg ? MSG_SENDER : MSG_RECIPIENT;
    cjTemp = cJSON_GetObjectItem(root, recipientSender);
    jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
    if (jsString == NULL) {
        errorInfo_ = recipientSender;
        return JS_FIELD_MISSING;
    }
    recipient->assign(jsString);

    // Get the message id
    cjTemp = cJSON_GetObjectItem(root, MSG_ID);
    jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
    if (jsString == NULL) {
        errorInfo_ = MSG_ID;
        return JS_FIELD_MISSING;
    }
    msgId->assign(jsString);

    // Get the message
    cjTemp = cJSON_GetObjectItem(root, MSG_MESSAGE);
    jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
    if (jsString == NULL) {
        errorInfo_ = MSG_MESSAGE;
        return JS_FIELD_MISSING;
    }
    message->assign(jsString);

    LOGGER(INFO, __func__, " <--");
    return OK;
}

string AppInterfaceImpl::getOwnIdentityKey() const
{
    LOGGER(INFO, __func__, " -->");

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5
    shared_ptr<ZinaConversation> axoConv = ZinaConversation::loadLocalConversation(ownUser_);
    if (!axoConv->isValid()) {
        LOGGER(ERROR, "No own conversation, ignore.")
        LOGGER(INFO, __func__, " <-- No own conversation.");
        return Empty;
    }

    const DhKeyPair* keyPair = axoConv->getDHIs();
    const DhPublicKey& pubKey = keyPair->getPublicKey();

    b64Encode(pubKey.getPublicKeyPointer(), pubKey.getSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);

    string idKey((const char*)b64Buffer);
    idKey.append(":");
    if (!axoConv->getDeviceName().empty()) {
        idKey.append(axoConv->getDeviceName());
    }
    idKey.append(":").append(scClientDevId_).append(":0");
    LOGGER(INFO, __func__, " <--");
    return idKey;
}

shared_ptr<list<string> > AppInterfaceImpl::getIdentityKeys(string& user) const
{
    LOGGER(INFO, __func__, " -->");

    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5
    shared_ptr<list<string> > idKeys = make_shared<list<string> >();

    shared_ptr<list<string> > devices = store_->getLongDeviceIds(user, ownUser_);

    while (!devices->empty()) {
        string recipientDeviceId = devices->front();
        devices->pop_front();
        auto axoConv = ZinaConversation::loadConversation(ownUser_, user, recipientDeviceId);
        if (!axoConv->isValid()) {
            continue;
        }
        const DhPublicKey* idKey = axoConv->getDHIr();
        if (idKey == NULL) {
            continue;
        }

        b64Encode(idKey->getPublicKeyPointer(), idKey->getSize(), b64Buffer, MAX_KEY_BYTES_ENCODED*2);

        string id((const char*)b64Buffer);
        id.append(":");
        if (!axoConv->getDeviceName().empty()) {
            id.append(axoConv->getDeviceName());
        }
        id.append(":").append(recipientDeviceId);
        snprintf(b64Buffer, 5, ":%d", axoConv->getZrtpVerifyState());
        b64Buffer[4] = '\0';          // make sure it's terminated
        id.append(b64Buffer);

        idKeys->push_back(id);
    }
    LOGGER(INFO, __func__, " <--");
    return idKeys;
}

void AppInterfaceImpl::reSyncConversation(const string &userName, const string& deviceId) {
    LOGGER(INFO, __func__, " -->");

    if (!store_->isReady()) {
        LOGGER(ERROR, __func__, " Axolotl conversation DB not ready.");
        return;
    }
    // Don't re-sync this device
    bool toSibling = userName == ownUser_;
    if (toSibling && deviceId == scClientDevId_)
        return;

    unique_lock<mutex> lck(convLock);

    // clear data and store the nearly empty conversation
    shared_ptr<ZinaConversation> conv = ZinaConversation::loadConversation(ownUser_, userName, deviceId);
    if (!conv->isValid()) {
        return;
    }
    conv->reset();
    conv->storeConversation();
    if (conv->getErrorCode() != SUCCESS) {
        return;
    }

    // Check if server still knows this device, if no device at all -> remove conversation.
    shared_ptr<list<pair<string, string> > > devices = Provisioning::getZinaDeviceIds(userName, authorization_);
    if (!devices || devices->empty()) {
        store_->deleteConversation(userName, deviceId, ownUser_);
        return;
    }
    bool deviceFound = false;
    string deviceName;
    for (auto it = devices->cbegin(); it != devices->cend(); ++it) {
        if (deviceId == (*it).first) {
            deviceName = (*it).second;
            deviceFound = true;
            break;
        }
    }

    // The server does not know this device anymore. In this case remove the conversation.
    if (!deviceFound) {
        store_->deleteConversation(userName, deviceId, ownUser_);
        return;
    }

    int64_t transportMsgId;
    ZrtpRandom::getRandomData(reinterpret_cast<uint8_t*>(&transportMsgId), 8);

    // The transport id is structured: bits 0..3 are status/type bits, bits 4..7 is a counter, bits 8..63 random data
    transportMsgId &= ~0xff;

    auto msgInfo = make_shared<CmdQueueInfo>();
    msgInfo->command = SendMessage;
    msgInfo->queueInfo_recipient = userName;
    msgInfo->queueInfo_deviceName = deviceName;
    msgInfo->queueInfo_deviceId = deviceId;
    msgInfo->queueInfo_msgId = generateMsgIdTime();
    msgInfo->queueInfo_message = Empty;
    msgInfo->queueInfo_attachment = Empty;
    msgInfo->queueInfo_message = ping;
    msgInfo->queueInfo_transportMsgId = transportMsgId | static_cast<uint64_t>(MSG_NORMAL);
    msgInfo->queueInfo_toSibling = toSibling;
    msgInfo->queueInfo_newUserDevice = true;
    queuePreparedMessage(msgInfo);
    doSendSingleMessage(msgInfo->queueInfo_transportMsgId);

    LOGGER(INFO, __func__, " <--");
    return;
}

int32_t AppInterfaceImpl::setDataRetentionFlags(const string& jsonFlags)
{
    LOGGER(INFO, __func__, " --> ", jsonFlags);
    if (jsonFlags.empty()) {
        return DATA_MISSING;
    }

    shared_ptr<cJSON> sharedRoot(cJSON_Parse(jsonFlags.c_str()), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    if (root == nullptr) {
        return CORRUPT_DATA;
    }
    drLrmm_ = Utilities::getJsonBool(root, LRMM, false);
    drLrmp_ = Utilities::getJsonBool(root, LRMP, false);
    drLrap_ = Utilities::getJsonBool(root, LRAP, false);
    drBldr_ = Utilities::getJsonBool(root, BLDR, false);
    drBlmr_ = Utilities::getJsonBool(root, BLMR, false);
    drBrdr_ = Utilities::getJsonBool(root, BRDR, false);
    drBrmr_ = Utilities::getJsonBool(root, BRMR, false);

    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

#pragma clang diagnostic pop
