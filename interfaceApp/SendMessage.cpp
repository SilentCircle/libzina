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

#include <cryptcommon/ZrtpRandom.h>
#include <map>
#include "AppInterfaceImpl.h"

#include "../util/Utilities.h"
#include "../provisioning/Provisioning.h"
#include "../util/b64helper.h"
#include "MessageEnvelope.pb.h"
#include "../storage/MessageCapture.h"
#include "../ratchet/ratchet/ZinaRatchet.h"
#include "../ratchet/ZinaPreKeyConnector.h"
#include "JsonStrings.h"

using namespace axolotl;


shared_ptr<list<shared_ptr<PreparedMessageData> > >
AppInterfaceImpl::prepareMessage(const string& messageDescriptor,
                                 const string& attachmentDescriptor,
                                 const string& messageAttributes, int32_t* result)
{
    return prepareMessageInternal(messageDescriptor, attachmentDescriptor, messageAttributes, false, MSG_NORMAL, result);
}

shared_ptr<list<shared_ptr<PreparedMessageData> > >
AppInterfaceImpl::prepareMessageToSiblings(const string &messageDescriptor,
                                           const string &attachmentDescriptor,
                                           const string &messageAttributes, int32_t *result)
{
    return prepareMessageInternal(messageDescriptor, attachmentDescriptor, messageAttributes, true, MSG_NORMAL, result);
}

static shared_ptr<list<pair<string, string> > >
getDevicesNewUser(string& recipient, string& authorization, int32_t* errorCode)
{
    auto devices = Provisioning::getAxoDeviceIds(recipient, authorization, errorCode);

    if (!devices) {
        char tmpBuff[20];
        snprintf(tmpBuff, 10, "%d", *errorCode);
        string errorString(tmpBuff);

        *errorCode = NETWORK_ERROR;
        LOGGER(ERROR, __func__, " <-- Network error: ", errorString);
        return shared_ptr<list<pair<string, string> > >();
    }

    if (devices->empty()) {
        *errorCode = NO_DEVS_FOUND;
        LOGGER(INFO, __func__, " <-- No device.");
        return shared_ptr<list<pair<string, string> > >();
    }
    *errorCode = SUCCESS;
    return devices;
}

/**
 * @brief Create a Id key and device info string as returned by @c getIdentityKeys().
 *
 * Because it's a new user we don't know its long-term identity key yet. Thus fill it
 * with a appropriate description.
 *
 * @param newDevList Device information from provisioning server for a new user
 * @return List of key id, device info string
 */
shared_ptr<list<string> >
createIdDevInfo(shared_ptr<list<pair<string, string> > > newDevList) {

    auto devInfoList = make_shared<list<string> >();

    while (!newDevList->empty()) {
        pair<string, string> devInfo = newDevList->front();
        newDevList->pop_front();
        string newDevInfo(string("<NOT_YET_AVAILABLE>:"));
        newDevInfo.append(devInfo.second).append(":").append(devInfo.first).append(":0");
        devInfoList->push_back(newDevInfo);
    }
    return devInfoList;
}

static mutex preparedMessagesLock;
static map<uint64_t, shared_ptr<MsgQueueInfo> > preparedMessages;

void AppInterfaceImpl::queuePreparedMessage(shared_ptr<MsgQueueInfo> &msgInfo)
{
    unique_lock<mutex> listLock(preparedMessagesLock);
    preparedMessages.insert(pair<uint64_t, shared_ptr<MsgQueueInfo>>(msgInfo->queueInfo_transportMsgId, msgInfo));
}

shared_ptr<list<shared_ptr<PreparedMessageData> > >
AppInterfaceImpl::prepareMessageInternal(const string& messageDescriptor,
                                         const string& attachmentDescriptor,
                                         const string& messageAttributes,
                                         bool toSibling, uint32_t messageType, int32_t* result, const string& grpRecipient)
{

    string recipient;
    string msgId;
    string message;

    LOGGER(INFO, __func__, " -->");

    auto messageData = make_shared<list<shared_ptr<PreparedMessageData> > >();

    if (result != nullptr) {
        *result = SUCCESS;
        errorCode_ = SUCCESS;
    }
    int32_t parseResult = parseMsgDescriptor(messageDescriptor, &recipient, &msgId, &message);
    if (parseResult < 0) {
        if (result != nullptr) {
            *result = parseResult;
        }
        errorCode_ = parseResult;
        errorInfo_ = "Wrong JSON data to send message";
        LOGGER(ERROR, __func__, " Wrong JSON data to send message, error code: ", parseResult);
        return messageData;
    }
    if (!grpRecipient.empty()) {
        recipient = grpRecipient;
    }
    if (toSibling) {
        recipient = ownUser_;
    }
    auto idKeys = getIdentityKeys(recipient);

    // If no identity keys and no device information available for this user then we need to handle this as
    // a new user, thus get some data from provisioning server. However, do this only if not sending
    // data to an own sibling device
    bool newUser = false;
    if (!toSibling && idKeys->empty()) {
        int32_t errorCode;
        auto devicesNewUser = getDevicesNewUser(recipient, authorization_, &errorCode);
        if (errorCode != SUCCESS) {
            if (result != nullptr) {
                *result = errorCode;
            }
            errorCode_ = errorCode;
            errorInfo_ = "Cannot get device info for new user";
            return messageData;
        }
        idKeys = createIdDevInfo(devicesNewUser);
        newUser = true;
    }

    if (idKeys->empty()) {
        int32_t code = toSibling ? SUCCESS : NO_DEVS_FOUND; // A user's account may not have sibling devices
        if (result != nullptr) {
            *result = code;
        }
        errorCode_ = code;
        errorInfo_ = "No device for available for this user.";
        return messageData;
    }
    int64_t transportMsgId;
    ZrtpRandom::getRandomData(reinterpret_cast<uint8_t*>(&transportMsgId), 8);
    uint64_t counter = 0;

    // The transport id is structured: bits 0..3 are status/type bits, bits 4..7 is a counter, bits 8..63 random data
    transportMsgId &= ~0xff;

    while (!idKeys->empty()) {
        const string idDevInfo = idKeys->front();
        idKeys->pop_front();

        // idDevInfo has the format:
        //       0           1         2        3
        // 'identityKey:deviceName:deviceId:verifyState', deviceName may be empty
        auto info = Utilities::splitString(idDevInfo, ":");

        string& deviceId = info->at(2);
        if (toSibling && deviceId == scClientDevId_) {
            continue;
        }
        // Setup and queue the prepared message info data
        auto msgInfo = make_shared<MsgQueueInfo>();
        msgInfo->command = SendMessage;
        msgInfo->queueInfo_recipient = recipient;
        msgInfo->queueInfo_deviceName = info->at(1);
        msgInfo->queueInfo_deviceId = deviceId;
        msgInfo->queueInfo_msgId = msgId;
        msgInfo->queueInfo_message = message;
        msgInfo->queueInfo_attachment = attachmentDescriptor;
        msgInfo->queueInfo_attributes = messageAttributes;
        msgInfo->queueInfo_transportMsgId = transportMsgId | (counter << 4) | messageType;
        msgInfo->queueInfo_toSibling = toSibling;
        msgInfo->queueInfo_newUserDevice = newUser;
        counter++;
        queuePreparedMessage(msgInfo);

        // Prepare the return data structure and fill into list
        auto resultData = make_shared<PreparedMessageData>();
        resultData->transportId = msgInfo->queueInfo_transportMsgId;
        resultData->receiverInfo = idDevInfo;
        messageData->push_back(resultData);
    }
    // Can happen if sending to siblings but no sibling device available
    if (messageData->empty()) {
        if (result != nullptr) {
            *result = NO_DEVS_FOUND;
        }
        errorCode_ = NO_DEVS_FOUND;
        errorInfo_ = "No sibling device(s) available.";
    }
    return messageData;
}

string  AppInterfaceImpl::createSendErrorJson(const shared_ptr<MsgQueueInfo>& info, int32_t errorCode)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);

    cJSON* details;
    cJSON_AddItemToObject(root, "details", details = cJSON_CreateObject());

    cJSON_AddStringToObject(details, "name", info->queueInfo_recipient.c_str());
    cJSON_AddStringToObject(details, "scClientDevId", info->queueInfo_deviceId.c_str());
    cJSON_AddStringToObject(details, "msgId", info->queueInfo_msgId.c_str());   // May help to diagnose the issue
    cJSON_AddNumberToObject(details, "errorCode", errorCode);

    char *out = cJSON_PrintUnformatted(root);
    string retVal(out);
    cJSON_Delete(root); free(out);

    return retVal;
}

int32_t AppInterfaceImpl::doSendSingleMessage(uint64_t transportId)
{
    auto ids = make_shared<vector<uint64_t> >();
    ids->push_back(transportId);
    return doSendMessages(ids);
}

int32_t AppInterfaceImpl::doSendMessages(shared_ptr<vector<uint64_t> > transportIds)
{
    LOGGER(INFO, __func__, " -->");

    size_t numOfIds = transportIds->size();
    list<shared_ptr<MsgQueueInfo> > messagesToProcess;

    unique_lock<mutex> prepareLock(preparedMessagesLock);
    for (size_t sz = 0; sz < numOfIds; sz++) {
        uint64_t id = transportIds->at(sz);
        auto it = preparedMessages.find(id);
        if (it != preparedMessages.end()) {
            // Found a prepared message
            messagesToProcess.push_back(it->second);
            preparedMessages.erase(it);
        }
    }
    prepareLock.unlock();

    addMsgInfosToRunQueue(messagesToProcess);

    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t
AppInterfaceImpl::sendMessageExisting(shared_ptr<MsgQueueInfo> sendInfo, shared_ptr<AxoConversation> axoConversation)
{
    LOGGER(INFO, __func__, " -->");

    errorCode_ = SUCCESS;

    // Don't send this to sender device when sending to my sibling devices
    if (sendInfo->queueInfo_toSibling && sendInfo->queueInfo_deviceId == scClientDevId_) {
        return SUCCESS;
    }

    string supplements;
    createSupplementString(sendInfo->queueInfo_attachment, sendInfo->queueInfo_attributes, &supplements);

    if (axoConversation == nullptr) {
        axoConversation = AxoConversation::loadConversation(ownUser_, sendInfo->queueInfo_recipient, sendInfo->queueInfo_deviceId);
        if (!axoConversation->isValid()) {
            LOGGER(DEBUGGING, "Axolotl Conversation is NULL. Owner: ", ownUser_, ", recipient: ", sendInfo->queueInfo_recipient,
                   ", recipientDeviceId: ", sendInfo->queueInfo_deviceId);
            errorCode_ = axoConversation->getErrorCode();
            errorInfo_ = sendInfo->queueInfo_deviceId;
            return errorCode_;
        }
    }

    shared_ptr<string> supplementsEncrypted = make_shared<string>();

    cJSON* convJson = axoConversation->prepareForCapture(nullptr, true);

    // Encrypt the user's message and the supplementary data if necessary
    pair<string, string> idHashes;
    shared_ptr<const string> wireMessage = ZinaRatchet::encrypt(*axoConversation, sendInfo->queueInfo_message, supplements,
                                                               supplementsEncrypted, &idHashes);

    convJson = axoConversation->prepareForCapture(convJson, false);

    char* out = cJSON_PrintUnformatted(convJson);
    string convState(out);
    cJSON_Delete(convJson); free(out);

    MessageCapture::captureSendMessage(sendInfo->queueInfo_recipient, sendInfo->queueInfo_msgId, sendInfo->queueInfo_deviceId, convState,
                                       sendInfo->queueInfo_attributes, !sendInfo->queueInfo_attachment.empty());

    // If encrypt does not return encrypted data then report an error, code was set by the encrypt function
    if (!wireMessage) {
        LOGGER(ERROR, "Encryption failed, no wire message created, device id: ", sendInfo->queueInfo_deviceId);
        LOGGER(INFO, __func__, " <-- Encryption failed.");
        return axoConversation->getErrorCode();
    }
    axoConversation->storeConversation();

    bool hasIdHashes = !idHashes.first.empty() && !idHashes.second.empty();
    /*
     * Create the message envelope:
     {
         "name":           <string>         # sender's name
         "scClientDevId":  <string>         # sender's long device id
         "supplement":     <string>         # supplementary data, encrypted, B64
         "message":        <string>         # message, encrypted, B64
     }
    */

    MessageEnvelope envelope;
    envelope.set_name(ownUser_);
    envelope.set_scclientdevid(scClientDevId_);
    envelope.set_msgid(sendInfo->queueInfo_msgId);
    envelope.set_msgtype(static_cast<uint32_t>(sendInfo->queueInfo_transportMsgId & MSG_TYPE_MASK));
    if (!supplementsEncrypted->empty())
        envelope.set_supplement(*supplementsEncrypted);
    envelope.set_message(*wireMessage);
    if (hasIdHashes) {
        envelope.set_recvidhash(idHashes.first.data(), 4);
        envelope.set_senderidhash(idHashes.second.data(), 4);
    }
    wireMessage.reset();

    uint8_t binDevId[20];
    size_t res = hex2bin(sendInfo->queueInfo_deviceId.c_str(), binDevId);
    if (res == 0)
        envelope.set_recvdevidbin(binDevId, 4);

    string serialized = envelope.SerializeAsString();

    // We need to have them in b64 encoding, check if buffer is large enough. Allocate twice
    // the size of binary data, this is big enough to hold B64 plus paddling and terminator
    if (serialized.size() * 2 > tempBufferSize_) {
        delete tempBuffer_;
        tempBuffer_ = new char[serialized.size()*2];
        tempBufferSize_ = serialized.size()*2;
    }
    size_t b64Len = b64Encode((const uint8_t*)serialized.data(), serialized.size(), tempBuffer_, tempBufferSize_);

    // replace the binary data with B64 representation
    serialized.assign(tempBuffer_, b64Len);

    memset_volatile((void*)supplementsEncrypted->data(), 0, supplementsEncrypted->size());

    transport_->sendAxoMessage(sendInfo, serialized);
    LOGGER(INFO, __func__, " <--");

    return SUCCESS;

}

int32_t
AppInterfaceImpl::sendMessageNewUser(shared_ptr<MsgQueueInfo> sendInfo)
{
    LOGGER(INFO, __func__, " -->");

    errorCode_ = SUCCESS;

    // Don't send this to sender device, even when sending to my sibling devices
    if (sendInfo->queueInfo_toSibling && sendInfo->queueInfo_deviceId == scClientDevId_) {
        return SUCCESS;
    }

    // Check if conversation/user really not known. On new users the 'reScan' triggered by
    // SIP NOTIFY could have already created the conversation. In this case skip further
    // processing and just handle it as an existing user.
    auto axoConversation = AxoConversation::loadConversation(ownUser_, sendInfo->queueInfo_recipient, sendInfo->queueInfo_deviceId);
    if (axoConversation->isValid()) {
        return sendMessageExisting(sendInfo, axoConversation);
    }

    pair<const DhPublicKey*, const DhPublicKey*> preIdKeys;
    int32_t preKeyId = Provisioning::getPreKeyBundle(sendInfo->queueInfo_recipient, sendInfo->queueInfo_deviceId, authorization_, &preIdKeys);
    if (preKeyId == 0) {
        LOGGER(ERROR, "No pre-key bundle available for recipient ", sendInfo->queueInfo_recipient, ", device id: ", sendInfo->queueInfo_deviceId);
        LOGGER(INFO, __func__, " <-- No pre-key bundle");
        return NO_PRE_KEY_FOUND;
    }

    int32_t buildResult = AxoPreKeyConnector::setupConversationAlice(ownUser_, sendInfo->queueInfo_recipient, sendInfo->queueInfo_deviceId, preKeyId, preIdKeys);

    // This is always a security issue: return immediately, don't process and send a message
    if (buildResult != SUCCESS) {
        errorCode_ = buildResult;
        errorInfo_ = sendInfo->queueInfo_deviceId;
        return errorCode_;
    }
    // Read the conversation again and store the device name of the new user's device. The the user/device
    // is known and we can handle it as an existing user.
    axoConversation = AxoConversation::loadConversation(ownUser_, sendInfo->queueInfo_recipient, sendInfo->queueInfo_deviceId);
    if (!axoConversation->isValid()) {
        errorCode_ = axoConversation->getErrorCode();
        errorInfo_ = sendInfo->queueInfo_deviceId;
        return errorCode_;
    }
    axoConversation->setDeviceName(sendInfo->queueInfo_deviceName);
    LOGGER(INFO, __func__, " <--");

    return sendMessageExisting(sendInfo, axoConversation);
}

string AppInterfaceImpl::createMessageDescriptor(const string& recipient, const string& msgId, const string& msg)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();

    cJSON_AddStringToObject(root, MSG_VERSION, "1");
    cJSON_AddStringToObject(root, MSG_RECIPIENT, recipient.c_str());
    cJSON_AddStringToObject(root, MSG_ID, msgId.c_str());
    cJSON_AddStringToObject(root, MSG_DEVICE_ID, scClientDevId_.c_str());
    cJSON_AddStringToObject(root, MSG_MESSAGE, msg.empty() ? "" : msg.c_str());

    char *out = cJSON_PrintUnformatted(root);
    string result(out);
    free(out);

    return result;
}

