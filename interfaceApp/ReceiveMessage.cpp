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

// Functions to handle received messages.
//
// Created by werner on 29.08.16.
//

#include "AppInterfaceImpl.h"
#include "MessageEnvelope.pb.h"
#include "../ratchet/ratchet/ZinaRatchet.h"
#include "../storage/MessageCapture.h"
#include "../util/b64helper.h"
#include "../util/Utilities.h"
#include "JsonStrings.h"

#include <zrtp/crypto/sha256.h>

using namespace zina;

static string receiveErrorJson(const string& sender, const string& senderScClientDevId, const string& msgId,
                               const char* msgHex, int32_t errorCode, const string& sentToId, int32_t sqlCode, int32_t msgType)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    cJSON_AddNumberToObject(root, "version", 1);

    cJSON* details;
    cJSON_AddItemToObject(root, "details", details = cJSON_CreateObject());

    cJSON_AddStringToObject(details, "name", sender.c_str());
    cJSON_AddStringToObject(details, "scClientDevId", senderScClientDevId.c_str());
    cJSON_AddStringToObject(details, "otherInfo", msgHex);            // App may use this to retry after fixing the problem
    cJSON_AddStringToObject(details, "msgId", msgId.c_str());         // May help to diagnose the issue
    cJSON_AddNumberToObject(details, "errorCode", errorCode);
    cJSON_AddStringToObject(details, "sentToId", sentToId.c_str());
    cJSON_AddNumberToObject(root, MSG_TYPE, msgType);
    if (errorCode == DATABASE_ERROR)
        cJSON_AddNumberToObject(details, "sqlErrorCode", sqlCode);

    char *out = cJSON_PrintUnformatted(root);
    string retVal(out);
    free(out);

    return retVal;
}

static string receiveErrorDescriptor(const string& messageDescriptor, int32_t result)
{
    shared_ptr<cJSON> sharedRoot(cJSON_Parse(messageDescriptor.c_str()), cJSON_deleter);
    cJSON* root = sharedRoot.get();

    string sender(Utilities::getJsonString(root, MSG_SENDER, ""));
    string deviceId(Utilities::getJsonString(root, MSG_DEVICE_ID, ""));
    string msgId(Utilities::getJsonString(root, MSG_ID, ""));

    return receiveErrorJson(sender, deviceId, msgId, "Error processing plain text message", result, "", 0, -1);
}

static bool isCommand(shared_ptr<CmdQueueInfo> plainMsgInfo)
{
    LOGGER(INFO, __func__, " -->");

    int32_t msgType = plainMsgInfo->queueInfo_msgType;
    if (msgType == GROUP_MSG_CMD || msgType == MSG_CMD)
        return true;

    if (plainMsgInfo->queueInfo_supplement.empty())
        return false;

    shared_ptr<cJSON> sharedRoot(cJSON_Parse(plainMsgInfo->queueInfo_supplement.c_str()), cJSON_deleter);
    cJSON* jsSupplement = sharedRoot.get();
    string attributes =  Utilities::getJsonString(jsSupplement, "m", "");
    if (attributes.empty())
        return false;

    shared_ptr<cJSON> attributesJson(cJSON_Parse(attributes.c_str()), cJSON_deleter);
    cJSON* attributesRoot = attributesJson.get();

    string possibleCmd = Utilities::getJsonString(attributesRoot, MSG_COMMAND, "");
    if (!possibleCmd.empty())
        return true;

    possibleCmd = Utilities::getJsonString(attributesRoot, MSG_SYNC_COMMAND, "");
    if (!possibleCmd.empty())
        return true;

    possibleCmd = Utilities::getJsonString(attributesRoot, GROUP_COMMAND, "");
    if (!possibleCmd.empty())
        return true;

    return false;
}

int32_t AppInterfaceImpl::receiveMessage(const string& envelope, const string& uidString, const string& displayName)
{
    int64_t sequence;
    store_->insertReceivedRawData(envelope, uidString, displayName, &sequence);

    shared_ptr<CmdQueueInfo> msgInfo = make_shared<CmdQueueInfo>();
    msgInfo->command = ReceivedRawData;
    msgInfo->queueInfo_envelope = envelope;
    msgInfo->queueInfo_uid = uidString;
    msgInfo->queueInfo_displayName = displayName;
    msgInfo->queueInfo_sequence = sequence;

    addMsgInfoToRunQueue(msgInfo);
    return OK;
}

// Take a message envelope (see sendMessage above), parse it, and process the embedded data. Then
// forward the data to the UI layer.
static int32_t duplicates = 0;

void AppInterfaceImpl::processMessageRaw(shared_ptr<CmdQueueInfo> msgInfo)
{
    LOGGER(INFO, __func__, " -->");

    string& messageEnvelope = msgInfo->queueInfo_envelope;
    string& uid = msgInfo->queueInfo_uid;
    string& displayName = msgInfo->queueInfo_displayName;

    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256((uint8_t*)messageEnvelope.data(), (uint32_t)messageEnvelope.size(), hash);

    string msgHash;
    msgHash.assign((const char*)hash, SHA256_DIGEST_LENGTH);

    int32_t sqlResult = store_->hasMsgHash(msgHash);

    // If we found a duplicate, log and silently ignore it. Remove from DB queue if it is still available
    if (sqlResult == SQLITE_ROW) {
        LOGGER(WARNING, __func__, " Duplicate messages detected so far: ", ++duplicates);
        store_->deleteReceivedRawData(msgInfo->queueInfo_sequence);
        return;
    }

    // Cleanup old message hashes
    time_t timestamp = time(0) - MK_STORE_TIME;
    store_->deleteMsgHashes(timestamp);

    if (messageEnvelope.size() > tempBufferSize_) {
        delete tempBuffer_;
        tempBuffer_ = new char[messageEnvelope.size()];
        tempBufferSize_ = messageEnvelope.size();
    }
    size_t binLength = b64Decode(messageEnvelope.data(), messageEnvelope.size(), (uint8_t*)tempBuffer_, tempBufferSize_);
    string envelopeBin((const char*)tempBuffer_, binLength);

    MessageEnvelope envelope;
    envelope.ParseFromString(envelopeBin);

    // ****** TODO -- remove once group chat becomes availabe
    // **** this is for backward compatibility only --- remove once group chat becomes availabe
//    if (envelope.has_msgtype() && envelope.msgtype() >= GROUP_MSG_NORMAL)
//        return OK;
    // **** Until here

    // backward compatibility or in case the message Transport does not support
    // UID. Then fallback to data in the message envelope.
    const string& sender = uid.empty() ? envelope.name() : uid;

    const string& senderScClientDevId = envelope.scclientdevid();
    const string& supplements = envelope.has_supplement() ? envelope.supplement() : Empty;
    const string& message = envelope.message();
    const string& msgId = envelope.msgid();

    string sentToId;
    if (envelope.has_recvdevidbin())
        sentToId = envelope.recvdevidbin();

    bool wrongDeviceId = false;
    if (!sentToId.empty()) {
        uint8_t binDevId[20];
        hex2bin(scClientDevId_.c_str(), binDevId);

        wrongDeviceId = memcmp((void*)sentToId.data(), binDevId, sentToId.size()) != 0;

        char receiverId[16] = {0};
        size_t len;
        bin2hex((const uint8_t*)sentToId.data(), sentToId.size(), receiverId, &len);
        if (wrongDeviceId) {
            LOGGER(ERROR, __func__, "Message is for device id: ", receiverId, ", my device id: ", scClientDevId_);
        }
    }
    uuid_t uu = {0};
    uuid_parse(msgId.c_str(), uu);
    time_t msgTime = uuid_time(uu, NULL);
    time_t currentTime = time(NULL);
    time_t timeDiff = currentTime - msgTime;

    bool oldMessage = (timeDiff > 0 && timeDiff >= MK_STORE_TIME);

    pair<string, string> idHashes;
    bool hasIdHashes = false;
    if (envelope.has_recvidhash() && envelope.has_senderidhash()) {
        hasIdHashes = true;
        const string& recvIdHash = envelope.recvidhash();
        const string& senderIdHash = envelope.senderidhash();
        idHashes.first = recvIdHash;
        idHashes.second = senderIdHash;
    }
    auto axoConv = ZinaConversation::loadConversation(ownUser_, sender, senderScClientDevId);

    shared_ptr<string> supplementsPlain = make_shared<string>();
    shared_ptr<const string> messagePlain;

    cJSON* convJson = axoConv->prepareForCapture(nullptr, true);

    messagePlain = ZinaRatchet::decrypt(axoConv.get(), message, supplements, supplementsPlain, hasIdHashes ? &idHashes : NULL);
    errorCode_ = axoConv->getErrorCode();

    int32_t msgType = envelope.has_msgtype() ? envelope.msgtype() : MSG_NORMAL;

//    LOGGER(DEBUGGING, __func__, "++++ After decrypt: %s", messagePlain ? messagePlain->c_str() : "NULL");
    if (!messagePlain) {

        char* out = cJSON_PrintUnformatted(convJson);
        string convState(out);
        cJSON_Delete(convJson); free(out);

        MessageCapture::captureReceivedMessage(sender, msgId, senderScClientDevId, convState, string("{\"cmd\":\"failed\"}"), false, true);
        char b2hexBuffer[1004] = {0};

        // Remove un-decryptable message data
        store_->deleteReceivedRawData(msgInfo->queueInfo_sequence);

        if (oldMessage)
            errorCode_ = OLD_MESSAGE;
        if (wrongDeviceId)
            errorCode_ = WRONG_RECV_DEV_ID;
        size_t msgLen = min(message.size(), (size_t)500);
        size_t outLen;
        bin2hex((const uint8_t*)message.data(), msgLen, b2hexBuffer, &outLen);
        stateReportCallback_(0, errorCode_, receiveErrorJson(sender, senderScClientDevId, msgId, b2hexBuffer, errorCode_, sentToId, axoConv->getSqlErrorCode(), msgType));
        LOGGER(ERROR, __func__ , " Decryption failed: ", errorCode_, ", sender: ", sender, ", device: ", senderScClientDevId );
        if (errorCode_ == DATABASE_ERROR) {
            LOGGER(ERROR, __func__, " Database error: ", axoConv->getSqlErrorCode(), ", SQL message: ", *store_->getLastError());
        }
        return;
    }
    convJson = axoConv->prepareForCapture(convJson, false);
    char* out = cJSON_PrintUnformatted(convJson);
    string convState(out);
    cJSON_Delete(convJson); free(out);
    MessageCapture::captureReceivedMessage(sender, msgId, senderScClientDevId, convState, string("{\"cmd\":\"dummy\"}"), false);

    /*
     * Message descriptor for received message:
     {
         "version":    <int32_t>,            # Version of JSON send message descriptor, 1 for the first implementation
         "sender":     <string>,             # for SC this is either the user's name or the user's DID
         "scClientDevId" : <string>,         # the sender's long device id
         "message":    <string>              # the actual plain text message, UTF-8 encoded (Java programmers beware!)
    }
    */
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON_AddStringToObject(root, MSG_SENDER, sender.c_str());        // sender is the UUID string

    // backward compatibility or in case the message Transport does not support
    // alias handling. Then fallback to data in the message envelope.
    cJSON_AddStringToObject(root, MSG_DISPLAY_NAME, displayName.empty() ? envelope.name().c_str() : displayName.c_str());
    cJSON_AddStringToObject(root, MSG_DEVICE_ID, senderScClientDevId.c_str());
    cJSON_AddStringToObject(root, MSG_ID, msgId.c_str());
    cJSON_AddStringToObject(root, MSG_MESSAGE, messagePlain->c_str());

    cJSON_AddNumberToObject(root, MSG_TYPE, msgType);
    messagePlain.reset();

    out = cJSON_PrintUnformatted(root);
    string msgDescriptor(out);
    cJSON_Delete(root); free(out);


    // At this point, in one DB transaction:
    // - save msgDescriptor and supplements plain in DB,
    // - store msgHash,
    // - store staged message keys,
    // - save conversation,
    // - delete raw message data
    int64_t sequence;
    int32_t result;
    {
        store_->beginTransaction();

        result = store_->insertMsgHash(msgHash);
        if (SQL_FAIL(result))
            goto error_;

        result = axoConv->storeStagedMks();
        if (SQL_FAIL(result))
            goto error_;

        result = axoConv->storeConversation();
        if (SQL_FAIL(result))
            goto error_;

        result = store_->insertTempMsg(msgDescriptor, *supplementsPlain, msgType, &sequence);
        if (!SQL_FAIL(result))
            goto success_;

        error_:
            store_->rollbackTransaction();
            stateReportCallback_(0, DATABASE_ERROR, receiveErrorJson(sender, senderScClientDevId, msgId, "Error while storing state data", DATABASE_ERROR, sentToId, result, msgType));
            return;

        success_:
           store_->commitTransaction();
           store_->deleteReceivedRawData(msgInfo->queueInfo_sequence);
    }
    shared_ptr<CmdQueueInfo> plainMsgInfo = make_shared<CmdQueueInfo>();
    plainMsgInfo->command = ReceivedTempMsg;
    plainMsgInfo->queueInfo_sequence = sequence;
    plainMsgInfo->queueInfo_message = msgDescriptor;
    plainMsgInfo->queueInfo_supplement = *supplementsPlain;
    plainMsgInfo->queueInfo_msgType = msgType;

#ifndef UNITTESTS
    sendDeliveryReceipt(plainMsgInfo);
#endif

    processMessagePlain(plainMsgInfo);
    LOGGER(INFO, __func__, " <--");

}

void AppInterfaceImpl::processMessagePlain(shared_ptr<CmdQueueInfo> msgInfo)
{
    LOGGER(INFO, __func__, " -->");

    int64_t sequence;
    int32_t result;

    string attachmentDescr;
    string attributesDescr;

    string& supplementsPlain = msgInfo->queueInfo_supplement;
    if (!supplementsPlain.empty()) {
        shared_ptr<cJSON> sharedRoot(cJSON_Parse(supplementsPlain.c_str()), cJSON_deleter);
        cJSON* jsSupplement = sharedRoot.get();

        cJSON* cjTemp = cJSON_GetObjectItem(jsSupplement, "a");
        char* jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
        if (jsString != NULL) {
            attachmentDescr = jsString;
        }

        cjTemp = cJSON_GetObjectItem(jsSupplement, "m");
        jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
        if (jsString != NULL) {
            attributesDescr = jsString;
        }
    }

    if (msgInfo->queueInfo_msgType >= GROUP_MSG_NORMAL) {
        result = processGroupMessage(msgInfo->queueInfo_msgType, msgInfo->queueInfo_message, attachmentDescr, attributesDescr);
        if (result != OK) {
            groupStateReportCallback_(result, receiveErrorDescriptor(msgInfo->queueInfo_message, result));
            return;
        }
    }
    else {
        result = receiveCallback_(msgInfo->queueInfo_message, attachmentDescr, attributesDescr);
        if (result != OK) {
            stateReportCallback_(0, result, receiveErrorDescriptor(msgInfo->queueInfo_message, result));
            return;
        }
    }
    store_->deleteTempMsg(msgInfo->queueInfo_sequence);
    LOGGER(INFO, __func__, " <--");
}


void AppInterfaceImpl::sendDeliveryReceipt(shared_ptr<CmdQueueInfo> plainMsgInfo)
{
    LOGGER(INFO, __func__, " -->");
    // send delivery receipt for real messages only, not for commands - for backward compatibility we need to scan supplements
    if (isCommand(plainMsgInfo)) {
        LOGGER(INFO, __func__, " <-- no delivery receipt");
        return;
    }
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* attributeJson = sharedRoot.get();

    cJSON_AddStringToObject(attributeJson, MSG_COMMAND, DELIVERY_RECEIPT);
    cJSON_AddStringToObject(attributeJson, DELIVERY_TIME, Utilities::currentTimeISO8601().c_str());
    char *out = cJSON_PrintUnformatted(attributeJson);

    string command(out);
    free(out);

    string sender;
    string msgId;
    string message;
    // Parse a msg descriptor that's always correct because it was constructed above :-)
    parseMsgDescriptor(plainMsgInfo->queueInfo_message, &sender, &msgId, &message, true);
    Utilities::wipeString(message);

    int32_t result;
    auto preparedMsgData = prepareMessageInternal(createMessageDescriptor(sender, msgId), Empty, command, false, MSG_CMD, &result);

    if (result != SUCCESS) {
        LOGGER(ERROR, __func__, " <-- Error: ", result);
        return;
    }
    doSendMessages(extractTransportIds(preparedMsgData));
    LOGGER(INFO, __func__, " <--");
}