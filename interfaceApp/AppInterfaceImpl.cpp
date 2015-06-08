#include "AppInterfaceImpl.h"
#include "MessageEnvelope.pb.h"

#include "../axolotl/crypto/AesCbc.h"
#include "../axolotl/Constants.h"
#include "../axolotl/AxoPreKeyConnector.h"
#include "../axolotl/state/AxoConversation.h"
#include "../axolotl/ratchet/AxoRatchet.h"

#include "../interfaceTransport/sip/SipTransport.h"
#include "../keymanagment/PreKeys.h"
#include "../util/cJSON.h"
#include "../util/b64helper.h"
#include "../provisioning/Provisioning.h"
#include "../provisioning/ScProvisioning.h"
#include "../storage/sqlite/SQLiteStoreConv.h"

#include <libzrtpcpp/zrtpB64Encode.h>
#include <libzrtpcpp/zrtpB64Decode.h>

#include <iostream>
#include <algorithm>
#include <utility>

using namespace axolotl;

static std::string Empty;

void Log(const char* format, ...);

AppInterfaceImpl::AppInterfaceImpl(const std::string& ownUser, const std::string& authorization, const std::string& scClientDevId,
                                 RECV_FUNC receiveCallback, STATE_FUNC stateReportCallback):
                 AppInterface(receiveCallback, stateReportCallback), tempBuffer_(NULL), tempBufferSize_(0),
                 ownUser_(ownUser), authorization_(authorization), scClientDevId_(scClientDevId)
{
    store_ = SQLiteStoreConv::getStore();
}

AppInterfaceImpl::~AppInterfaceImpl()
{
    tempBufferSize_ = 0; delete tempBuffer_; tempBuffer_ = NULL;
    delete transport_; transport_ = NULL;
}

static void createSupplementString(const std::string& attachementDesc, const std::string& messageAttrib, std::string* supplement)
{
    if (!attachementDesc.empty() || !messageAttrib.empty()) {
        cJSON* msgSupplement = cJSON_CreateObject();

        if (!attachementDesc.empty())
            cJSON_AddStringToObject(msgSupplement, "a", attachementDesc.c_str());

        if (!messageAttrib.empty())
            cJSON_AddStringToObject(msgSupplement, "m", messageAttrib.c_str());

        char *out = cJSON_PrintUnformatted(msgSupplement);

        supplement->append(out);
        cJSON_Delete(msgSupplement); free(out);
    }
}

/*
 {
    "version":    <int32_t>,            # Version of JSON send message descriptor, 1 for the first implementation
    "recipient":  <string>,             # for SC this is either the user's name of the user's DID
    "deviceId" :  <int32_t>,            # optional, if we support multi-device, defaults to 1 if missing
                                        # set to 0 to send the message to each registered device 
                                        # of the user
    "message":    <string>              # the actual plain text message, UTF-8 encoded (Java programmers beware!)
 }
 */
std::vector<int64_t>* AppInterfaceImpl::sendMessage(const std::string& messageDescriptor, const std::string& attachementDescriptor, const std::string& messageAttributes)
{

    std::string recipient;
    std::string message;
    int32_t parseResult = parseMsgDescriptor(messageDescriptor, &recipient, &message);

    if (parseResult < 0)
        return NULL;

    std::list<std::string>* devices = store_->getLongDeviceIds(recipient, ownUser_);
    int32_t numDevices = devices->size();

    if (numDevices == 0) {
        std::vector<std::pair<std::string, std::string> >* msgPairs = sendMessagePreKeys(messageDescriptor, attachementDescriptor, messageAttributes);
        if (msgPairs == NULL) {
            return NULL;
        }
        std::vector<int64_t>* returnMsgIds = transport_->sendAxoMessage(recipient, msgPairs);
        delete msgPairs;
        return returnMsgIds;
    }

    // TODO: some check to look-up for new devices of a user, maybe triggered by UI etc.

    std::string supplements;
    createSupplementString(attachementDescriptor, messageAttributes, &supplements);

    // Prepare the messages for all known device of this user
    std::vector<std::pair<std::string, std::string> >* msgPairs = new std::vector<std::pair<std::string, std::string> >;

    while (!devices->empty()) {
        std::string recipientDeviceId = devices->front();
        devices->pop_front();

        AxoConversation* axoConv = AxoConversation::loadConversation(ownUser_, recipient, recipientDeviceId);
 
        std::string supplementsEncrypted;

        // Encrypt the user's message and the supplementary data if necessary
        const string* wireMessage = AxoRatchet::encrypt(*axoConv, message, supplements, &supplementsEncrypted);
        axoConv->storeConversation();
        delete axoConv;
        /*
         * Create the message envelope:
         {
             "name":           <string>         # sender's name
             "scClientDevId":  <string>         # sender's long device id
             "supplement":     <string>         # suplementary data, encrypted, B64
             "message":        <string>         # message, encrypted, B64
         }
        */

        MessageEnvelope envelope;
        envelope.set_name(ownUser_);
        envelope.set_scclientdevid(scClientDevId_);
        if (!supplementsEncrypted.empty())
            envelope.set_supplement(supplementsEncrypted);
        envelope.set_message(*wireMessage);
        std::string serialized = envelope.SerializeAsString();

        // We need to have them in b64 encodeing, check if buffer is large enough. Allocate twice
        // the size of binary data, this is big enough to hold B64 plus paddling and terminator
        if (serialized.size() * 2 > tempBufferSize_) {
            delete tempBuffer_;
            tempBuffer_ = new char[serialized.size()*2];
            tempBufferSize_ = serialized.size()*2;
        }
        int32_t b64Len = b64Encode((const uint8_t*)serialized.data(), serialized.size(), tempBuffer_);
        tempBuffer_[b64Len] = 0;

        // replace the binary data with B64 representation
        serialized.assign(tempBuffer_, b64Len);

        std::pair<std::string, std::string> msgPair(recipientDeviceId, serialized);
        msgPairs->push_back(msgPair);

        supplementsEncrypted.clear();
    }
    delete devices;

    std::vector<int64_t>* returnMsgIds = transport_->sendAxoMessage(recipient, msgPairs);
    delete msgPairs;
    return returnMsgIds;
}


static std::string receiveErrorJson(int32_t errorCode, const std::string& sender, const std::string& senderScClientDevId,
                                    const std::string& msgEnvelope)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON_AddNumberToObject(root, "code", errorCode);

    cJSON* details;
    cJSON_AddItemToObject(root, "details", details = cJSON_CreateObject());

    cJSON_AddStringToObject(details, "name", sender.c_str());
    cJSON_AddStringToObject(details, "scClientDevId", senderScClientDevId.c_str());
    cJSON_AddStringToObject(details, "otherInfo", msgEnvelope.c_str());    // App may use this to retry after fixing the problem

    char *out = cJSON_PrintUnformatted(root);
    std::string retVal(out);
    cJSON_Delete(root); free(out);

    return retVal;
}

// Take a message envelope (see sendMessage above), parse it, and process the embedded data. Then
// forward the data to the UI layer.
int32_t AppInterfaceImpl::receiveMessage(const std::string& messageEnvelope)
{
    if (messageEnvelope.size() > tempBufferSize_) {
        delete tempBuffer_;
        tempBuffer_ = new char[messageEnvelope.size()];
        tempBufferSize_ = messageEnvelope.size();
    }
    int32_t binLength = b64Decode(messageEnvelope.data(), messageEnvelope.size(), (uint8_t*)tempBuffer_);
    std::string envelopeBin((const char*)tempBuffer_, binLength);

    MessageEnvelope envelope;
    envelope.ParseFromString(envelopeBin);

    const std::string& sender = envelope.name();
    const std::string& senderScClientDevId = envelope.scclientdevid();
    const std::string& supplements = envelope.has_supplement() ? envelope.supplement() : Empty;
    const std::string& message = envelope.message();

    AxoConversation* axoConv = AxoConversation::loadConversation(ownUser_, sender, senderScClientDevId);

    Log("++++ Conversation: %p", axoConv);
    // This is a not yet seen user. Set up a basic Conversation structure. Decrypt uses it and fills
    // in the other data based on the received message.
    if (axoConv == NULL) {
        axoConv = new AxoConversation(ownUser_, sender, senderScClientDevId);
    }
    Log("++++ Conversation partner: %s", axoConv->getPartner().getName().c_str());
    std::string supplementsPlain;
    std::string* messagePlain;
    messagePlain = AxoRatchet::decrypt(*axoConv, message, supplements, &supplementsPlain);

    if (messagePlain == NULL) {
        errorCode_ = NOT_DECRYPTABLE;
        messageStateReport(0, -1, receiveErrorJson(errorCode_, sender, senderScClientDevId, messageEnvelope));
        delete axoConv;
        return errorCode_;
    }
    // Here we can delete A0 in case it was set, if this as Alice then Bob replied and
    // A0 is not needed anymore.
    delete(axoConv->getA0());
    axoConv->setA0(NULL);
    axoConv->storeConversation();
    delete axoConv;
    /*
     * Message descriptor for received message:
     {
         "version":    <int32_t>,            # Version of JSON send message descriptor, 1 for the first implementation
         "sender":     <string>,             # for SC this is either the user's name or the user's DID
                                             # set to 0 to send the message to each registered device 
                                             # of the user
         "scClientDevId" : <string>,         # the sender's long device id
         "message":    <string>              # the actual plain text message, UTF-8 encoded (Java programmers beware!)
    }
    */
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON_AddStringToObject(root, "sender", sender.c_str());
    cJSON_AddStringToObject(root, "scClientDevId", senderScClientDevId.c_str());
    cJSON_AddStringToObject(root, "message", messagePlain->c_str());
    delete messagePlain;

    char *out = cJSON_PrintUnformatted(root);
    std::string msgDescriptor(out);

    cJSON_Delete(root); free(out);

    std::string attachmentDescr;
    std::string attributesDescr;
    if (!supplementsPlain.empty()) {
        checkAndRemovePadding(supplementsPlain);
        cJSON* jsSupplement = cJSON_Parse(supplementsPlain.c_str());

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
        cJSON_Delete(jsSupplement);
    }
    receiveCallback_(msgDescriptor, attachmentDescr, attributesDescr);
    return OK;
}

/*
JSON state information block:
{   
    "version":    <int32_t>,            # Version of the JSON known users structure,
                                        # 1 for the first implementation
    "code":       <int32_t>,            # success, error codes (code values to be 
                                        # defined)
    "details": {                        # optional, in case of error code it includes
                                        # detail information
        "name":      <string>,          # optional, name of sender/recipient of message,
                                        # if known
        "deviceId":  <int32_t>,         # optional, device id of sender/recipient,
                                        # if known
        "scClientDevId" : <string>,     # the same string as used to register the 
                                        # device (v1/me/device/{device_id}/)
        "otherInfo": <string>           # optional, additional info, e.g. SIP server 
                                        # messages
    }
}
*/
void AppInterfaceImpl::messageStateReport(int64_t messageIdentfier, int32_t statusCode, const std::string& stateInformation)
{
    stateReportCallback_(messageIdentfier, statusCode, stateInformation);
}

std::string* AppInterfaceImpl::getKnownUsers()
{
    if (!store_->isReady())
        return NULL;

    std::list<std::string>* names = store_->getKnownConversations(ownUser_);

    if (SQL_FAIL(store_->getSqlCode()) || names == NULL) {
        std::cerr << "generatePreKey: " << store_->getLastError() << '\n';
        return NULL;
    }
    int32_t size = names->size();

    cJSON *root,*nameArray;
    root=cJSON_CreateObject();
    cJSON_AddItemToObject(root, "version", cJSON_CreateNumber(1));
    cJSON_AddItemToObject(root, "users", nameArray = cJSON_CreateArray());

    for (int32_t i = 0; i < size; i++) {
        std::string name = names->front();
        cJSON_AddItemToArray(nameArray, cJSON_CreateString(name.c_str()));
        names->pop_front();
    }
    delete names;

    char *out = cJSON_PrintUnformatted(root);
    std::string* retVal = new std::string(out);
    cJSON_Delete(root); free(out);

    return retVal;
}

/*
 * JSON data for a registration request:
{
    "version" :        <int32_t>,        # Version of JSON registration, 1 for the first implementation
    "scClientDevId"  : <string>,         # the same string as used to register the device (v1/me/device/{device_id}/)
    "registrationId" : <int32_t>,        # this client's Axolotl registration id
    "identityKey" :    <string>,         # public part encoded base64 data 
    "signedPreKey" :
    {
        "keyId" :     <int32_t>,         # The key id of the signed pre key
        "key" :       <string>,          # public part encoded base64 data
        "signature" : <string>           # base64 encoded signature data"
    }
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
int32_t AppInterfaceImpl::registerAxolotlDevice(std::string* result)
{
    cJSON *root;
    char b64Buffer[MAX_KEY_BYTES_ENCODED*2];   // Twice the max. size on binary data - b64 is times 1.5

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
//    cJSON_AddStringToObject(root, "scClientDevId", scClientDevId_.c_str());

    AxoConversation* ownConv = AxoConversation::loadLocalConversation(ownUser_);
    if (ownConv == NULL) {
        cJSON_Delete(root);
        return NO_OWN_ID;
    }
    const DhKeyPair* myIdPair = ownConv->getDHIs();
    if (myIdPair == NULL) {
        cJSON_Delete(root);
        return NO_OWN_ID;
    }
    std::string data = myIdPair->getPublicKey().serialize();

    delete myIdPair;

    int32_t b64Len = b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer);
    b64Buffer[b64Len] = 0;
    cJSON_AddStringToObject(root, "identity_key", b64Buffer);

    cJSON* jsonPkrArray;
    cJSON_AddItemToObject(root, "prekeys", jsonPkrArray = cJSON_CreateArray());

    list<pair< int32_t, const DhKeyPair* > >* preList = PreKeys::generatePreKeys(store_);
    if (preList == NULL) {
        cJSON_Delete(root);
        return REG_PRE_KEY;
    }
    int32_t size = preList->size();
    for (int32_t i = 0; i < size; i++) {
        pair< int32_t, const DhKeyPair* >pkPair = preList->front();
        preList->pop_front();

        cJSON* pkrObject;
        cJSON_AddItemToArray(jsonPkrArray, pkrObject = cJSON_CreateObject());
        cJSON_AddNumberToObject(pkrObject, "id", pkPair.first);

        // Get pre-key's public key data, serialized
        const DhKeyPair* ecPair = pkPair.second;
        const std::string data = ecPair->getPublicKey().serialize();

        b64Len = b64Encode((const uint8_t*)data.data(), data.size(), b64Buffer);
        b64Buffer[b64Len] = 0;
        cJSON_AddStringToObject(pkrObject, "key", b64Buffer);
        delete ecPair;
    }
    delete preList;

    char *out = cJSON_Print(root);
    std::string registerRequest(out);
    cJSON_Delete(root); free(out);

    int32_t code = Provisioning::registerAxoDevice(registerRequest, authorization_, scClientDevId_, result);

    return code;
}

int32_t AppInterfaceImpl::newPreKeys(int32_t number)
{
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    string result;
    return ScProvisioning::newPreKeys(store, scClientDevId_, authorization_, &result);
}

void AppInterfaceImpl::setHttpHelper(HTTP_FUNC httpHelper)
{
    ScProvisioning::setHttpHelper(httpHelper);
}

// ***** Private functions 
// *******************************

std::vector<std::pair<std::string, std::string> >* AppInterfaceImpl::sendMessagePreKeys(const std::string& messageDescriptor, 
                                                                                        const std::string& attachementDescriptor, 
                                                                                        const std::string& messageAttributes)
{
    std::string recipient;
    std::string message;
    int32_t parseResult = parseMsgDescriptor(messageDescriptor, &recipient, &message);

    if (parseResult < 0)
        return NULL;

    std::string supplements;
    createSupplementString(attachementDescriptor, messageAttributes, &supplements);

    std::list<std::string>* devices = Provisioning::getAxoDeviceIds(recipient, authorization_);
    if (devices == NULL || devices->empty()) {
        errorCode_ = NO_DEVS_FOUND;
        errorInfo_ = recipient;
        return NULL;
    }

    // Prepare the messages for all known device of this user
    std::vector<std::pair<std::string, std::string> >* msgPairs = new std::vector<std::pair<std::string, std::string> >;

    while (!devices->empty()) {
        std::string recipientDeviceId = devices->front();
        devices->pop_front();

        int32_t result = createPreKeyMsg(recipient, recipientDeviceId, message, supplements, msgPairs);
        if (result == 0)   // no pre-key bundle available for name/device-id combination
            continue;

        // This is always a security issue: return immediately, don't process and send a message
        if (result < 0) {
            delete msgPairs;
            delete devices;
            errorCode_ = result;
            errorInfo_ = recipientDeviceId;
            return NULL;
        }
    }
    delete devices;

    if (msgPairs->empty()) {
        delete msgPairs;
        errorCode_ = NO_PRE_KEY_FOUND;
        errorInfo_ = recipient;
        return NULL;
    }
    return msgPairs;
}


int32_t AppInterfaceImpl::parseMsgDescriptor(const std::string& messageDescriptor, std::string* recipient, std::string* message)
{
    cJSON* root = cJSON_Parse(messageDescriptor.c_str());
    if (root == NULL) {
        errorInfo_ = "root";
        errorCode_ = JS_FIELD_MISSING;
        return JS_FIELD_MISSING;
    }

    cJSON* cjTemp = cJSON_GetObjectItem(root, "recipient");
    char* jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;

    if (jsString == NULL) {
        errorInfo_ = "recipient";
        goto cleanup;
    }
    recipient->assign(jsString);

    // Get the message
    cjTemp = cJSON_GetObjectItem(root, "message");
    jsString = (cjTemp != NULL) ? cjTemp->valuestring : NULL;
    if (jsString == 0) {
        errorInfo_ = "message";
        goto cleanup;
    }
    message->assign(jsString);
    cJSON_Delete(root);    // Done with JSON root for message data
    return OK;

cleanup:
    cJSON_Delete(root);    // Done with JSON root for message data
    return JS_FIELD_MISSING;
}


int32_t AppInterfaceImpl::createPreKeyMsg(string& recipient,  const std::string& recipientDeviceId,
                                          const std::string& message, const std::string& supplements, 
                                          std::vector<std::pair<std::string, std::string> >* msgPairs)
{
    pair<const DhPublicKey*, const DhPublicKey*> preIdKeys;
    int32_t preKeyId = Provisioning::getPreKeyBundle(recipient, recipientDeviceId, authorization_, &preIdKeys);
    if (preKeyId == 0)
        return 0;

    int32_t buildResult = AxoPreKeyConnector::setupConversationAlice(ownUser_, recipient, recipientDeviceId, preKeyId, preIdKeys);
    // This is always a security issue: return immediately, don't process and send a message
    if (buildResult < 0) {
        errorCode_ = buildResult;
        errorInfo_ = recipientDeviceId;
        return buildResult;
    }
    AxoConversation* axoConv = AxoConversation::loadConversation(ownUser_, recipient, recipientDeviceId);
 
    std::string supplementsEncrypted;

    // Encrypt the user's message and the supplementary data if necessary
    const string* wireMessage = AxoRatchet::encrypt(*axoConv, message, supplements, &supplementsEncrypted);
    axoConv->storeConversation();
    delete axoConv;
    /*
     * Create the message envelope:
     {
         "name":           <string>         # sender's name
         "scClientDevId":  <string>         # sender's long device id
         "deviceId":       <int32_t>        # optional, TextSecure device id
         "supplement":     <string>         # suplementary data, encrypted, B64
         "message":        <string>         # message, encrypted, B64
      }
      */

    MessageEnvelope envelope;
    envelope.set_name(ownUser_);
    envelope.set_scclientdevid(scClientDevId_);
    if (!supplementsEncrypted.empty())
        envelope.set_supplement(supplementsEncrypted);
    envelope.set_message(*wireMessage);

    std::string serialized = envelope.SerializeAsString();

    // We need to have them in b64 encodeing, check if buffer is large enough. Allocate twice
    // the size of binary data, this is big enough to hold B64 plus paddling and terminator
    if (serialized.size() * 2 > tempBufferSize_) {
        delete tempBuffer_;
        tempBuffer_ = new char[serialized.size()*2];
        tempBufferSize_ = serialized.size()*2;
    }
    int32_t b64Len = b64Encode((const uint8_t*)serialized.data(), serialized.size(), tempBuffer_);
    tempBuffer_[b64Len] = 0;

    // replace the binary data with B64 representation
    serialized.assign(tempBuffer_, b64Len);

    std::pair<std::string, std::string> msgPair(recipientDeviceId, serialized);
    msgPairs->push_back(msgPair);

    supplementsEncrypted.clear();
    return OK;
}
