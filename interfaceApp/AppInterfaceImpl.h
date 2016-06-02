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
#ifndef UIINTERFACEIMPL_H
#define UIINTERFACEIMPL_H

/**
 * @file AppInterfaceImpl.h
 * @brief Implementation of the UI interface methods
 * @ingroup Axolotl++
 * @{
 */

#include <stdint.h>

#include "AppInterface.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../util/UUID.h"
#include "MessageEnvelope.pb.h"

// Same as in ScProvisioning, keep in sync
typedef int32_t (*HTTP_FUNC)(const string& requestUri, const string& requestData, const string& method, string* response);

using namespace std;

namespace axolotl {
class SipTransport;

class AppInterfaceImpl : public AppInterface
{
public:
#ifdef UNITTESTS
    explicit AppInterfaceImpl(SQLiteStoreConv* store) : AppInterface(), tempBuffer_(NULL), store_(store), transport_(NULL) {}
    AppInterfaceImpl(SQLiteStoreConv* store, const string& ownUser, const string& authorization, const string& scClientDevId) : 
                    AppInterface(), tempBuffer_(NULL), tempBufferSize_(0), ownUser_(ownUser), authorization_(authorization), scClientDevId_(scClientDevId),
                    store_(store), transport_(NULL), ownChecked_(false) {}
#endif
    AppInterfaceImpl(const string& ownUser, const string& authorization, const string& scClientDevId, 
                     RECV_FUNC receiveCallback, STATE_FUNC stateReportCallback, NOTIFY_FUNC notifyCallback);

    ~AppInterfaceImpl();

    // Documentation see AppInterface.h
    void setTransport(Transport* transport) { transport_ = transport; }

    Transport* getTransport()               { return transport_; }

    vector<int64_t>* sendMessage(const string& messageDescriptor, const string& attachementDescriptor, const string& messageAttributes);

    vector<int64_t>* sendMessageToSiblings(const string& messageDescriptor, const string& attachementDescriptor, const string& messageAttributes);

    int32_t receiveMessage(const string& messageEnvelope);

    int32_t receiveMessage(const string& messageEnvelope, const string& uid, const string& alias);

    void messageStateReport(int64_t messageIdentfier, int32_t statusCode, const string& stateInformation);

    string* getKnownUsers();

    string getOwnIdentityKey() const;

    list<string>* getIdentityKeys(string& user) const;

    int32_t registerAxolotlDevice(string* result);

    int32_t removeAxolotlDevice(string& scClientDevId, string* result);

    int32_t newPreKeys(int32_t number);

    int32_t getNumPreKeys() const;

    void rescanUserDevices(string& userName);

    void reSyncConversation(const string& userName, const string& deviceId);

    string createNewGroup(string& groupName, string& groupDescription);

    int32_t createInvitedGroup(string& groupId, string& groupName, string& groupDescription, string& owner);

    bool modifyGroupSize(string& groupId, int32_t newSize);

    int32_t inviteUser(string& groupUuid, string& userId);


    // **** Below are methods for this implementation, not part of AppInterface.h
    /**
     * @brief Return the stored error code.
     * 
     * Functions of this implementation store error code in case they detect
     * a problem and return @c NULL, for example. In this case the caller should
     * get the error code and the additional error information for detailled error
     * data.
     * 
     * Functions overwrite the stored error code only if they return @c NULL or some
     * other error indicator.
     * 
     * @return The stored error code.
     */
    int32_t getErrorCode() const             { return errorCode_; }

    /**
     * @brief Get name of local user for this Axolotl conversation.
     */
    const string& getOwnUser() const         { return ownUser_; }

    /**
     * @brief Get authorization data of local user.
     */
    const string& getOwnAuthrization() const { return authorization_; }

    /**
     * @brief Return the stored error information.
     * 
     * Functions of this implementation store error information in case they detect
     * a problem and return @c NULL, for example. In this case the caller should
     * get the error code and the additional error information for detailed error
     * data.
     * 
     * Functions overwrite the stored error information only if they return @c NULL 
     * or some other error indicator.
     * 
     * @return The stored error information string.
     */
    const string& getErrorInfo() { return errorInfo_; }

    /**
     * @brief Initialization code must set a HTTP helper function
     * 
     * @param httpHelper Pointer to the helper functions
     */
    static void setHttpHelper(HTTP_FUNC httpHelper);

    void setFlags(int32_t flags)  { flags_ = flags; }

    bool isRegistered()           {return ((flags_ & 0x1) == 1); }

private:
    // do not support copy, assignment and equals
    AppInterfaceImpl (const AppInterfaceImpl& other ) = delete;
    AppInterfaceImpl& operator= ( const AppInterfaceImpl& other ) = delete;
    bool operator== ( const AppInterfaceImpl& other ) const  = delete;

    vector<int64_t>*
    sendMessageInternal(const string& recipient, const string& msgId, const string& message,
                        const string& attachmentDescriptor, const string& messageAttributes, uint32_t messageType=0);

    vector<int64_t>*
    sendMessagePreKeys(const string& recipient, const string& msgId, const string& message,
                       const string& attachmentDescriptor, const string& messageAttributes, uint32_t messageType=0);

    int32_t parseMsgDescriptor(const string& messageDescriptor, string* recipient, string* msgId, string* message );
    /**
     * Only the 'Alice' role uses this function to create a pre-key message (msg-type 2)
     * and sends this to the receiver (the 'Bob' role)
     */
    int32_t createPreKeyMsg(const string& recipient, const string& recipientDeviceId, const string& recipientDeviceName, const string& message, 
                            const string& supplements, const string& msgId, vector< pair< string, string > >* msgPairs, shared_ptr<string> convState,
                            uint32_t messageType=0);

    int32_t processReceivedGroupMsg(MessageEnvelope& envelope, string& msgDescriptor, string& attachmentDescr, string& attributesDescr);

    static string generateMsgId() {
        uuid_t uuid = {0};
        uuid_string_t uuidString = {0};

        uuid_generate_time(uuid);
        uuid_unparse(uuid, uuidString);
        return string(uuidString);
    }

    char* tempBuffer_;
    size_t tempBufferSize_;
    string ownUser_;
    string authorization_;
    string scClientDevId_;

    int32_t errorCode_;
    string errorInfo_;
    SQLiteStoreConv* store_;
    Transport* transport_;
    int32_t flags_;
    // If this is true then we checked own devices and see only one device for
    // own account it's the sending device. If another device registers for this
    // account it sends out a sync message, the client receives this and we have
    // a second device
    bool ownChecked_;
};
} // namespace

/**
 * @}
 */

#endif // UIINTERFACEIMPL_H
