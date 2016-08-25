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
#include <map>

#include "AppInterface.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../util/UUID.h"
#include "../Constants.h"
#include "../axolotl/state/AxoConversation.h"

// Same as in ScProvisioning, keep in sync
typedef int32_t (*HTTP_FUNC)(const string& requestUri, const string& requestData, const string& method, string* response);

using namespace std;

namespace axolotl {

/**
 * @brief Structure that contains return data of @c prepareMessage functions.
 */
typedef struct PreparedMessageData_ {
    uint64_t transportId;           //!<  The transport id of the prepared message
    string receiverInfo;            //!<  Some details about the receiver's device of this message
} PreparedMessageData;


typedef struct MsgQueueInfo_ {
    string recipient;
    string deviceId;
    string msgId;
    string deviceName;
    string message;
    string attachmentDescriptor;
    string messageAttributes;
    string envelope;
    uint64_t transportMsgId;
    bool toSibling;
    bool newUserDevice;
} MsgQueueInfo;

class SipTransport;
class MessageEnvelope;

// This is the ping command the code sends to new devices to create an Axolotl setup
static string ping("{\"cmd\":\"ping\"}");

class AppInterfaceImpl : public AppInterface
{
public:
#ifdef UNITTESTS
    explicit AppInterfaceImpl(SQLiteStoreConv* store) : AppInterface(), tempBuffer_(NULL), store_(store), transport_(NULL) {}
    AppInterfaceImpl(SQLiteStoreConv* store, const string& ownUser, const string& authorization, const string& scClientDevId) : 
                    AppInterface(), tempBuffer_(NULL), tempBufferSize_(0), ownUser_(ownUser), authorization_(authorization), scClientDevId_(scClientDevId),
                    store_(store), transport_(NULL), ownChecked_(false), delayRatchetCommit_(false) {}
#endif
    AppInterfaceImpl(const string& ownUser, const string& authorization, const string& scClientDevId, 
                     RECV_FUNC receiveCallback, STORE_FUNC storeCallback, STATE_FUNC stateReportCallback, NOTIFY_FUNC notifyCallback,
                     GROUP_MSG_RECV_FUNC groupMsgCallback, GROUP_CMD_RECV_FUNC groupCmdCallback,  GROUP_STATE_FUNC groupStateCallback);

    ~AppInterfaceImpl();

    // Documentation see AppInterface.h
    void setTransport(Transport* transport) { transport_ = transport; }

    Transport* getTransport()               { return transport_; }

//    vector<int64_t>* sendMessage(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes);
//
//    vector<int64_t>* sendMessageToSiblings(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes);

    int32_t receiveMessage(const string& messageEnvelope);

    int32_t receiveMessage(const string& messageEnvelope, const string& uid, const string& alias);

    string* getKnownUsers();

    string getOwnIdentityKey() const;

    shared_ptr<list<string> > getIdentityKeys(string& user) const;

    int32_t registerAxolotlDevice(string* result);

    int32_t removeAxolotlDevice(string& scClientDevId, string* result);

    int32_t newPreKeys(int32_t number);

    int32_t getNumPreKeys() const;

    void rescanUserDevices(string& userName);

    void reSyncConversation(const string& userName, const string& deviceId);

    string createNewGroup(string& groupName, string& groupDescription, int32_t maxMembers);

    int32_t createInvitedGroup(string& groupId, string& groupName, string& groupDescription, string& owner, int32_t maxMembers);

    bool modifyGroupSize(string& groupId, int32_t newSize);

    int32_t inviteUser(string& groupUuid, string& userId);

    int32_t answerInvitation(const string& command, bool accept, const string& reason);

    int32_t sendGroupMessage(const string& messageDescriptor, const string& attachmentDescriptor, const string& messageAttributes);

    int32_t leaveGroup(const string& groupId);

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

    bool isRegistered()           { return ((flags_ & 0x1) == 1); }

    SQLiteStoreConv* getStore()   { return store_; }

    void setDelayRatchetCommit(bool delay) { delayRatchetCommit_ = delay; }

    bool isDelayRatchetCommit() { return delayRatchetCommit_; }

    /**
     * This is a functions we need only during development and testing.
     */
    void clearGroupData();

    /**
     * @brief Prepare a user-to-user message for sending.
     *
     * The functions prepares a message and queues it for sending to the receiver' devices.
     * The function only prpares the message(s) but does not send them. To actually send the
     * the messages to the device(s) the application needs to call the @c sendPreparedMessage()
     * function.
     *
     * This function may trigger network actions, thus it must not run on the UI thread.
     *
     * The function creates a list of PreparedMessage data structures that contain information
     * for each prepared message:
     * <ul>
     * <li> a 64 bit integer which is the transport id of the prepared message. Libzina uses this
     *      transport id to identify a message in transit (during send) to the server and to report
     *      a message status to the application. The application must not modify this data and may
     *      use it to setup a queue to monitor the message status reports.</li>
     * <li> A string that contains recipient information. The data and format is the same as returned
     *      by @c AppInterfaceImpl::getIdentityKeys
     * </ul>
     *
     * @param messageDescriptor      the JSON formatted message descriptor, required
     * @param attachmentDescriptor   Optional, a string that contains an attachment descriptor. An empty string
     *                               shows that not attachment descriptor is available.
     * @param messageAttributes      Optional, a JSON formatted string that contains message attributes.
     *                               An empty string shows that not attributes are available.
     * @param result Pointer to result of the operation, if not @c SUCCESS then the returned list is empty
     * @return A list of prepared message information, or empty on failure
     */
    shared_ptr<list<shared_ptr<PreparedMessageData> > > prepareMessage(const string& messageDescriptor,
                                                                       const string& attachmentDescriptor,
                                                                       const string& messageAttributes, int32_t* result);

    shared_ptr<list<shared_ptr<PreparedMessageData> > > prepareMessageToSibling(const string& messageDescriptor,
                                                                                const string& attachmentDescriptor,
                                                                                const string& messageAttributes, int32_t* result);

    /**
     * @brief Encrypt the prepared messages and send them to the receiver.
     *
     * Queue the prepared message for encryption and sending to the receiver's devices.
     *
     * @param transportIds An array of transport id that identify the message to rncrypt and send.
     * @return SUCCESS in case moving data was OK
     */
    int32_t doSendMessages(shared_ptr<vector<uint64_t> > transportIds);

#ifdef UNITTESTS
        void setStore(SQLiteStoreConv* store) { store_ = store; }
        void setGroupCmdCallback(GROUP_CMD_RECV_FUNC callback) { groupCmdCallback_ = callback; }
        void setGroupMsgCallback(GROUP_MSG_RECV_FUNC callback) { groupMsgCallback_ = callback; }
        void setOwnChecked(bool value) {ownChecked_ = value; }

        static string generateMsgIdTime() {
            uuid_t uuid = {0};
            uuid_string_t uuidString = {0};

            uuid_generate_time(uuid);
            uuid_unparse(uuid, uuidString);
            return string(uuidString);
        }

#endif

private:
    // do not support copy, assignment and equals
    AppInterfaceImpl (const AppInterfaceImpl& other ) = delete;
    AppInterfaceImpl& operator= ( const AppInterfaceImpl& other ) = delete;
    bool operator== ( const AppInterfaceImpl& other ) const  = delete;

    /**
     * @brief Internal function to send a message.
     *
     * Sends a message to a receiver and the devices in the devices list.
     *
     * @param recipient The message receiver
     * @msgId The message id (UUID)
     * @param message The JSON formatted message descriptor, required
     * @param attachmentDescriptor  A string that contains an attachment descriptor. An empty string
     *                               shows that not attachment descriptor is available.
     * @param messageAttributes      Optional, a JSON formatted string that contains message attributes.
     *                               An empty string shows that not attributes are available.
     * @param devices a list of the recipient's devices
     * @messageType Identifies which type of message, see @c Constants.h for details
     * @return unique message identifiers if the messages were processed for sending, 0 if processing
     *         failed.
     *
     */
    vector<int64_t>*
    sendMessageInternal(const string& recipient, const string& msgId, const string& message,
                        const string& attachmentDescriptor, const string& messageAttributes,
                        shared_ptr<list<string> > devices, uint32_t messageType=MSG_NORMAL);

    /**
     * @brief Internal function to send a message to a new user.
     *
     * Sends a message to new recipient, optionally restricting to give device.
     *
     * For a new recipient we don't have a ratchet setup, this functions prepares the ratchet
     * and send the message. If the device list pointer is valid it may contain one device and
     * the function restricts the ratchet setup to this device
     *
     * @param recipient The message receiver
     * @msgId The message id (UUID)
     * @param message The JSON formatted message descriptor, required
     * @param attachmentDescriptor  A string that contains an attachment descriptor. An empty string
     *                               shows that not attachment descriptor is available.
     * @param messageAttributes      Optional, a JSON formatted string that contains message attributes.
     *                               An empty string shows that not attributes are available.
     * @param devices a list of the recipient's devices
     * @messageType Identifies which type of message, see @c Constants.h for details
     * @return unique message identifiers if the messages were processed for sending, 0 if processing
     *         failed.
     *
     */
    vector<int64_t>*
    sendMessagePreKeys(const string& recipient, const string& msgId, const string& message,
                       const string& attachmentDescriptor, const string& messageAttributes,
                       shared_ptr<list<string> > devices, uint32_t messageType=MSG_NORMAL);

    int32_t parseMsgDescriptor(const string& messageDescriptor, string* recipient, string* msgId, string* message );

    /**
     * Only the 'Alice' role uses this function to create a pre-key message (msg-type 2)
     * and sends this to the receiver (the 'Bob' role)
     */
    int32_t createPreKeyMsg(const string& recipient, const string& recipientDeviceId, const string& recipientDeviceName, const string& message, 
                            const string& supplements, const string& msgId, vector< pair< string, string > >* msgPairs, shared_ptr<string> convState,
                            uint32_t messageType=0);

    /**
     * @brief Handle a group message, either a normal or a command message.
     *
     * The normal receiver function already decrypted the message, attribute, and attachment data.
     */
    int32_t processGroupMessage(const MessageEnvelope &envelope, const string &msgDescriptor,
                                const string &attachmentDescr, const string &attributesDescr);

    /**
     * @brief Process a group command message.
     *
     * The @c processGroupMessage function calls this function after it checked
     * the message type.
     */
    int32_t processGroupCommand(const string& commandIn);

    int32_t sendGroupCommand(const string &recipient, const string &msgId, const string &command);

    int32_t syncNewGroup(const cJSON *root);

    int32_t invitationAccepted(const cJSON *root);

    int32_t createMemberListAnswer(const cJSON* root);

    bool checkActiveAndHash(const string &msgDescriptor, const string &messageAttributes);

    /**
     * @brief Process a member list answer.
     *
     * Another client sent a member list answer because this client requested it or as the
     * final answer if the invitation flow. The functions adds missing member nut does not
     * check the member-list hash value. The next group message or group command processing
     * performs this.
     *
     * @param root The parsed cJSON data structure of the member list command.
     * @return OK if the message list was processed without error.
     */
    int32_t processMemberListAnswer(const cJSON* root);

    /**
     * @brief Process a leave group command.
     *
     * The receiver of the command removes the member from the group. If the receiver is a
     * sibling device, i.e. has the same member id, then it removes all group member data
     * and then the group data. The function only removes/clears group related data, it
     * does not remove/clear the normal ratchet data of the removed group members.
     *
     * @param root The parsed cJSON data structure of the leave group command.
     * @return OK if the message list was processed without error.
     */
    int32_t processLeaveGroupCommand(const cJSON* root);

    /**
     * @brief Checks if the group exists or is active.
     *
     * If the client receives a group command message (except commands of the Invite flow)
     * or a group message but the group does not exist or is inactive on this client then
     * this function prepares and sends a "not a group member" response to the sender and
     * returns false.
     *
     * @param groupId The group to check
     * @param sender  The command/message sender
     * @return @c true if the group exists/is active, @c false otherwise
     */
    bool isGroupActive(const string& groupId, const string& sender);

    /**
     * @brief Process a Hello group command.
     *
     * The receiver of the command inserts the member to the group.
     *
     * @param root The parsed cJSON data structure of the leave group command.
     * @return OK if the message list was processed without error.
     */
    int32_t processHelloCommand(const cJSON* root);

     /**
      * @brief Parse a member list array in JSON and update in database.
      *
      * @param root The parsed cJSON data structure of the leave group command.
      * @param initialList if @c true the list was sent during invitation processing
      * @return OK if the message list was processed without error.
      */
    int32_t parseMemberList(const cJSON* root, bool initialList, const string& groupId);

    shared_ptr<list<shared_ptr<PreparedMessageData> > >
    prepareMessageInternal(const string& messageDescriptor,
                           const string& attachmentDescriptor,
                           const string& messageAttributes,
                           bool toSibling, uint32_t messageType, int32_t* result, string grpRecipient = Empty);

    int32_t sendMessageExisting(shared_ptr<MsgQueueInfo> sendInfo, shared_ptr<AxoConversation> axoConversation = nullptr);
    int32_t sendMessageNewUser(shared_ptr<MsgQueueInfo> sendInfo);

    void queuePreparedMessage(shared_ptr<MsgQueueInfo> &msgInfo);

    /**
     * @brief Move a single prepared message info to the processing queue.
     *
     * A small wrapper to hanle a single 64-bit transport id and queue the message info
     * for processing.
     *
     * @param transportId The transport id of the message info to move to processing queue.
     * @return SUCCESS in case moving data was OK
     */
    int32_t doSendSingleMessage(uint64_t transportId);

    static void runSendQueue(AppInterfaceImpl* obj);

    static void createSupplementString(const string& attachmentDesc, const string& messageAttrib, string* supplement);

#ifndef UNITTESTS
    static string generateMsgIdTime() {
        uuid_t uuid = {0};
        uuid_string_t uuidString = {0};

        uuid_generate_time(uuid);
        uuid_unparse(uuid, uuidString);
        return string(uuidString);
    }
#endif

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
    bool delayRatchetCommit_;

    /**
     * @brief Store Message data callback function.
     *
     * ZINA calls this function only if the parameter @c delayRatchetCommit_ is @c true
     *
     * Takes JSON formatted message descriptor of the received message and forwards it to the UI
     * code via a callback functions. The function accepts an optional JSON formatted attachment
     * descriptor and forwards it to the UI code if a descriptor is available.
     *
     * The implementation of this function should parse/store the data as appropriate and store it
     * in its message storage. If it could store the data successfully then the function returns
     * OK (1). Any other return code indicates an error.
     *
     * NOTE: this function must not call any ZINA functions to send messages or delivery receipts,
     *       burn notices, read receipts.
     *
     * This function should not perform long-running actions and should return as fast as possible.
     *
     * @param messageDescriptor      The JSON formatted message descriptor, string, required.
     *
     * @param attachmentDescriptor   Optional, a string that contains an attachment descriptor. An empty
     *                               string ot {@code null} shows that not attachment descriptor is available.
     *
     * @param messageAttributes      Optional, a JSON formatted string that contains message attributes.
     *                               An empty string ot {@code null} shows that not attributes are available.
     * @return Either success or an error code
     */
    STORE_FUNC storeCallback_;

    };
} // namespace

/**
 * @}
 */

#endif // UIINTERFACEIMPL_H
