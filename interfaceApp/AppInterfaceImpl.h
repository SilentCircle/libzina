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
#ifndef APPINTERFACEIMPL_H
#define APPINTERFACEIMPL_H

/**
 * @file AppInterfaceImpl.h
 * @brief Implementation of the UI interface methods
 * @ingroup Zina
 * @{
 */

#include <stdint.h>
#include <map>

#include "AppInterface.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../util/UUID.h"
#include "../Constants.h"
#include "../ratchet/state/ZinaConversation.h"

typedef int32_t (*HTTP_FUNC)(const string& requestUri, const string& requestData, const string& method, string* response);

// Same as in ScProvisioning, keep in sync
typedef int32_t (*S3_FUNC)(const string& region, const string& requestData, string* response);

using namespace std;

namespace zina {
typedef enum CmdQueueCommands_ {
    SendMessage = 1,
    ReceivedRawData,
    ReceivedTempMsg,
    CheckForRetry
} CmdQueueCommands;

typedef struct CmdQueueInfo_ {
    CmdQueueCommands command;
    string stringData1;
    string stringData2;
    string stringData3;
    string stringData4;
    string stringData5;
    string stringData6;
    string stringData7;
    uint64_t uint64Data;
    int64_t int64Data;
    int32_t int32Data;
    bool boolData1;
    bool boolData2;
} CmdQueueInfo;

// Define useful names/aliases for the CmdQueueInfo structure, send message operation
#define queueInfo_recipient     stringData1
#define queueInfo_deviceId      stringData2
#define queueInfo_msgId         stringData3
#define queueInfo_deviceName    stringData4
#define queueInfo_message       stringData5
#define queueInfo_attachment    stringData6
#define queueInfo_attributes    stringData7
#define queueInfo_transportMsgId uint64Data
#define queueInfo_toSibling     boolData1
#define queueInfo_newUserDevice boolData2

// Define useful names/aliases for the CmdQueueInfo structure, receive message operation
#define queueInfo_envelope      stringData1
#define queueInfo_uid           stringData2
#define queueInfo_displayName   stringData3
#define queueInfo_supplement    stringData4
#define queueInfo_message_desc  stringData5
#define queueInfo_sequence      int64Data
#define queueInfo_msgType       int32Data

// Define bits for local retrnion handling
#define RETAIN_LOCAL_DATA       0x1
#define RETAIN_LOCAL_META       0x2

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
                    AppInterface(), tempBuffer_(NULL), tempBufferSize_(0), ownUser_(ownUser), authorization_(authorization),
                    scClientDevId_(scClientDevId), store_(store), transport_(NULL), siblingDevicesScanned_(false),
                    drLrmm_(false), drLrmp_(false), drLrap_(false), drBldr_(false), drBlmr_(false), drBrdr_(false), drBrmr_(false) {}
#endif
    AppInterfaceImpl(const string& ownUser, const string& authorization, const string& scClientDevId, 
                     RECV_FUNC receiveCallback, STATE_FUNC stateReportCallback, NOTIFY_FUNC notifyCallback,
                     GROUP_MSG_RECV_FUNC groupMsgCallback, GROUP_CMD_RECV_FUNC groupCmdCallback,
                     GROUP_STATE_FUNC groupStateCallback);

    ~AppInterfaceImpl();

    // Documentation see AppInterface.h
    void setTransport(Transport* transport) { transport_ = transport; }

    Transport* getTransport()               { return transport_; }

    int32_t receiveMessage(const string& messageEnvelope, const string& uid, const string& displayName);

    string* getKnownUsers();

    string getOwnIdentityKey() const;

    shared_ptr<list<string> > getIdentityKeys(string& user) const;

    int32_t registerZinaDevice(string* result);

    int32_t removeZinaDevice(string& scClientDevId, string* result);

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

    int32_t groupMessageRemoved(const string& groupId, const string& messageId);

    shared_ptr<list<shared_ptr<PreparedMessageData> > > prepareMessage(const string& messageDescriptor,
                                                                       const string& attachmentDescriptor,
                                                                       const string& messageAttributes,
                                                                       bool normalMsg, int32_t* result);

    shared_ptr<list<shared_ptr<PreparedMessageData> > > prepareMessageToSiblings(const string &messageDescriptor,
                                                                                 const string &attachmentDescriptor,
                                                                                 const string &messageAttributes,
                                                                                 bool normalMsg, int32_t *result);

    int32_t doSendMessages(shared_ptr<vector<uint64_t> > transportIds);

    int32_t removePreparedMessages(shared_ptr<vector<uint64_t> > transportIds);

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
     * @brief Get own device identifier.
     * @return Reference to own device identifier string
     */
    const string& getOwnDeviceId() const     { return scClientDevId_; }

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

    /**
     * @brief Initialization code must set a S3 helper function
     *
     * This is used ot post data to Amazon S3 for data retention
     * purposes. If it is not called then data retention is disabled.
     *
     * @param s3Helper Pointer to the helper function
     */
    static void setS3Helper(S3_FUNC httpHelper);

    void setFlags(int32_t flags)  { flags_ = flags; }

    bool isRegistered()           { return ((flags_ & 0x1) == 1); }

    SQLiteStoreConv* getStore()   { return store_; }

    /**
     * This is a functions we need only during development and testing.
     */
    void clearGroupData();


    /**
     * @brief Check for unhandled raw or plain messages in the database and retry.
     *
     * To keep the correct order of messages the function first checks and retries
     * plain messages and then for raw (encrypted) messages in the database queues.
     */
    void retryReceivedMessages();

    /**
     * @brief Set the data retention flags for the local user.
     *
     * The caller sets up a JSON formatted string that holds the data retention flags
     * for the local user. The JSON string
     *<verbatim>
     * {
     * "lrmm": "true" | "false",
     * "lrmp": "true" | "false",
     * "lrap": "true" | "false",
     * "bldr": "true" | "false",
     * "blmr": "true" | "false",
     * "brdr": "true" | "false",
     * "brmr": "true" | "false"
     * }
     *<endverbatim>
     * If the application does not call this function after ZINA initialization then ZINA
     * assumes "false" for each flag, same if the JSON string does not contain a flag or
     * the flag's value is not "true" or "false". Otherwise ZINA sets the flag to the
     * given value.
     *
     * @param flagsJson The JSON data of the flags to set.
     * @return SUCCESS (0) or error code. The function does not change flags in case of
     *         error return
     */
    int32_t setDataRetentionFlags(const string& jsonFlags);

#ifdef UNITTESTS
        void setStore(SQLiteStoreConv* store) { store_ = store; }
        void setGroupCmdCallback(GROUP_CMD_RECV_FUNC callback) { groupCmdCallback_ = callback; }
        void setGroupMsgCallback(GROUP_MSG_RECV_FUNC callback) { groupMsgCallback_ = callback; }
        void setOwnChecked(bool value) {siblingDevicesScanned_ = value; }

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

    int32_t parseMsgDescriptor(const string& messageDescriptor, string* recipient, string* msgId, string* message, bool receivedMsg = false);

    /**
     * @brief Handle a group message, either a normal or a command message.
     *
     * The normal receiver function already decrypted the message, attribute, and attachment data.
     */
    int32_t processGroupMessage(int32_t msgType, const string &msgDescriptor,
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

    /**
     * @brief Helper function add a message info structure to the run-Q
     *
     * @param msgInfo The message information structure of the message to send
     */
    void queuePreparedMessage(shared_ptr<CmdQueueInfo> &msgInfo);


    shared_ptr<list<shared_ptr<PreparedMessageData> > >
    prepareMessageInternal(const string& messageDescriptor,
                           const string& attachmentDescriptor,
                           const string& messageAttributes,
                           bool toSibling, uint32_t messageType, int32_t* result, const string& grpRecipient = Empty);

    /**
     * @brief Send a message to a user who has a valid ratchet conversation.
     *
     * If the caller provides a valid ratchet conversation the function use this conversation,
     * otherwise it looks up a conversation using data from the message information structure.
     * The function then encrypts the message data and supplementary data and hands over the
     * encrypted message data to the transport send function.
     *
     * This function runs in the run-Q thread only.
     *
     * @param sendInfo The message information structure of the message to send
     * @param zinaConversation an optional valid ratchet conversation
     * @return An error code in case of a failure, @c SUCCESS otherwise
     */
    int32_t sendMessageExisting(shared_ptr<CmdQueueInfo> sendInfo, shared_ptr<ZinaConversation> zinaConversation = nullptr);

    /**
     * @brief Send a message to a use who does not have a valid ratchet conversation.
     *
     * The function contacts the server to get a pre-key bundle for the user's device, prepares
     * a ratchet conversation for it, stores it and then call the function of an existing user
     * to further process the message.
     *
     * This function runs in the run-Q thread only.
     *
     * @param sendInfo The message information structure of the message to send
     * @return An error code in case of a failure, @c SUCCESS otherwise
     */
    int32_t sendMessageNewUser(shared_ptr<CmdQueueInfo> sendInfo);

    /**
     * @brief Move a single prepared message info to the processing queue.
     *
     * A small wrapper to handle a single 64-bit transport id and queue the message info
     * for processing.
     *
     * @param transportId The transport id of the message info to move to processing queue.
     * @return SUCCESS in case moving data was OK
     */
    int32_t doSendSingleMessage(uint64_t transportId);

    /**
     * @brief Add one message info data structure to the run queue.
     *
     * The function checks if the run-Q thread is active and starts it if not. It
     * then appends the data structure to the end of the run-Q.
     *
     * @param messageToProcess message info structure
     */
    void addMsgInfoToRunQueue(shared_ptr<CmdQueueInfo> messageToProcess);

    /**
     * @brief Add a List of message info structure to the run queue.
     *
     * The function checks if the run-Q thread is active and starts it if not. It
     * then appends the list entries to the end of the run-Q.
     *
     * @param messagesToProcess The list of message info structures
     */
    void addMsgInfosToRunQueue(list<shared_ptr<CmdQueueInfo> > messagesToProcess);

    /**
     * @brief Setup a retry command message info structure and add it to the run-Q.
     *
     * The application should call this after a fresh start to check and retry messages
     * stored in the persitent database queues.
     */
    void insertRetryCommand();

    /**
     * @brief Check is run-Q thread is actif and start it if not.
     */
    void checkStartRunThread();

    /**
     * @brief The run-Q thread function.
     *
     * @param obj The AppInterface object used by this thread function
     */
    static void commandQueueHandler(AppInterfaceImpl *obj);

    /**
     * @brief Decrypt received message.
     *
     * Gets received messages and decrypts them. If decryption was successful it
     * stores the decrypted message in a temporary message in in the database and
     * saves ratchet state data.
     *
     * It creates a message informatio structure and call the @c processMessagePlain
     * function to handle the plain message data.
     *
     * In case of decryption failures or database access errors the function creates
     * a JSON formatted state report and hands it to the application via the message
     * state report callback.
     *
     * This function runs in the run-Q thread only.
     *
     * @param msgInfo The received message information structure
     */
    void processMessageRaw(shared_ptr<CmdQueueInfo> msgInfo);

    /**
     * @brief Decrypt received message.
     *
     * Gets decrypted messages, performs the callback to the application (caller) and
     * removes the temporarily stored plain message if the callback returns without error.
     *
     * In case the application's callback function returns with an error code the function
     * creates a JSON formatted state report and hands it to the application via the message
     * state report callback.
     *
     * This function runs in the run-Q thread only.
     *
     * @param msgInfo The received message information structure
     */
    void processMessagePlain(shared_ptr<CmdQueueInfo> msgInfo);

    /**
     * @brief Send delivery receipt after successful decryption of the message
     *
     * This function runs in the run-Q thread only.
     *
     * @param plainMsgInfo The message command data
     */
    void sendDeliveryReceipt(shared_ptr<CmdQueueInfo> plainMsgInfo);

    /**
     * @brief Get sibling devices from provisioning server and add missing devices to id key list.
     *
     * @param idKeys List of already known sibling device id keys,
     * @return The list of new, yet unkonwn sibling devices, may be empty.
     */
    shared_ptr<list<string> > addSiblingDevices(shared_ptr<list<string> > idKeys);

    /**
     * @brief Helper function which creates a JSON formatted message descriptor.
     *
     * @param recipient Recipient of the message
     * @param msgId The message's identifier
     * @param msg The message, optional.
     * @return JSON formatted string
     */
    string createMessageDescriptor(const string& recipient, const string& msgId, const string& msg = Empty);

    /**
     * @brief Check data retentions flags and prepare for data retention.
     *
     * Check the data retention flags of the local party (the sender) and the remote
     * party (the receiver) to decide if it's OK to retain some data. If it's not OK
     * to retain data the function returns an error code.
     *
     * If it's OK to retain some data then prepare/enhance the message attributes to
     * contain the defined flags to info the remote party.
     *
     * @param recipient The UID of the remote party
     * @param msgAttributes The original message attributes
     * @param newMsgAttributes Contains the enhanced/modified message attrinutes if it's OK
     *        to retain data, not changed if the function returns an error code.
     * @param It data rention is OK then holds local retention flags: 1 - retain data, 2 - retain meta data
     * @return OK if data retention is OK, an error code otherwise
     */
    int32_t checkDataRetentionSend(const string &recipient, const string &msgAttributes,
                                   shared_ptr<string> newMsgAttributes, uint8_t *localRetentionFlags);

    /**
     * @brief Check and perform data retention, send delivery receipt or reject message.
     *
     * The function uses the various data retention flags and the the DR flags in the
     * message attributes to decide if data retention for this message is OK or not.
     *
     * If it's OK to retain the data then perform data retention, prepare and send a
     * delivery receipt and return @c true to the caller. The function also returns
     * @c true if data retention is not enabled at all.
     *
     * If it's not OK to retain the data the functions creates and sends an error command
     * message to the sender and returns @c false.
     *
     * @param plainMsgInfo Data of the received message
     * @return @c true or @c false in case the message was rejected due to DR policy
     */
    bool dataRetentionReceive(shared_ptr<CmdQueueInfo> plainMsgInfo);

    /**
     * @brief Check if the message is a command message
     *
     * @param msgType the message type
     * @param attributes JSON formatted string that contains the message attributes
     * @return @c true if it's a command message, @c false otherwise
     */
    bool isCommand(int32_t msgType, const string& attributes);

    /**
     * @brief Check if the message is a command message
     *
     * @param plainMsgInfo information about the message
     * @return @c true if it's a command message, @c false otherwise
     */
    bool isCommand(shared_ptr<CmdQueueInfo> plainMsgInfo);

    /**
     * @brief Send an error response to the sender of the message.
     *
     * The function sets some attributes to provide flexible handling. The local client
     * does not retain (stores) this command message and allows the receiver to retain it.
     *
     * @param error The error code
     * @param sender The message sender's uid
     * @param msgId The id of the message in error
     */
    void sendErrorCommand(const string& error, const string& sender, const string& msgId);

    /**
     * @brief Setup data and call data retention functions.
     *
     * Based on retainInfo the function either store the message meta data and/ot the
     * message plain text data.
     *
     * @param retainInfo Flags that control which data to store
     * @param sendInfo The message information
     * @return SUCCESS or an error code
     */
    int32_t doSendDataRetention(uint32_t retainInfo, shared_ptr<CmdQueueInfo> sendInfo);

    /**
     * @brief Helper function to create the JSON formatted supplementary message data.
     *
     * @param attachmentDesc The attachment descriptor of the message, may be empty
     * @param messageAttrib The message attributes, may be empty
     * @return JSON formatted string
     */
    static string createSupplementString(const string& attachmentDesc, const string& messageAttrib);

    /**
     * @brief Helper function to create a JSON formatted error report if sending fails.
     *
     * @param info The message's information structure
     * @param errorCode The error code, failure reason
     * @return JSON formatted string
     */
    static string createSendErrorJson(const shared_ptr<CmdQueueInfo>& info, int32_t errorCode);

    /**
     * @brief Helper function to extract transport ids from prepage message data.
     *
     * The function extracts transport ids from a list of prepared message data and stores
     * them in a unsigned int64 vector, ready for the @c doSendMessages function.
     *
     * @param data List of prepared message data
     * @return Vector with the transport ids
     */
    static shared_ptr<vector<uint64_t> > extractTransportIds(shared_ptr<list<shared_ptr<PreparedMessageData> > > data);

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
    // If we send to sibling devices and siblingDevicesScanned_ then check for possible new
    // sibling devices that may have registered while this client was offline.
    // If another sibling device registers for this account it does the same and sends
    // a sync message, the client receives it and we know the new device.
    bool siblingDevicesScanned_;

    // Data retention flags valid for the local user
    bool drLrmm_,       //!< local client retains message metadata
            drLrmp_,    //!< local client retains message plaintext
            drLrap_,    //!< local client retains attachment plaintext
            drBldr_,    //!< Block local data retention
            drBlmr_,    //!< Block local metadata retention
            drBrdr_,    //!< Block remote data retention
            drBrmr_;    //!< Block remote metadata retention
    };
} // namespace

/**
 * @}
 */

#endif // APPINTERFACEIMPL_H
