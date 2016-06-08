//
// Implementation of group chat API
//
// Created by werner on 22.05.16.
//

#include "AppInterfaceImpl.h"

#include "../Constants.h"

#include "../logging/AxoLogging.h"
#include "GroupJsonStrings.h"
#include "MessageEnvelope.pb.h"
#include "../util/Utilities.h"

using namespace std;
using namespace axolotl;


static vector<string> tokens;

static void storeInviteToken(const string& token)
{
    tokens.push_back(token);
}

// Check if a token exist, if yes remove it and return true.
static bool checkInviteToken(const string& token)
{
    for (auto it = tokens.begin(); it != tokens.end(); ++it) {
        if (token != *it)
            continue;
        tokens.erase(it);
        return true;
    }
    return false;
}


static string inviteAnswerCmd(const cJSON* command, const string &user, const string &deviceId, bool accepted, const string &reason)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, INVITE_ANSWER);
    cJSON_AddStringToObject(root, GROUP_ID, Utilities::getJsonString(command, GROUP_ID, ""));
    cJSON_AddStringToObject(root, MEMBER_ID, user.c_str());
    cJSON_AddStringToObject(root, MEMBER_DEVICE_ID, deviceId.c_str());
    cJSON_AddStringToObject(root, TOKEN, Utilities::getJsonString(command, TOKEN, ""));
    cJSON_AddBoolToObject(root, ACCEPTED, accepted);

    if (!accepted && !reason.empty())
        cJSON_AddStringToObject(root, REASON, reason.c_str());

    char *out = cJSON_PrintUnformatted(root);
    string inviteCommand(out);
    free(out);
    return inviteCommand;
}

// ****** Public instance functions
// *******************************************************
string AppInterfaceImpl::createNewGroup(string& groupName, string& groupDescription) {
    LOGGER(INFO, __func__, " -->");

    uuid_t groupUuid = {0};
    uuid_string_t uuidString = {0};

    uuid_generate_time(groupUuid);
    uuid_unparse(groupUuid, uuidString);
    string groupId(uuidString);

    SQLiteStoreConv *store = SQLiteStoreConv::getStore();
    if (!store->isReady()) {
        errorInfo_ = " Conversation store not ready.";
        LOGGER(ERROR, __func__, errorInfo_);
        return Empty;
    }
    store->insertGroup(groupId, groupName, ownUser_, groupDescription, DEFAULT_GROUP_SIZE);

    // TODO: insert own record into member table
    LOGGER(INFO, __func__, " <--");
    return groupId;
}

int32_t AppInterfaceImpl::createInvitedGroup(string& groupId, string& groupName, string& groupDescription, string& owner)
{
    LOGGER(INFO, __func__, " -->");
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    if (!store->isReady()) {
        errorInfo_ = " Conversation store not ready.";
        LOGGER(ERROR, __func__, errorInfo_);
        return SQLITE_CANTOPEN;
    }
    int32_t result = store->insertGroup(groupId, groupName,  owner, groupDescription, DEFAULT_GROUP_SIZE);
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

bool AppInterfaceImpl::modifyGroupSize(string& groupId, int32_t newSize)
{
    LOGGER(INFO, __func__, " -->");
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    if (!store->isReady()) {
        errorInfo_ = " Conversation store not ready.";
        LOGGER(ERROR, __func__, errorInfo_);
        return false;
    }
    int32_t result;
    shared_ptr<cJSON> group = store->listGroup(groupId, &result);
    if (!group || SQL_FAIL(result)) {
        errorInfo_ = " Cannot get group data: ";
        errorInfo_.append(groupId);
        LOGGER(ERROR, __func__, errorInfo_);
        return false;
    }
    cJSON* root = group.get();
    string groupOwner(Utilities::getJsonString(root, GROUP_OWNER, ""));

    if (ownUser_ != groupOwner) {
        errorInfo_ = " Only owner can modify group member size";
        LOGGER(ERROR, __func__, errorInfo_);
        return false;
    }
    int32_t members = Utilities::getJsonInt(root, GROUP_MEMBER_COUNT, -1);
    if (members == -1 || members > newSize) {
        errorInfo_ = " Already more members in group than requested.";
        LOGGER(ERROR, __func__, errorInfo_, members);
        return false;

    }
    LOGGER(INFO, __func__, " <--");
    return true;
}

int32_t AppInterfaceImpl::inviteUser(string& groupUuid, string& userId)
{
    LOGGER(INFO, __func__, " -->");
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    if (!store->isReady()) {
        errorInfo_ = " Conversation store not ready.";
        LOGGER(ERROR, __func__, errorInfo_);
        return false;
    }

    int32_t result;
    shared_ptr<cJSON> group = store->listGroup(groupUuid, &result);
    if (!group || SQL_FAIL(result)) {
        errorInfo_ = " Cannot get group data: ";
        errorInfo_.append(groupUuid);
        LOGGER(ERROR, __func__, errorInfo_);
        return GROUP_ERROR_BASE + result;
    }
    cJSON* root = group.get();
    int32_t members = Utilities::getJsonInt(root, GROUP_MEMBER_COUNT, 1);
    int32_t maxMembers = Utilities::getJsonInt(root, GROUP_MAX_MEMBERS, 0);

    if (members >= maxMembers) {
        errorInfo_ = " Member limit reached.";
        LOGGER(ERROR, __func__, errorInfo_);
        return MAX_MEMBERS_REACHED;
    }
    cJSON_DeleteItemFromObject(root, GROUP_MEMBER_COUNT);
    cJSON_DeleteItemFromObject(root, GROUP_MOD_TIME);

    uuid_t inviteToken = {0};
    uuid_string_t tokenString = {0};

    uuid_generate_random(inviteToken);
    uuid_unparse(inviteToken, tokenString);
    storeInviteToken(tokenString);

    cJSON_AddStringToObject(root, GROUP_COMMAND, INVITE);
    cJSON_AddStringToObject(root, TOKEN, tokenString);
    cJSON_AddStringToObject(root, MEMBER_ID, ownUser_.c_str());     // which member sends the Invite

    char *out = cJSON_PrintUnformatted(root);
    string inviteCommand(out);
    free(out);

    LOGGER(INFO, __func__, " <--");
    return sendGroupCommandAllDevices(userId, generateMsgIdTime(), inviteCommand);
}

int32_t AppInterfaceImpl::answerInvitation(const string &command, bool accept, const string &reason)
{
    LOGGER(INFO, __func__, " -->");

    if (command.empty()) {
        return GROUP_CMD_MISSING_DATA;
    }
    shared_ptr<cJSON> sharedRoot(cJSON_Parse(command.c_str()), cJSON_deleter);
    cJSON* root = sharedRoot.get();

    string invitingUser(Utilities::getJsonString(root, MEMBER_ID, ""));
    if (!accept) {
        return sendGroupCommandAllDevices(invitingUser, generateMsgIdTime(),
                                          inviteAnswerCmd(root, ownUser_, scClientDevId_, accept, reason));
    }

    // User accepted invitation, get necessary data and create group data in database
    string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    string groupName(Utilities::getJsonString(root, GROUP_NAME, ""));
    string description(Utilities::getJsonString(root, GROUP_DESC, ""));
    string owner(Utilities::getJsonString(root, GROUP_OWNER, ""));

    createInvitedGroup(groupId, groupName, description, owner);

    // If this is a invite-sync command then just return, all necessary actions done.
    string grpCmd(Utilities::getJsonString(root, GROUP_COMMAND, ""));
    if (grpCmd.compare(INVITE_SYNC) == 0) {
        return OK;
    }
    string messageId = generateMsgIdTime();

    // Prepare invite-sync and sync the sibling devices
    cJSON_ReplaceItemInObject(root, GROUP_COMMAND, cJSON_CreateString(INVITE_SYNC));
    sendGroupCommandAllDevices(ownUser_, messageId, command);

    // Now send the accept message to the inviting user
    return sendGroupCommandAllDevices(invitingUser, messageId,
                                      inviteAnswerCmd(root, ownUser_, scClientDevId_, accept, reason));
}

// ****** Non public instance functions and helpers
// ******************************************************
int32_t AppInterfaceImpl::processGroupMessage(const MessageEnvelope &envelope, const string &msgDescriptor,
                                              const string &attachmentDescr, const string &attributesDescr)
{
    LOGGER(INFO, __func__, " -->");

    if (envelope.msgtype() == GROUP_MSG_CMD) {
        return processGroupCommand(attributesDescr);
    }
    if (envelope.msgtype() == GROUP_MSG_NORMAL && msgDescriptor.empty()) {
        return GROUP_MSG_DATA_INCONSISTENT;
    }
    // TODO check member-list hash and trigger actions if hashes differ
    groupMsgCallback_(msgDescriptor, attachmentDescr, attributesDescr);
    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::processGroupCommand(const string& commandIn)
{
    LOGGER(INFO, __func__, " --> ", commandIn);

    if (commandIn.empty()) {
        return GROUP_CMD_MISSING_DATA;
    }
    // wrap the cJSON root into a shared pointer with custom cJSON deleter, this
    // will always free the cJSON root when we leave the function :-) .
    shared_ptr<cJSON> sharedRoot(cJSON_Parse(commandIn.c_str()), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    string groupCommand(Utilities::getJsonString(root, GROUP_COMMAND, ""));

    if (groupCommand.empty()) {
        return GROUP_CMD_DATA_INCONSISTENT;
    }
    if (groupCommand.compare(INVITE) == 0) {
        groupCmdCallback_(commandIn);
    } else if (groupCommand.compare(INVITE_SYNC) == 0) {
        answerInvitation(commandIn, true, Empty);
    } else if (groupCommand.compare(INVITE_ANSWER) == 0) {
        groupCmdCallback_(commandIn);
        bool accepted = Utilities::getJsonBool(root, ACCEPTED, false);
        if (accepted) {
            invitationAccepted(root);
        }
    } else if (groupCommand.compare(MEMBER_LIST) == 0) {
        processMemberListAnswer(root);
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::sendGroupCommandAllDevices(const string &recipient, const string &msgId,
                                                     const string &command)
{
    LOGGER(INFO, __func__, " --> ", recipient, ", ", ownUser_);
    shared_ptr<list<string> > devices = store_->getLongDeviceIds(recipient, ownUser_);
    vector<int64_t> *sipMsgIds = sendMessageInternal(recipient, msgId, Empty, Empty, command, devices, GROUP_MSG_CMD);
    if (sipMsgIds == nullptr) {
        // If errorCode is 1: send to sibling devices and don't have a sibling
        LOGGER(ERROR, __func__, " <-- Error: ", errorCode_);
        return errorCode_;
    }
    delete sipMsgIds;
    devices = store_->getLongDeviceIds(recipient, ownUser_);
    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::sendGroupCommandToDevice(const string &recipient, const string &deviceId, const string &msgId,
                                                   const string &command) {

    LOGGER(INFO, __func__, " -->");
    shared_ptr<list<string> > device = make_shared<list<string> >();
    device->push_front(deviceId);
    vector<int64_t> *sipMsgIds = sendMessageInternal(recipient, msgId, Empty, Empty, command, device, GROUP_MSG_CMD);
    if (sipMsgIds == nullptr) {
        LOGGER(ERROR, __func__, " <-- Error: ", errorCode_);
        return errorCode_;
    }
    delete sipMsgIds;

    LOGGER(INFO, __func__, " <--");
    return OK;
}


int32_t AppInterfaceImpl::sendGroupCommandNewUserDevice(const string &recipient, const string &deviceId,
                                                        const string &msgId, const string &command) {

    LOGGER(INFO, __func__, " -->");
    shared_ptr<list<string> > device = make_shared<list<string> >();
    device->push_front(deviceId);
    vector<int64_t> *sipMsgIds = sendMessagePreKeys(recipient, msgId, Empty, Empty, command, device, GROUP_MSG_CMD);
    if (sipMsgIds == NULL) {
        LOGGER(ERROR, __func__, " <-- Error: ", errorCode_);
        return errorCode_;
    }
    delete sipMsgIds;

    LOGGER(INFO, __func__, " <--");
    return OK;
}


static void fillMemberArray(cJSON* root, shared_ptr<list<shared_ptr<cJSON> > > members)
{
    LOGGER(INFO, __func__, " --> ");
    cJSON* memberArray;
    cJSON_AddItemToObject(root, MEMBERS, memberArray = cJSON_CreateArray());

    // The member list is sorted by memberId
    string previousMemberId;
    for (auto it = members->begin(); it != members->end(); ++it) {
//        cJSON* memberObject = cJSON_CreateObject();
        string member(Utilities::getJsonString(it->get(), MEMBER_ID, ""));
        if (member == previousMemberId)
            continue;
        previousMemberId = member;
//        cJSON_AddStringToObject(memberObject, MEMBER_ID, member.c_str());
//        cJSON_AddStringToObject(memberObject, MEMBER_DEVICE_ID, Utilities::getJsonString(it->get(), MEMBER_DEVICE_ID, ""));
        cJSON_AddItemToArray(memberArray, cJSON_CreateString(member.c_str()));
    }
    LOGGER(INFO, __func__, " <-- ");
}

int32_t AppInterfaceImpl::invitationAccepted(const cJSON *root)
{
    LOGGER(INFO, __func__, " --> ");

    int32_t result;
    const string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    const string invitedMember(Utilities::getJsonString(root, MEMBER_ID, ""));
    const string invitedMemberDevice(Utilities::getJsonString(root, MEMBER_DEVICE_ID, ""));

    // Get all known members of the group before adding the invited member
    shared_ptr<list<shared_ptr<cJSON> > > members = store_->listAllGroupMembers(groupId, &result);

    shared_ptr<cJSON> sharedAnswer(cJSON_CreateObject(), cJSON_deleter);
    cJSON* answer = sharedAnswer.get();

    cJSON_AddStringToObject(answer, GROUP_COMMAND, MEMBER_LIST);
    cJSON_AddStringToObject(answer, GROUP_ID, groupId.c_str());
    cJSON_AddBoolToObject(answer, INITIAL_LIST, true);
    fillMemberArray(answer, members);

    char *out = cJSON_PrintUnformatted(answer);
    string listCommand(out);
    free(out);

    // Now insert the new group member in our database
    shared_ptr<cJSON> member = store_->listGroupMember(groupId, invitedMember, invitedMemberDevice);
    if (!member)
        store_->insertMember(groupId, invitedMember, invitedMemberDevice, ownUser_);

    sendGroupCommandAllDevices(invitedMember, generateMsgIdTime(), listCommand);

    LOGGER(INFO, __func__, " <-- ", listCommand);
    return OK;
}

int32_t AppInterfaceImpl::createMemberListAnswer(const cJSON *root) {
    LOGGER(INFO, __func__, " --> ");

    LOGGER(INFO, __func__, " <--");
    return OK;
}


int32_t AppInterfaceImpl::processMemberListAnswer(const cJSON* root) {
    LOGGER(INFO, __func__, " --> ");

    const string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    cJSON* memberArray = cJSON_GetObjectItem(const_cast<cJSON*>(root), MEMBERS);
    if (memberArray->type != cJSON_Array)
        return CORRUPT_DATA;

    bool initialList = Utilities::getJsonBool(root, INITIAL_LIST, false);

    shared_ptr<cJSON> sharedHello(cJSON_CreateObject(), cJSON_deleter);
    cJSON* hello = sharedHello.get();
    cJSON_AddStringToObject(hello, GROUP_COMMAND, HELLO);
    cJSON_AddStringToObject(hello, MEMBER_ID, ownUser_.c_str());

    char *out = cJSON_PrintUnformatted(hello);
    string helloCommand(out);
    free(out);

    int32_t result;
    int size = cJSON_GetArraySize(memberArray);
    for (int i = 0; i < size; i++) {
        cJSON* member = cJSON_GetArrayItem(memberArray, i);
        const string memberId(member->valuestring);
//        const string devId(Utilities::getJsonString(member, MEMBER_DEVICE_ID, ""));

        // Sending a command to a  member populates the ratchet data for all devices of
        // a user, thus even ratchet data of new users are available after the command.
        // Using the 'getLongDeviceIds' functions returns all device ids for this member
        // and we can store this in the member table.
        sendGroupCommandAllDevices(memberId, generateMsgIdTime(), initialList? helloCommand : ping);

        shared_ptr<list<string> > devIds = store_->getLongDeviceIds(memberId, ownUser_);

        while (!devIds->empty()) {
            const string devId = devIds->front();
            devIds->pop_front();

            shared_ptr<cJSON> hasMember = store_->listGroupMember(groupId, memberId, devId);
            if (!hasMember) {
                result = store_->insertMember(groupId, memberId, devId, ownUser_);
                if (SQL_FAIL(result)) {
                    LOGGER(ERROR, __func__, "Cannot store member: ", memberId, ":", devId, ", ", result);
                    return GROUP_MEMBER_NOT_STORED;
                }
            }
        }
    }

    LOGGER(INFO, __func__, " <--");
    return OK;
}


