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

//
// Implementation of group chat
//
// Created by werner on 22.05.16.
//

#include "AppInterfaceImpl.h"

#include "JsonStrings.h"
#include "../util/Utilities.h"
#include "../util/b64helper.h"

using namespace std;
using namespace zina;


static vector<string> tokens;

static void storeRandomToken(const string &token)
{
    tokens.push_back(token);
}

// Check if a token exist, if yes remove it and return true.
static bool checkRandomToken(const string& token)
{
    for (auto it = tokens.begin(); it != tokens.end(); ++it) {
        if (token != *it)
            continue;
        tokens.erase(it);
        return true;
    }
    return false;
}

static string getRandomToken()
{
    uuid_t randomToken = {0};
    uuid_string_t tokenString = {0};

    uuid_generate_random(randomToken);
    uuid_unparse(randomToken, tokenString);
    return string(tokenString);
}

static string inviteAnswerCmd(const cJSON* command, const string &user, bool accepted, const string &reason)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, INVITE_ANSWER);
    cJSON_AddStringToObject(root, GROUP_ID, Utilities::getJsonString(command, GROUP_ID, ""));
    cJSON_AddStringToObject(root, MEMBER_ID, user.c_str());
    cJSON_AddStringToObject(root, TOKEN, Utilities::getJsonString(command, TOKEN, ""));
    cJSON_AddBoolToObject(root, ACCEPTED, accepted);

    if (!accepted && !reason.empty())
        cJSON_AddStringToObject(root, REASON, reason.c_str());

    char *out = cJSON_PrintUnformatted(root);
    string inviteCommand(out);
    free(out);
    return inviteCommand;
}

static void fillMemberArray(cJSON* root, shared_ptr<list<shared_ptr<cJSON> > > members)
{
    LOGGER(INFO, __func__, " --> ");
    cJSON* memberArray;
    cJSON_AddItemToObject(root, MEMBERS, memberArray = cJSON_CreateArray());

    // The member list is sorted by memberId
    for (auto it = members->begin(); it != members->end(); ++it) {
        cJSON_AddItemToArray(memberArray, cJSON_CreateString(Utilities::getJsonString(it->get(), MEMBER_ID, "")));
    }
    LOGGER(INFO, __func__, " <-- ");
}

static string prepareListAnswer(const string &groupId, const string &sender, const string& token,
                                           shared_ptr<list<shared_ptr<cJSON> > > members, bool initial)
{
    shared_ptr<cJSON> sharedAnswer(cJSON_CreateObject(), cJSON_deleter);
    cJSON* answer = sharedAnswer.get();

    cJSON_AddStringToObject(answer, GROUP_COMMAND, MEMBER_LIST);
    cJSON_AddStringToObject(answer, GROUP_ID, groupId.c_str());
    cJSON_AddStringToObject(answer, MEMBER_ID,  sender.c_str());
    cJSON_AddBoolToObject(answer, INITIAL_LIST, initial);
    if (initial)
        cJSON_AddStringToObject(answer, TOKEN, token.c_str());

    fillMemberArray(answer, members);

    char *out = cJSON_PrintUnformatted(answer);
    string listCommand(out);
    free(out);

    return listCommand;
}

static string leaveNotMemberCommand(const string& groupId, const string& memberId, bool leaveCommand)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, leaveCommand ? LEAVE : NOT_MEMBER);
    cJSON_AddStringToObject(root, MEMBER_ID, memberId.c_str());
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());

    char *out = cJSON_PrintUnformatted(root);
    string command(out);
    free(out);

    return command;
}

static string syncNewGroupCommand(const string& groupId, string& groupName, string& groupDescription, string& owner, int32_t maxMembers)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, NEW_GROUP_SYNC);
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    cJSON_AddStringToObject(root, GROUP_NAME, groupName.c_str());
    cJSON_AddStringToObject(root, GROUP_DESC, groupDescription.c_str());
    cJSON_AddStringToObject(root, GROUP_OWNER, owner.c_str());
    cJSON_AddNumberToObject(root, GROUP_MAX_MEMBERS, maxMembers);

    char *out = cJSON_PrintUnformatted(root);
    string command(out);
    free(out);

    return command;
}

// Request a list of known members from another client. The request contains the list of members known
// by the rquester
static string requestMemberList(const string& groupId, string& requester, shared_ptr<list<shared_ptr<cJSON> > > members)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();

    cJSON_AddStringToObject(root, GROUP_COMMAND, REQ_MEMBER_LIST);
    cJSON_AddStringToObject(root, MEMBER_ID, requester.c_str());
    string token = getRandomToken();
    storeRandomToken(token);
    cJSON_AddStringToObject(root, TOKEN, token.c_str());

    fillMemberArray(root, members);

    char *out = cJSON_PrintUnformatted(root);
    string result(out);
    free(out);

    return result;
}

static string listHashB64(const string& groupId, SQLiteStoreConv* store)
{
    // Compute the member list hash and add it to the message attribute
    uint8_t hash[32];
    store->memberListHash(groupId, hash);

    char b64Hash[64];
    b64Encode(hash, 32, b64Hash, 63);
    return string(b64Hash);

}

static int32_t deleteGroupAndMembers(string const& groupId, SQLiteStoreConv* store)
{
    LOGGER(INFO, __func__, " --> ");

    int32_t returnCode = OK;
    int32_t result = store->deleteAllMembers(groupId);
    if (SQL_FAIL(result)) {
        LOGGER(ERROR, __func__, "Could not delete all members of group: ", groupId, ", SQL code: ", result);
        // Try to deactivate group at least
        store->clearGroupAttribute(groupId, ACTIVE);
        store->setGroupAttribute(groupId, INACTIVE);
        returnCode = GROUP_ERROR_BASE + result;
    }
    if (returnCode == OK) {
        result = store->deleteGroup(groupId);
        if (SQL_FAIL(result)) {
            LOGGER(ERROR, __func__, "Could not delete group: ", groupId, ", SQL code: ", result);
            // Try to deactivate group at least
            store->clearGroupAttribute(groupId, ACTIVE);
            store->setGroupAttribute(groupId, INACTIVE);
            returnCode = GROUP_ERROR_BASE + result;
        }
    }
    return returnCode;
}

// ****** Public instance functions
// *******************************************************
string AppInterfaceImpl::createNewGroup(string& groupName, string& groupDescription, int32_t maxMembers) {
    LOGGER(INFO, __func__, " -->");

    if (maxMembers > MAXIMUM_GROUP_SIZE)
        return Empty;

    uuid_t groupUuid = {0};
    uuid_string_t uuidString = {0};

    uuid_generate_time(groupUuid);
    uuid_unparse(groupUuid, uuidString);
    string groupId(uuidString);

    store_->insertGroup(groupId, groupName, ownUser_, groupDescription, maxMembers);

    // Add myself to the new group, this saves us a "send to sibling" group function, then inform my sibling about
    // the new group
    store_->insertMember(groupId, ownUser_);
    sendGroupCommand(ownUser_, generateMsgIdTime(), syncNewGroupCommand(groupId, groupName, groupDescription, ownUser_, maxMembers));

    LOGGER(INFO, __func__, " <--");
    return groupId;
}

int32_t AppInterfaceImpl::createInvitedGroup(string& groupId, string& groupName, string& groupDescription, string& owner, int32_t maxMembers)
{
    LOGGER(INFO, __func__, " -->");
    int32_t result = store_->insertGroup(groupId, groupName,  owner, groupDescription, maxMembers);

    // Add myself to the new group, this saves us a "send to sibling" group function
    store_->insertMember(groupId, ownUser_);

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
    cJSON_DeleteItemFromObject(root, GROUP_MOD_TIME);

    string tokenString = getRandomToken();
    storeRandomToken(tokenString);

    cJSON_AddStringToObject(root, GROUP_COMMAND, INVITE);
    cJSON_AddStringToObject(root, TOKEN, tokenString.c_str());
    cJSON_AddStringToObject(root, MEMBER_ID, ownUser_.c_str());     // which member sends the Invite

    char *out = cJSON_PrintUnformatted(root);
    string inviteCommand(out);
    free(out);

    LOGGER(INFO, __func__, " <--");
    return sendGroupCommand(userId, generateMsgIdTime(), inviteCommand);
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
        return sendGroupCommand(invitingUser, generateMsgIdTime(),
                                inviteAnswerCmd(root, ownUser_, accept, reason));
    }

    // User accepted invitation, get necessary data and create group data in database
    string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    string groupName(Utilities::getJsonString(root, GROUP_NAME, ""));
    string description(Utilities::getJsonString(root, GROUP_DESC, ""));
    string owner(Utilities::getJsonString(root, GROUP_OWNER, ""));
    int32_t maxMember = Utilities::getJsonInt(root, GROUP_MAX_MEMBERS, 0);
    if (maxMember <= 0 || maxMember > MAXIMUM_GROUP_SIZE)
        return MAX_MEMBERS_REACHED;

    createInvitedGroup(groupId, groupName, description, owner, maxMember);

    // If this is a invite-sync command then just return, all necessary actions done.
    string grpCmd(Utilities::getJsonString(root, GROUP_COMMAND, ""));
    if (grpCmd.compare(INVITE_SYNC) == 0) {
        return OK;
    }
    string messageId = generateMsgIdTime();

    // Prepare invite-sync and sync the sibling devices
    cJSON_ReplaceItemInObject(root, GROUP_COMMAND, cJSON_CreateString(INVITE_SYNC));
    sendGroupCommand(ownUser_, messageId, command);

    // Now send the accept message to the inviting user
    return sendGroupCommand(invitingUser, messageId,
                            inviteAnswerCmd(root, ownUser_, accept, reason));
}

int32_t AppInterfaceImpl::sendGroupMessage(const string &messageDescriptor, const string &attachmentDescriptor,
                                           const string &messageAttributes) {
    string groupId;
    string msgId;
    string message;

    LOGGER(INFO, __func__, " -->");
    int32_t parseResult = parseMsgDescriptor(messageDescriptor, &groupId, &msgId, &message);
    if (parseResult < 0) {
        errorCode_ = parseResult;
        LOGGER(ERROR, __func__, " Wrong JSON data to send group message, error code: ", parseResult);
        return parseResult;
    }
    if (!store_->hasGroup(groupId) || ((store_->getGroupAttribute(groupId).first & ACTIVE) != ACTIVE)) {
        return NO_SUCH_ACTIVE_GROUP;
    }

    string b64Hash = listHashB64(groupId, store_);
    cJSON* root = !messageAttributes.empty() ? cJSON_Parse(messageAttributes.c_str()) : cJSON_CreateObject();
    shared_ptr<cJSON> sharedRoot(root, cJSON_deleter);

    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    cJSON_AddStringToObject(root, LIST_HASH, b64Hash.c_str());

    char *out = cJSON_PrintUnformatted(root);
    string newAttributes(out);
    free(out);

    int32_t result;
    shared_ptr<list<shared_ptr<cJSON> > > members = store_->getAllGroupMembers(groupId, &result);
    size_t membersFound = members->size();
    while (!members->empty()) {
        string recipient(Utilities::getJsonString(members->front().get(), MEMBER_ID, ""));
        members->pop_front();
        bool toSibling = recipient == ownUser_;
        auto preparedMsgData = prepareMessageInternal(messageDescriptor, attachmentDescriptor, newAttributes, toSibling, GROUP_MSG_NORMAL, &result, recipient);
        if (result != SUCCESS) {
            LOGGER(ERROR, __func__, " <-- Error: ", result);
            return result;
        }
        doSendMessages(extractTransportIds(preparedMsgData.get()));
    }
    LOGGER(INFO, __func__, " <--, ", membersFound);
    return OK;
}

int32_t AppInterfaceImpl::leaveGroup(const string& groupId) {
    LOGGER(INFO, __func__, " -->");

    int32_t result;
    string msgId = generateMsgIdTime();
    string leaveCommand = leaveNotMemberCommand(groupId, ownUser_, true);

    // Get the member list and send out the Leave command before deleting the data
    shared_ptr<list<shared_ptr<cJSON> > > members = store_->getAllGroupMembers(groupId, &result);
    for (auto it = members->begin(); it != members->end(); ++it) {
        string recipient(Utilities::getJsonString(it->get(), MEMBER_ID, ""));

        if (sendGroupCommand(recipient, msgId, leaveCommand) != OK) {
            LOGGER(ERROR, __func__, " <-- Error: ", errorCode_);
            return errorCode_;
        }
    }
    LOGGER(INFO, __func__, " <-- ");

    return deleteGroupAndMembers(groupId, store_);
}

int32_t AppInterfaceImpl::groupMessageRemoved(const string& groupId, const string& messageId)
{
    if (groupId.empty() || messageId.empty()) {
        return DATA_MISSING;
    }
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();

    cJSON_AddStringToObject(root, GROUP_COMMAND, REMOVE_MSG);
    cJSON_AddStringToObject(root, GROUP_ID, groupId.c_str());
    cJSON_AddStringToObject(root, MSG_ID, messageId.c_str());

    char *out = cJSON_PrintUnformatted(root);
    string command(out);
    free(out);

    sendGroupCommand(ownUser_, generateMsgIdTime(), command);
    return OK;
}

// ****** Non public instance functions and helpers
// ******************************************************

int32_t AppInterfaceImpl::processGroupMessage(int32_t msgType, const string &msgDescriptor,
                                              const string &attachmentDescr, const string &attributesDescr)
{
    LOGGER(INFO, __func__, " -->");

    if (msgType == GROUP_MSG_CMD) {
        return processGroupCommand(attributesDescr);
    }
    if (msgType == GROUP_MSG_NORMAL && msgDescriptor.empty()) {
        return GROUP_MSG_DATA_INCONSISTENT;
    }
    if (checkActiveAndHash(msgDescriptor, attributesDescr)) {
        groupMsgCallback_(msgDescriptor, attachmentDescr, attributesDescr);
    }
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
    string groupId(Utilities::getJsonString(root, GROUP_ID, ""));

    if (groupCommand.empty()) {
        return GROUP_CMD_DATA_INCONSISTENT;
    }
    if (groupCommand.compare(INVITE) == 0) {
        if (store_->hasGroup(groupId) && ((store_->getGroupAttribute(groupId).first & ACTIVE) == ACTIVE)) {
            LOGGER(INFO, __func__, " <-- Group exists: ", groupId);
            return OK;
        }
        groupCmdCallback_(commandIn);
    } else if (groupCommand.compare(NEW_GROUP_SYNC) == 0) {
        syncNewGroup(root);
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
        groupCmdCallback_(commandIn);
    } else if (groupCommand.compare(REQ_MEMBER_LIST) == 0) {
        createMemberListAnswer(root);
    } else if (groupCommand.compare(LEAVE) == 0 || groupCommand.compare(NOT_MEMBER) == 0) {
        processLeaveGroupCommand(root);
        groupCmdCallback_(commandIn);
    } else if (groupCommand.compare(HELLO) == 0) {
        groupCmdCallback_(commandIn);
        processHelloCommand(root);
    } else if (groupCommand.compare(REMOVE_MSG) == 0) {
        groupCmdCallback_(commandIn);
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::sendGroupCommand(const string &recipient, const string &msgId, const string &command) {
    LOGGER(INFO, __func__, " --> ", recipient, ", ", ownUser_);

    bool toSibling = recipient == ownUser_;
    int32_t result;
    auto preparedMsgData = prepareMessageInternal(createMessageDescriptor(recipient, msgId), Empty, command, toSibling, GROUP_MSG_CMD, &result, recipient);
    if (result != SUCCESS) {
        LOGGER(ERROR, __func__, " <-- Error: ", result);
        return result;
    }
    doSendMessages(extractTransportIds(preparedMsgData.get()));

    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::invitationAccepted(const cJSON *root)
{
    LOGGER(INFO, __func__, " --> ");

    int32_t result;
    const string token(Utilities::getJsonString(root, TOKEN, ""));

    if (!checkRandomToken(token)) {
        LOGGER(INFO, __func__, " <-- No token");
        return OK;
    }
    const string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    const string invitedMember(Utilities::getJsonString(root, MEMBER_ID, ""));

    // Get all known members of the group before adding the invited member
    shared_ptr<list<shared_ptr<cJSON> > > members = store_->getAllGroupMembers(groupId, &result);

    const string listCommand = prepareListAnswer(groupId, ownUser_, Empty, members, true);

    // Now insert the new group member in our database
    if (!store_->isMemberOfGroup(groupId, invitedMember))
        store_->insertMember(groupId, invitedMember);

    sendGroupCommand(invitedMember, generateMsgIdTime(), listCommand);

    LOGGER(INFO, __func__, " <-- ", listCommand);
    return OK;
}

int32_t AppInterfaceImpl::createMemberListAnswer(const cJSON *root) {
    LOGGER(INFO, __func__, " --> ");

    const string token(Utilities::getJsonString(root, TOKEN, ""));
    const string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    const string requester(Utilities::getJsonString(root, MEMBER_ID, ""));

    if (!isGroupActive(groupId, requester)) {
        LOGGER(INFO, __func__, "<-- no active group: ", groupId);
        return OK;
    }
    // The member list request also contains the requester's member list, parse it
    // and update our own database
    parseMemberList(root, false, groupId);

    int32_t result;
    shared_ptr<list<shared_ptr<cJSON> > > members = store_->getAllGroupMembers(groupId, &result);

    const string listCommand = prepareListAnswer(groupId, ownUser_, token, members, false);

    sendGroupCommand(requester, generateMsgIdTime(), listCommand);

    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::processMemberListAnswer(const cJSON* root) {
    LOGGER(INFO, __func__, " --> ");

    const string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    const string sender(Utilities::getJsonString(root, MEMBER_ID, ""));

    // Is it an initial list as the last step of the Invite flow?
    bool initialList = Utilities::getJsonBool(root, INITIAL_LIST, false);

    // If not an initial list then check the request token to avoid multiple
    // answer processing
    if (!initialList) {
        string token(Utilities::getJsonString(root, TOKEN, ""));

        bool groupActive = isGroupActive(groupId, sender);

        // If token was already consumed just return, got the list already from
        // the member's other device. Also ignore if we don't know the group or
        // if it's not active anymore
        if (!checkRandomToken(token) || !groupActive)
            return OK;
    }

    return parseMemberList(root, initialList, groupId);
}

bool AppInterfaceImpl::checkActiveAndHash(const string &msgDescriptor, const string &messageAttributes)
{
    LOGGER(INFO, __func__, " -->");

    // Get the member list hash computed by sender of message
    shared_ptr<cJSON> sharedRoot(cJSON_Parse(messageAttributes.c_str()), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    string remoteHash(Utilities::getJsonString(root, LIST_HASH, ""));
    string groupId(Utilities::getJsonString(root, GROUP_ID, ""));

    // Get the group id (the recipient) and the message sender
    sharedRoot = shared_ptr<cJSON>(cJSON_Parse(msgDescriptor.c_str()), cJSON_deleter);
    root = sharedRoot.get();
    string sender(Utilities::getJsonString(root, MSG_SENDER, ""));

    if (!isGroupActive(groupId, sender)) {
        LOGGER(INFO, __func__, " <-- no active group: ", groupId);
        return false;
    }
    string ownHash = listHashB64(groupId, store_);

    if (remoteHash != ownHash) {
        int32_t result;
        // Get all known members of the group
        shared_ptr<list<shared_ptr<cJSON> > > members = store_->getAllGroupMembers(groupId, &result);
        sendGroupCommand(sender, generateMsgIdTime(), requestMemberList(groupId, ownUser_, members));
    }
    LOGGER(INFO, __func__, " <-- ");
    return true;
}

bool AppInterfaceImpl::isGroupActive(const string& groupId, const string& sender)
{
    LOGGER(INFO, __func__, " -->");

    if (store_->hasGroup(groupId) && ((store_->getGroupAttribute(groupId).first & ACTIVE) == ACTIVE)) {
        return true;
    }
    string msgId = generateMsgIdTime();
    string command = leaveNotMemberCommand(groupId, ownUser_, false);

    sendGroupCommand(ownUser_, msgId, command);      // synchronize siblings
    sendGroupCommand(sender, msgId, command);
    return false;
}

int32_t AppInterfaceImpl::processLeaveGroupCommand(const cJSON* root) {

    LOGGER(INFO, __func__, " --> ");

    const string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    const string memberId(Utilities::getJsonString(root, MEMBER_ID, ""));

    // The leave/not user command from a sibling, thus remove group completely
    if (ownUser_ == MEMBER_ID) {
        return deleteGroupAndMembers(groupId, store_);
    }
    int32_t result = store_->deleteMember(groupId, memberId);
    int32_t returnCode = OK;
    if (SQL_FAIL(result)) {
        LOGGER(ERROR, __func__, "Could not delete member from group: ", groupId, " (", memberId, "), SQL code: ", result);
        // Try to deactivate the member at least
        store_->clearMemberAttribute(groupId, memberId, ACTIVE);
        store_->setMemberAttribute(groupId, memberId, INACTIVE);
        returnCode = GROUP_ERROR_BASE + result;
    }
    return returnCode;
}

int32_t AppInterfaceImpl::syncNewGroup(const cJSON *root) {
    LOGGER(INFO, __func__, " --> ");

    // User accepted invitation, get necessary data and create group data in database
    string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    string groupName(Utilities::getJsonString(root, GROUP_NAME, ""));
    string description(Utilities::getJsonString(root, GROUP_DESC, ""));
    string owner(Utilities::getJsonString(root, GROUP_OWNER, ""));
    int32_t maxMember = Utilities::getJsonInt(root, GROUP_MAX_MEMBERS, 0);
    if (maxMember <= 0 || maxMember > MAXIMUM_GROUP_SIZE)
        return MAX_MEMBERS_REACHED;

    if (owner != ownUser_) {
        return GROUP_CMD_DATA_INCONSISTENT;
    }
    int32_t result = store_->insertGroup(groupId, groupName,  owner, description, maxMember);
    store_->insertMember(groupId, ownUser_);

    return OK;
}


void AppInterfaceImpl::clearGroupData()
{
    LOGGER(INFO, __func__, " --> ");
    shared_ptr<list<shared_ptr<cJSON> > > groups = store_->listAllGroups();

    for (; groups && !groups->empty(); groups->pop_front()) {
        shared_ptr<cJSON>& group = groups->front();
        string groupId(Utilities::getJsonString(group.get(), GROUP_ID, ""));
        store_->deleteAllMembers(groupId);
        store_->deleteGroup(groupId);
    }
}


int32_t AppInterfaceImpl::processHelloCommand(const cJSON *root) {
    LOGGER(INFO, __func__, " --> ");

    const string groupId(Utilities::getJsonString(root, GROUP_ID, ""));
    const string memberId(Utilities::getJsonString(root, MEMBER_ID, ""));

    if (!store_->isMemberOfGroup(groupId, memberId)) {
        int32_t result = store_->insertMember(groupId, memberId);
        if (SQL_FAIL(result)) {
            LOGGER(ERROR, __func__, "Cannot store member: ", memberId, ", ", result);
            return GROUP_MEMBER_NOT_STORED;
        }
    }
    return OK;
}

int32_t AppInterfaceImpl::parseMemberList(const cJSON* root, bool initialList, const string& groupId) {
    cJSON* memberArray = cJSON_GetObjectItem(const_cast<cJSON*>(root), MEMBERS);
    if (memberArray == nullptr || memberArray->type != cJSON_Array)
        return CORRUPT_DATA;


    shared_ptr<cJSON> sharedHello(cJSON_CreateObject(), cJSON_deleter);
    cJSON* hello = sharedHello.get();
    cJSON_AddStringToObject(hello, GROUP_COMMAND, HELLO);
    cJSON_AddStringToObject(hello, GROUP_ID, groupId.c_str());
    cJSON_AddStringToObject(hello, MEMBER_ID, ownUser_.c_str());

    char *out = cJSON_PrintUnformatted(hello);
    string helloCommand(out);
    free(out);

    int32_t result;
    int size = cJSON_GetArraySize(memberArray);
    for (int i = 0; i < size; i++) {
        cJSON* member = cJSON_GetArrayItem(memberArray, i);
        const string memberId(member->valuestring);

        if (!store_->isMemberOfGroup(groupId, memberId)) {
            result = store_->insertMember(groupId, memberId);
            if (SQL_FAIL(result)) {
                LOGGER(ERROR, __func__, "Cannot store member: ", memberId, ", ", result);
                return GROUP_MEMBER_NOT_STORED;
            }
            // Sending a command to a member creates the ratchet data for all devices of
            // a user if necessary.
            sendGroupCommand(memberId, generateMsgIdTime(), initialList ? helloCommand : ping);
        }
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}

