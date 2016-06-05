//
// Implementation of group chat API
//
// Created by werner on 22.05.16.
//

#include "AppInterfaceImpl.h"

#include "../Constants.h"

#include "../logging/AxoLogging.h"
#include "GroupJsonStrings.h"

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
    for (auto it = tokens.begin(); it < tokens.end(); ++it) {
        if (token != *it)
            continue;
        tokens.erase(it);
        return true;
    }
    return false;
}


// ********* small static helpers, not worth as instance/class functions
static int32_t getJsonInt(cJSON* root, const char* tag, int32_t error)
{
    if (root == nullptr)
        return error;
    cJSON* jsonItem = cJSON_GetObjectItem(root, tag);
    if (jsonItem == NULL)
        return error;
    return jsonItem->valueint;
}

static const char* getJsonString(cJSON* root, const char* tag, const char* error)
{
    if (root == nullptr)
        return error;
    cJSON* jsonItem = cJSON_GetObjectItem(root, tag);
    if (jsonItem == NULL)
        return error;
    return jsonItem->valuestring;
}

static string inviteAnswerCmd(const cJSON* command, bool accepted, const string &reason)
{
    shared_ptr<cJSON> sharedRoot(cJSON_CreateObject(), cJSON_deleter);
    cJSON* root = sharedRoot.get();
    cJSON_AddStringToObject(root, GROUP_COMMAND, INVITE_ANSWER);
    cJSON_AddStringToObject(root, GROUP_ID, getJsonString(const_cast<cJSON*>(command), GROUP_ID, ""));
    cJSON_AddStringToObject(root, TOKEN, getJsonString(const_cast<cJSON*>(command), TOKEN, ""));
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
    string groupOwner(getJsonString(root, GROUP_OWNER, ""));

    if (ownUser_ != groupOwner) {
        errorInfo_ = " Only owner can modify group member size";
        LOGGER(ERROR, __func__, errorInfo_);
        return false;
    }
    int32_t members = getJsonInt(root, GROUP_MEMBER_COUNT, -1);
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
    int32_t members = getJsonInt(root, GROUP_MEMBER_COUNT, 1);
    int32_t maxMembers = getJsonInt(root, GROUP_MAX_MEMBERS, 0);

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
    return sendGroupCommand(userId, generateMsgIdTime(), inviteCommand);
}

int32_t AppInterfaceImpl::processReceivedGroupMsg(const MessageEnvelope& envelope, const string& msgDescriptor,
                                                  const string& attachmentDescr, const string& attributesDescr)
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
    cJSON* attributeRoot;

    if (commandIn.empty()) {
        return GROUP_CMD_MISSING_DATA;
    }
    // wrap the cJSON root into a shared pointer with custom cJSON deleter, this
    // will always free the cJSON root when we leave the function :-) .
    shared_ptr<cJSON> sharedRoot(cJSON_Parse(commandIn.c_str()), cJSON_deleter);
    string groupCommand(getJsonString(sharedRoot.get(), GROUP_COMMAND, ""));

    if (groupCommand.empty()) {
        return GROUP_CMD_DATA_INCONSISTENT;
    }
    if (groupCommand.compare(INVITE) == 0) {
        groupCmdCallback_(commandIn);
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}


int32_t AppInterfaceImpl::answerInvitation(const string &command, bool accept, const string &reason)
{
    LOGGER(INFO, __func__, " -->");

    if (command.empty()) {
        return GROUP_CMD_MISSING_DATA;
    }
    shared_ptr<cJSON> sharedRoot(cJSON_Parse(command.c_str()), cJSON_deleter);
    cJSON* root = sharedRoot.get();

    string invitingUser(getJsonString(root, MEMBER_ID, ""));
    if (!accept) {
        return sendGroupCommand(invitingUser, generateMsgIdTime(), inviteAnswerCmd(root, accept, reason));
    }

    // User accepted invitation, get necessary data and create group data in database
    string groupId(getJsonString(root, GROUP_ID, ""));
    string groupName(getJsonString(root, GROUP_NAME, ""));
    string description(getJsonString(root, GROUP_DESC, ""));
    string owner(getJsonString(root, GROUP_OWNER, ""));

    createInvitedGroup(groupId, groupName, description, owner);

    string messageId = generateMsgIdTime();

    // Prepare to and sync the sibling devices
    cJSON_ReplaceItemInObject(root, GROUP_COMMAND, cJSON_CreateString(INVITE_SYNC));
    sendGroupCommand(ownUser_, messageId, command);

    // Now send the accept message to the inviting user
    return sendGroupCommand(invitingUser, generateMsgIdTime(), inviteAnswerCmd(root, accept, reason));
}


// ****** Non public instance functions and helpers
// ******************************************************
int32_t AppInterfaceImpl::sendGroupCommand(const string &recipient, const string &msgId, const string &command)
{
    vector<int64_t> *sipMsgIds = sendMessageInternal(recipient, msgId, Empty, Empty, command, GROUP_MSG_CMD);
    if (sipMsgIds == nullptr) {
        return errorCode_;
    }
    delete (sipMsgIds);
    return OK;
}

