//
// Implementation of group chat API
//
// Created by werner on 22.05.16.
//

#include "AppInterfaceImpl.h"

#include "../Constants.h"

#include "../util/UUID.h"
#include "../logging/AxoLogging.h"
#include "GroupJsonStrings.h"

using namespace std;
using namespace axolotl;

static int32_t getJsonInt(cJSON* root, const char* tag, int32_t error)
{
    cJSON* jsonItem = cJSON_GetObjectItem(root, tag);
    if (jsonItem == NULL)
        return error;
    return jsonItem->valueint;
}

static const char* getJsonString(cJSON* root, const char* tag, const char* error)
{
    cJSON* jsonItem = cJSON_GetObjectItem(root, tag);
    if (jsonItem == NULL)
        return error;
    return jsonItem->valuestring;
}

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
    store->insertGroup(groupId, groupName, groupDescription, ownUser_, DEFAULT_GROUP_SIZE);
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
    int32_t result = store->insertGroup(groupId, groupName, groupDescription, owner, DEFAULT_GROUP_SIZE);
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
    cJSON_DeleteItemFromObject(root, GROUP_MAX_MEMBERS);

    uuid_t inviteToken = {0};
    uuid_string_t tokenString = {0};

    uuid_generate_random(inviteToken);          // TODO: store token
    uuid_unparse(inviteToken, tokenString);

    cJSON_AddStringToObject(root, INVITE_TOKEN, tokenString);
    cJSON_AddStringToObject(root, GROUP_COMMAND, INVITE);

    const string& msgId = generateMsgId();
    char *out = cJSON_PrintUnformatted(root);
    string inviteCommand(out);
    free(out);

    // Command send: has a message id, Empty message and attachment, invite command as attribute
    vector<int64_t>* sipMsgIds = sendMessageInternal(userId, msgId, Empty, Empty, inviteCommand, GROUP_MSG_CMD);
    if (sipMsgIds == nullptr) {
        return errorCode_;
    }
    delete(sipMsgIds);

    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::processReceivedGroupMsg(MessageEnvelope& envelope, string& msgDescriptor, string& attachmentDescr, string& attributesDescr)
{

}
