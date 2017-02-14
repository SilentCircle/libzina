/*
Copyright 2017 Silent Circle, LLC

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
// Created by werner on 30.01.17.
//

#include <cryptcommon/ZrtpRandom.h>
#include "AppInterfaceImpl.h"

#include "GroupProtocol.pb.h"
#include "../util/b64helper.h"
#include "../vectorclock/VectorHelper.h"
#include "JsonStrings.h"
#include "../util/Utilities.h"

using namespace std;
using namespace zina;
using namespace vectorclock;

typedef shared_ptr<GroupChangeSet> PtrChangeSet;

static mutex currentChangeSetLock;
static map<string, PtrChangeSet> currentChangeSets;

// The key in this map is: updateId || groupId  (|| means concatenate)
// This map stores change sets (one per group) which are waiting for ACKs
static map<string, PtrChangeSet> pendingChangeSets;

// Update-id is just some random data, guarded by "update in progress" flag
static uint8_t updateId[UPDATE_ID_LENGTH];
static bool updateInProgress = false;

static bool addNewGroupToChangeSet(const string &groupId)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    auto changeSet = make_shared<GroupChangeSet>();

    return currentChangeSets.insert(pair<string, PtrChangeSet >(groupId, changeSet)).second;
}

#ifdef UNITTESTS
PtrChangeSet getPendingGroupChangeSet(const string &groupId);
#else
static
#endif
PtrChangeSet getPendingGroupChangeSet(const string &groupId)
{
    auto end = pendingChangeSets.end();
    for (auto it = pendingChangeSets.begin(); it != end; ++it) {
        string oldGroupId = it->first.substr(UPDATE_ID_LENGTH);
        if (oldGroupId == groupId) {
            return it->second;
        }
    }
    return PtrChangeSet();
}

static void removeGroupFromChangeSet(const string &groupId)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    currentChangeSets.erase(groupId);
}

// Returns pointer to a group's change set class
//
// Return an empty if the group is not valid.
// Function assumes the lock is set
// make it visible for unittests
#ifdef UNITTESTS
PtrChangeSet getCurrentGroupChangeSet(const string &groupId, SQLiteStoreConv &store);
#else
static
#endif
PtrChangeSet getCurrentGroupChangeSet(const string &groupId, SQLiteStoreConv &store)
{
    auto it = currentChangeSets.find(groupId);
    if (it != currentChangeSets.end()) {
        return it->second;
    }
    // no group change set yet. Check if we really have the group
    if (!store.hasGroup(groupId) || ((store.getGroupAttribute(groupId).first & ACTIVE) != ACTIVE)) {
        return PtrChangeSet();
    }

    // Yes, we have this group, create a change set, insert into map, return the pointer
    auto changeSet = make_shared<GroupChangeSet>();
    if (!currentChangeSets.insert(pair<string, PtrChangeSet >(groupId, changeSet)).second) {
        return PtrChangeSet();
    }
    return changeSet;
}

// Get the current change set for the group, return an empty Ptr in no active set available
static PtrChangeSet getGroupChangeSet(const string &groupId)
{
    auto it = currentChangeSets.find(groupId);
    if (it != currentChangeSets.end()) {
        return it->second;
    }
    return PtrChangeSet();
}

// Sets name only. We add the vector clock later, just before sending out the change
// Overwrites an existing name update
static bool setGroupNameToChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    // get mutable pointer
    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    // Proto buffer implementation takes ownership of pointer, also releases an already set update message
    changeSet->mutable_updatename()->set_name(name);

    return true;
}

static bool removeGroupNameFromChangeSet(const string &groupId, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    // get mutable pointer
    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    GroupUpdateSetName *oldName = changeSet->release_updatename();
    delete oldName;

    return true;
}

// Sets avatar info only. We add the vector clock later, just before sending out the change
// Overwrite an existing avatar update
static bool setGroupAvatarToChangeSet(const string &groupId, const string &avatar, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    // Proto buffer implementation takes ownership of pointer, also releases an already set update message
    changeSet->mutable_updateavatar()->set_avatar(avatar);

    return true;
}

static bool removeGroupAvatarFromChangeSet(const string &groupId, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    GroupUpdateSetAvatar *oldAvatar = changeSet->release_updateavatar();
    delete oldAvatar;

    return true;
}

// Sets burn info only. We add the vector clock later, just before sending out the change
// Overwrite an existing avatar update
static bool setGroupBurnToChangeSet(const string &groupId, uint64_t burn, GroupUpdateSetBurn_BurnMode mode, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    // Proto buffer implementation takes ownership of pointer, also releases an already set update message
    changeSet->mutable_updateburn()->set_burn_mode(mode);
    changeSet->mutable_updateburn()->set_burn_ttl_sec(burn);

    return true;
}

// This function removes an remove member from the group update
// Function assumes the change set is locked
static bool removeRmNameFromChangeSet(PtrChangeSet changeSet, const string &name)
{
    if (!changeSet->has_updatermmember()) {
        return true;
    }
    GroupUpdateRmMember *updateRmMember = changeSet->mutable_updatermmember();
    int32_t numberNames = updateRmMember->rmmember_size();

    // Search for a name and remove it. Because repeated fields do not provide
    // a direct Remove(index) we first swap the found element with the last element
    // and then remove the last element.
    for (int32_t i = 0; i < numberNames; ++i) {
        if (name == updateRmMember->rmmember(i).user_id()) {
            updateRmMember->mutable_rmmember()->SwapElements(i, numberNames-1);
            updateRmMember->mutable_rmmember()->RemoveLast();
            break;
        }
    }
    return true;
}
static bool removeRmNameFromChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    return removeRmNameFromChangeSet(changeSet, name);
}

// Function checks for duplicates and ignores them, otherwise adds the name to the group update
// assumes the change set is locked
static bool addAddNameToChangeSet(PtrChangeSet changeSet, const string &name)
{

    GroupUpdateAddMember *updateAddMember = changeSet->mutable_updateaddmember();
    int32_t numberNames = updateAddMember->addmember_size();

    // Check and silently ignore duplicate names
    for (int i = 0; i < numberNames; i++) {
        if (name == updateAddMember->addmember(i).user_id()) {
            return true;
        }
    }
    Member *member = updateAddMember->add_addmember();
    member->set_user_id(name);
    return true;

}

// Thus function adds an add member to the change set, collapsed into a repeated GROUP_ADD_MEMBER update
// message. The function silently ignores duplicate names.
// adding a new member to the change set checks the remove update and removes an entry with the
// same name if found
static bool addAddNameToChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    // In case we added this name to the current change set, remove it, don't need to remove
    // it. However, add it the the change set to add names.
    removeRmNameFromChangeSet(changeSet, name);
    return addAddNameToChangeSet(changeSet, name);
}

// Thus function removes an add member from the change set
// Function assumes the change set is locked
static bool removeAddNameFromChangeSet(PtrChangeSet changeSet, const string &name)
{
    // If update has no add member yet, cannot remove anything return false, done
    if (!changeSet->has_updateaddmember()) {
        return true;
    }
    GroupUpdateAddMember *updateAddMember = changeSet->mutable_updateaddmember();
    int32_t numberNames = updateAddMember->addmember_size();

    // Search for a name and remove it. Because repeated fields do not provide
    // a direct Remove(index) we first swap the found element with the last element
    // and then remove the last element.
    for (int32_t i = 0; i < numberNames; ++i) {
        if (name == updateAddMember->addmember(i).user_id()) {
            updateAddMember->mutable_addmember()->SwapElements(i, numberNames-1);
            updateAddMember->mutable_addmember()->RemoveLast();
            break;
        }
    }
    return true;
}

static bool removeAddNameFromChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    // In case we added this name to the current changes set, remove it, don't need to add
    // it. However, add it the the change set to remove names.
    return removeAddNameFromChangeSet(changeSet, name);
}

// Function checks for duplicates and ignores them, otherwise adds the name to the group update
// assumes the change set is locked
static bool addRemoveNameToChangeSet(PtrChangeSet changeSet, const string &name)
{
    GroupUpdateRmMember *updateRmMember = changeSet->mutable_updatermmember();
    int32_t numberNames = updateRmMember->rmmember_size();
    // Check and silently ignore duplicate names
    for (int i = 0; i < numberNames; i++) {
        if (name == updateRmMember->rmmember(i).user_id()) {
            return true;
        }
    }
    Member *member = updateRmMember->add_rmmember();
    member->set_user_id(name);
    return true;
}

// This function adds a remove member, collapsed into a repeated GROUP_REMOVE_MEMBER update message
// The function silently ignores duplicate names.
// adding a new member to the change set checks the add update and removes an entry with the
// same name if found
static bool addRemoveNameToChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    auto changeSet = getCurrentGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    removeAddNameFromChangeSet(changeSet, name);
    return addRemoveNameToChangeSet(changeSet, name);
}

static int32_t prepareChangeSet(const string &groupId, const string &binDeviceId, PtrChangeSet changeSet, GroupUpdateType type, const uint8_t *updateId, SQLiteStoreConv &store)
{
    LocalVClock lvc;
    VectorClock<string> vc;

    int32_t result = readLocalVectorClock(store, groupId, type, &lvc);
    if (result == SUCCESS) {        // we may not yet have a vector clock for this group update type, thus deserialize on SUCCESS only
        deserializeVectorClock(lvc.vclock(), &vc);
    }

    // In a first step read the local vector clock for this (group id, update type) tuple
    // increment the clock for our device.
    //
    // In the second step set this new clock to the appropriate update change set.
    vc.incrementNodeClock(binDeviceId);

    switch (type) {
        case GROUP_SET_NAME:
            changeSet->mutable_updatename()->set_update_id(updateId, UPDATE_ID_LENGTH);
            serializeVectorClock(vc, changeSet->mutable_updatename()->mutable_vclock());
            break;

        case GROUP_SET_AVATAR:
            changeSet->mutable_updateavatar()->set_update_id(updateId, UPDATE_ID_LENGTH);
            serializeVectorClock(vc, changeSet->mutable_updateavatar()->mutable_vclock());
            break;

        case GROUP_SET_BURN:
            changeSet->mutable_updateburn()->set_update_id(updateId, UPDATE_ID_LENGTH);
            serializeVectorClock(vc, changeSet->mutable_updateburn()->mutable_vclock());
            break;

        default:
            return ILLEGAL_ARGUMENT;

    }
    // Now update and persist the local vector clock
    lvc.set_update_id(updateId, UPDATE_ID_LENGTH);
    serializeVectorClock(vc, lvc.mutable_vclock());
    return storeLocalVectorClock(store, groupId, type, lvc);
}

static int32_t serializeChangeSet(PtrChangeSet changeSet, const string &groupId, cJSON *root, string *newAttributes)
{
    string serialized;
    if (!changeSet->SerializeToString(&serialized)) {
        return GENERIC_ERROR;
    }
    size_t b64Size = static_cast<size_t>(serialized.size() * 2);
    unique_ptr<char[]> b64Buffer(new char[b64Size]);
    if (b64Encode(reinterpret_cast<const uint8_t *>(serialized.data()), serialized.size(), b64Buffer.get(), b64Size) == 0) {
        return GENERIC_ERROR;
    }
    string serializedSet;
    serializedSet.assign(b64Buffer.get());

    if (!serializedSet.empty()) {
        cJSON_AddStringToObject(root, GROUP_CHANGE_SET, serializedSet.c_str());
    }
    CharUnique out(cJSON_PrintUnformatted(root));
    newAttributes->assign(out.get());
    return SUCCESS;
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

    addNewGroupToChangeSet(groupId);
    addAddNameToChangeSet(groupId, getOwnUser(), *store_);
    if (!groupName.empty()) {
        setGroupNameToChangeSet(groupId, groupName, *store_);
    }
    LOGGER(INFO, __func__, " <--");
    return groupId;
}

int32_t AppInterfaceImpl::addUser(const string& groupUuid, const string& userId)
{
    LOGGER(INFO, __func__, " -->");

    if (groupUuid.empty() || userId.empty()) {
        return DATA_MISSING;
    }
    if (userId == getOwnUser()) {
        return ILLEGAL_ARGUMENT;
    }
    if (!addAddNameToChangeSet(groupUuid, userId, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::removeUserFromAddUpdate(const string& groupUuid, const string& userId)
{
    LOGGER(INFO, __func__, " -->");

    if (groupUuid.empty() || userId.empty()) {
        return DATA_MISSING;
    }

    unique_lock<mutex> lck(currentChangeSetLock);
    if (!removeAddNameFromChangeSet(groupUuid, userId, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::leaveGroup(const string& groupId) {
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }
    removeGroupFromChangeSet(groupId);          // when leaving group - no other changes allowed
    if (!addRemoveNameToChangeSet(groupId, getOwnUser(), *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    applyGroupChangeSet(groupId);

    processLeaveGroup(groupId, getOwnUser(), true);

    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::processLeaveGroup(const string &groupId, const string &userId, bool fromSibling) {

    LOGGER(INFO, __func__, " --> ");

    // The leave/not user command from a sibling, thus remove group completely
    if (fromSibling) {
        // No wait-for-ack, ignore any ACKs from members of the group, we are gone
        store_->removeWaitAckWithGroup(groupId);

        // Remove group's pending change set
        auto end = pendingChangeSets.end();
        for (auto it = pendingChangeSets.begin(); it != end; ++it) {
            string oldGroupId = it->first.substr(UPDATE_ID_LENGTH);
            if (oldGroupId != groupId) {
                continue;
            }
            pendingChangeSets.erase(it);
        }
        return deleteGroupAndMembers(groupId);
    }
    int32_t result = store_->deleteMember(groupId, userId);
    if (SQL_FAIL(result)) {
        LOGGER(ERROR, __func__, "Could not delete member from group: ", groupId, " (", userId, "), SQL code: ", result);
        // Try to deactivate the member at least
        store_->clearMemberAttribute(groupId, userId, ACTIVE);
        store_->setMemberAttribute(groupId, userId, INACTIVE);
        return GROUP_ERROR_BASE + result;
    }
    return SUCCESS;
}

int32_t AppInterfaceImpl::removeUser(const string& groupId, const string& userId, bool allowOwnUser)
{
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty() || userId.empty()) {
        return DATA_MISSING;
    }

    if (!allowOwnUser && userId == getOwnUser()) {
        return ILLEGAL_ARGUMENT;
    }
    if (!addRemoveNameToChangeSet(groupId, userId, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::removeUserFromRemoveUpdate(const string& groupUuid, const string& userId)
{
    LOGGER(INFO, __func__, " -->");

    if (groupUuid.empty() || userId.empty()) {
        return DATA_MISSING;
    }

    unique_lock<mutex> lck(currentChangeSetLock);
    if (!removeRmNameFromChangeSet(groupUuid, userId, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;

}

int32_t AppInterfaceImpl::setGroupName(const string& groupId, const string* groupName)
{
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }

    if (groupName == nullptr) {
        if (!removeGroupNameFromChangeSet(groupId, *store_)) {
            return NO_SUCH_ACTIVE_GROUP;
        }
    }
    else if (!setGroupNameToChangeSet(groupId, *groupName, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::setGroupBurnTime(const string& groupId, uint64_t burnTime, int32_t mode)
{
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }

    if (mode == 0 || !GroupUpdateSetBurn_BurnMode_IsValid(mode)) {
        return ILLEGAL_ARGUMENT;
    }
    if (!setGroupBurnToChangeSet(groupId, burnTime, (GroupUpdateSetBurn_BurnMode) mode, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::setGroupAvatar(const string& groupId, const string* avatar)
{
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }

    if (avatar == nullptr) {
        if (!removeGroupAvatarFromChangeSet(groupId, *store_)) {
            return NO_SUCH_ACTIVE_GROUP;
        }
    }
    else if (!setGroupAvatarToChangeSet(groupId, *avatar, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::cancelGroupChangeSet(const string& groupId)
{
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }
    removeGroupFromChangeSet(groupId);
    LOGGER(INFO, __func__, " <--");
    return SUCCESS;
}

int32_t AppInterfaceImpl::applyGroupChangeSet(const string& groupId)
{
    string msgId = generateMsgIdTime();
    int32_t result = sendGroupMessage(createMessageDescriptor(groupId, msgId), Empty, Empty);
    return result == OK ? SUCCESS : result;
}

static void addMissingMetaData(PtrChangeSet changeSet, shared_ptr<cJSON> group)
{
    if (!changeSet->has_updatename()) {
        string name = Utilities::getJsonString(group.get(), GROUP_NAME, "");
        changeSet->mutable_updatename()->set_name(name);
    }

    if (!changeSet->has_updateavatar()) {
        string avatar = Utilities::getJsonString(group.get(), GROUP_AVATAR, "");
        changeSet->mutable_updateavatar()->set_avatar(avatar);
    }
    if (!changeSet->has_updateburn()) {
        uint64_t sec = Utilities::getJsonInt(group.get(), GROUP_BURN_SEC, 0);
        int32_t mode = Utilities::getJsonInt(group.get(), GROUP_BURN_MODE, 0);
        changeSet->mutable_updateburn()->set_burn_ttl_sec(sec);
        changeSet->mutable_updateburn()->set_burn_mode((GroupUpdateSetBurn_BurnMode)mode);
    }
}

int32_t AppInterfaceImpl::prepareChangeSetSend(const string &groupId) {
    if (groupId.empty()) {
        return DATA_MISSING;
    }
    errorCode_ = SUCCESS;
    unique_lock<mutex> lck(currentChangeSetLock);

    // Get an active change set, if none then nothing to do, return success
    auto changeSet = getGroupChangeSet(groupId);
    if (!changeSet) {
        return SUCCESS;
    }

    // Still creating and sending a previous change set, don't mix data
    if (updateInProgress) {
        return GROUP_UPDATE_RUNNING;
    }
    updateInProgress = true;
    ZrtpRandom::getRandomData(updateId, sizeof(updateId));

    int32_t returnCode;

    // Check if this change set is for a new group
    if (!store_->hasGroup(groupId)) {
        returnCode = insertNewGroup(groupId, *changeSet, nullptr);
        if (returnCode < 0) {
            errorCode_ = returnCode;
            return returnCode;
        }
    }
    string binDeviceId;
    makeBinaryDeviceId(getOwnDeviceId(), &binDeviceId);

    if (changeSet->has_updateaddmember()) {
        int32_t result;
        shared_ptr<cJSON> group = store_->listGroup(groupId, &result);
        addMissingMetaData(changeSet, group);
    }

    // Now check each update: add vector clocks, update id, then store the new data in group and member tables
    if (changeSet->has_updatename()) {
        returnCode = prepareChangeSet(groupId, binDeviceId, changeSet, GROUP_SET_NAME, updateId, *store_);
        if (returnCode < 0) {
            errorCode_ = returnCode;
            return returnCode;
        }
        store_->setGroupName(groupId, changeSet->updatename().name());
    }
    if (changeSet->has_updateavatar()) {
        returnCode = prepareChangeSet(groupId, binDeviceId, changeSet, GROUP_SET_AVATAR, updateId, *store_);
        if (returnCode < 0) {
            errorCode_ = returnCode;
            return returnCode;
        }
        store_->setGroupAvatarInfo(groupId, changeSet->updateavatar().avatar());
    }
    if (changeSet->has_updateburn()) {
        returnCode = prepareChangeSet(groupId, binDeviceId, changeSet, GROUP_SET_BURN, updateId, *store_);
        if (returnCode < 0) {
            errorCode_ = returnCode;
            return returnCode;
        }
        store_->setGroupBurnTime(groupId, changeSet->updateburn().burn_ttl_sec(), changeSet->updateburn().burn_mode());
    }
    if (changeSet->has_updateaddmember()) {
        const int32_t size = changeSet->updateaddmember().addmember_size();
        for (int i = 0; i < size; i++) {
            const string &userId = changeSet->updateaddmember().addmember(i).user_id();
            if (!store_->isMemberOfGroup(groupId, userId)) {
                store_->insertMember(groupId, userId);
            }
        }
    }
    if (changeSet->has_updatermmember()) {
        const int32_t size = changeSet->updatermmember().rmmember_size();
        for (int i = 0; i < size; i++) {
            const string &userId = changeSet->updatermmember().rmmember(i).user_id();
            store_->deleteMember(groupId, userId);
        }
    }
    return SUCCESS;
}

int32_t AppInterfaceImpl::createChangeSetDevice(const string &groupId, const string &deviceId, const string &attributes, string *newAttributes)
{
    if (groupId.empty() || deviceId.empty()) {
        return DATA_MISSING;
    }

    // The attributes string has a serialized change set in case ZINA responds with an ACK change sets
    // to a user's device.  Don't process a current change set
    JsonUnique sharedRoot(!attributes.empty() ? cJSON_Parse(attributes.c_str()) : cJSON_CreateObject());
    cJSON* root = sharedRoot.get();

    if (Utilities::hasJsonKey(sharedRoot.get(), GROUP_CHANGE_SET)) {
        return SUCCESS;
    }
    unique_lock<mutex> lck(currentChangeSetLock);

    PtrChangeSet changeSet;

    if (updateInProgress) {
        changeSet = getGroupChangeSet(groupId);
        if (!changeSet) {
            return GROUP_UPDATE_INCONSISTENT;
        }
        // Do we have any updates? If not, remove from current change set map and just return
        if (!changeSet->has_updatename() && !changeSet->has_updateavatar() && !changeSet->has_updateburn()
            && !changeSet->has_updateaddmember() && !changeSet->has_updatermmember()) {
            removeGroupFromChangeSet(groupId);
            return SUCCESS;
        }
    }
    else {
        changeSet = getPendingGroupChangeSet(groupId);
        if (!changeSet) {
            return SUCCESS;
        }
    }
    if (!updateInProgress) {
        return serializeChangeSet(changeSet, groupId, root, newAttributes);
    }

    string binDeviceId;
    makeBinaryDeviceId(deviceId, &binDeviceId);

    string updateIdString(reinterpret_cast<const char*>(updateId), UPDATE_ID_LENGTH);

    auto oldEnd = pendingChangeSets.cend();
    for (auto it = pendingChangeSets.cbegin(); it != oldEnd; ++it) {

        string oldGroupId = it->first.substr(UPDATE_ID_LENGTH);
        if (oldGroupId != groupId) {
            continue;
        }
        string oldUpdateId = it->first.substr(0, UPDATE_ID_LENGTH);
        auto oldChangeSet = it->second;

        // Collapse older add/remove member group updates into the current one
        // if the old change set has add new member _and_ the device has not ACK'd it, copy the old member into
        // current change set
        if (oldChangeSet->has_updateaddmember() && store_->hasWaitAck(groupId, binDeviceId, oldUpdateId, GROUP_ADD_MEMBER,
                                                                      nullptr)) {
            // Use the own addAddName function: skips duplicate names, checks the remove member data
            const int32_t size = oldChangeSet->updateaddmember().addmember_size();
            for (int i = 0; i < size; i++) {
                addAddNameToChangeSet(changeSet, oldChangeSet->updateaddmember().addmember(i).user_id());
                // Don't need to wait for ACK of old change set, we copied the data into the new set.
                store_->removeWaitAck(groupId, binDeviceId, oldUpdateId, GROUP_ADD_MEMBER);
            }
        }

        if (oldChangeSet->has_updatermmember() && store_->hasWaitAck(groupId, binDeviceId, oldUpdateId, GROUP_REMOVE_MEMBER,
                                                                     nullptr)) {
            // Use the own addRemoveName function: skips duplicate names, checks the add member data
            const int32_t size = oldChangeSet->updatermmember().rmmember_size();
            for (int i = 0; i < size; i++) {
                addRemoveNameToChangeSet(changeSet, oldChangeSet->updatermmember().rmmember(i).user_id());
                store_->removeWaitAck(groupId, binDeviceId, oldUpdateId, GROUP_REMOVE_MEMBER);
            }
        }
    }

    // We may now have an add member update: may have added names from old change set, thus add
    // meta data if necessary.
    if (changeSet->has_updateaddmember()) {
        int32_t result;
        shared_ptr<cJSON> group = store_->listGroup(groupId, &result);
        addMissingMetaData(changeSet, group);
    }

    // Because we send a new group update we can remove older group updates from wait-for-ack. The
    // recent update overwrites older updates. ZINA then ignores ACKs for the older updates.
    // Then store a new wait-for-ack record with the current update id.
    if (changeSet->has_updatename()) {
        store_->removeWaitAckWithType(groupId, binDeviceId, GROUP_SET_NAME);
        store_->insertWaitAck(groupId, binDeviceId, updateIdString, GROUP_SET_NAME);
    }
    if (changeSet->has_updateavatar()) {
        store_->removeWaitAckWithType(groupId, binDeviceId, GROUP_SET_AVATAR);
        store_->insertWaitAck(groupId, binDeviceId, updateIdString, GROUP_SET_AVATAR);
    }
    if (changeSet->has_updateburn()) {
        store_->removeWaitAckWithType(groupId, binDeviceId, GROUP_SET_BURN);
        store_->insertWaitAck(groupId, binDeviceId, updateIdString, GROUP_SET_AVATAR);
    }

    // Add wait-for-ack records for add/remove group updates
    if (changeSet->has_updateaddmember()) {
        store_->insertWaitAck(groupId, binDeviceId, updateIdString, GROUP_ADD_MEMBER);
    }
    if (changeSet->has_updatermmember()) {
        store_->insertWaitAck(groupId, binDeviceId, updateIdString, GROUP_REMOVE_MEMBER);
    }

    int32_t result = serializeChangeSet(changeSet, groupId, root, newAttributes);
    if (result != SUCCESS) {
        errorCode_ = result;
    }
    return result;
}

void AppInterfaceImpl::groupUpdateSendDone(const string& groupId)
{
    unique_lock<mutex> lck(currentChangeSetLock);

    if (!updateInProgress) {
        return;
    }
    string currentKey;
    currentKey.assign(reinterpret_cast<const char*>(updateId), sizeof(updateId)).append(groupId);

    memset(updateId, 0, sizeof(updateId));

    // Remove old change sets of the group. This guarantees that we have at most one pending change set per group
    auto oldEnd = pendingChangeSets.end();
    for (auto it = pendingChangeSets.begin(); it != oldEnd; ++it) {
        if (it->first == currentKey) {
            continue;
        }
        string oldGroupId = it->first.substr(UPDATE_ID_LENGTH);
        if (oldGroupId != groupId) {
            continue;
        }
        pendingChangeSets.erase(it);
    }

    PtrChangeSet changeSet = getGroupChangeSet(groupId);
    if (!changeSet) {
        return;
    }
    pendingChangeSets.insert(pair<string, PtrChangeSet>(currentKey, changeSet));
    currentChangeSets.erase(groupId);

    updateInProgress = false;
}

// The device_id inside then change set and vector clocks consists of the first 8 binary bytes
// of the unique device id (16 binary bytes)
void AppInterfaceImpl::makeBinaryDeviceId(const string &deviceId, string *binaryId)
{
    unique_ptr<uint8_t[]> binBuffer(new uint8_t[deviceId.size()]);
    hex2bin(deviceId.c_str(), binBuffer.get());
    string vecDeviceId;
    binaryId->assign(reinterpret_cast<const char*>(binBuffer.get()), VC_ID_LENGTH);
}

void AppInterfaceImpl::removeFromPendingChangeSets(const string &key) 
{
    auto oldEnd = pendingChangeSets.end();
    for (auto it = pendingChangeSets.begin(); it != oldEnd; ++it) {
        if (it->first == key) {
            pendingChangeSets.erase(it);
            break;
        }
    }
}