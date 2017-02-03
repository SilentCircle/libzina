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

#include "AppInterfaceImpl.h"

#include "GroupProtocol.pb.h"

using namespace std;
using namespace zina;

typedef shared_ptr<GroupChangeset> PtrChangeSet;

static mutex localChangeSetLock;
static map<string, PtrChangeSet> localChangeSet;

static bool addNewGroupToChangeSet(const string &groupId)
{
    unique_lock<mutex> lck(localChangeSetLock);

    auto changeSet = make_shared<GroupChangeset>();

    return localChangeSet.insert(pair<string, PtrChangeSet >(groupId, changeSet)).second;
}


static void removeGroupFromChangeSet(const string &groupId)
{
    unique_lock<mutex> lck(localChangeSetLock);

    localChangeSet.erase(groupId);
}

// Returns pointer to a group's change set class
//
// Return an empty if the group is not valid.
// Function assumes the lock is set
// make it visible for unittests
#ifdef UNITTESTS
PtrChangeSet getGroupChangeSet(const string &groupId, SQLiteStoreConv &store);
#else
static
#endif
PtrChangeSet getGroupChangeSet(const string &groupId, SQLiteStoreConv &store)
{
    auto it = localChangeSet.find(groupId);
    if (it != localChangeSet.end()) {
        return it->second;
    }
    // no group change set yet. Check if we really have the group
    if (!store.hasGroup(groupId) || ((store.getGroupAttribute(groupId).first & ACTIVE) != ACTIVE)) {
        return PtrChangeSet();
    }

    // Yes, we have this group, create a change set, insert into map, return the pointer
    auto changeSet = make_shared<GroupChangeset>();
    if (!localChangeSet.insert(pair<string, PtrChangeSet >(groupId, changeSet)).second) {
        return PtrChangeSet();
    }
    return changeSet;
}

// Sets name only. We add the vector clock later, just before sending out the change
// Overwrite an existing name update
static bool setGroupNameToChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(localChangeSetLock);

    // get mutable pointer
    auto changeSet = getGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    if (name.empty()) {
        string *oldName = changeSet->mutable_updatename()->release_name();
        delete oldName;
    }
    else {
        // Proto buffer implementation takes ownership of pointer, also releases an already set update message
        changeSet->mutable_updatename()->set_name(name);
    }

    return true;
}

// Sets avatar info only. We add the vector clock later, just before sending out the change
// Overwrite an existing avatar update
static bool setGroupAvatarToChangeSet(const string &groupId, const string &avatar, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(localChangeSetLock);

    auto changeSet = getGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    if (avatar.empty()) {
        string *oldAvatar = changeSet->mutable_updateavatar()->release_avatar();
        delete oldAvatar;
    }
    else {
        // Proto buffer implementation takes ownership of pointer, also releases an already set update message
        changeSet->mutable_updateavatar()->set_avatar(avatar);
    }

    return true;
}

// Sets burn info only. We add the vector clock later, just before sending out the change
// Overwrite an existing avatar update
static bool setGroupBurnToChangeSet(const string &groupId, uint64_t burn, GroupUpdateSetBurn_BurnMode mode, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(localChangeSetLock);

    auto changeSet = getGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    // Proto buffer implementation takes ownership of pointer, also releases an already set update message
    changeSet->mutable_updateburn()->set_burn_mode(GroupUpdateSetBurn_BurnMode_FROM_SEND_RETROACTIVE);
    changeSet->mutable_updateburn()->set_burn_ttl_sec(burn);

    return true;
}

// Thus function removes an remove member from the change set
// Function assumes the change set is locked
static bool removeRmNameFromChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    auto changeSet = getGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
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

// Thus function adds an add member to the change set, collapsed into a repeated GROUP_ADD_MEMBER update
// message. The function silently ignores duplicate names.
// adding a new member to the change set checks the remove update and removes an entry with the
// same name if found
static bool addAddNameToChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(localChangeSetLock);

    auto changeSet = getGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
    // In case we added this name to the current change set, remove it, don't need to remove
    // it. However, add it the the change set to add names.
    removeRmNameFromChangeSet(groupId, name, store);

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

// Thus function removes an add member from the change set
// Function assumes the change set is locked
static bool removeAddNameFromChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    auto changeSet = getGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }
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

// Thus function adds a remove member, collapsed into a repeated GROUP_REMOVE_MEMBER update message
// The function silently ignores duplicate names.
// adding a new member to the change set checks the add update and removes an entry with the
// same name if found
static bool addRemoveNameToChangeSet(const string &groupId, const string &name, SQLiteStoreConv &store)
{
    unique_lock<mutex> lck(localChangeSetLock);

    auto changeSet = getGroupChangeSet(groupId, store);
    if (!changeSet) {
        return false;
    }

    // In case we added this name to the current changes set, remove it, don't need to add
    // it. However, add it the the change set to remove names.
    removeAddNameFromChangeSet(groupId, name, store);

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

    addNewGroupToChangeSet(groupId);
    if (!groupName.empty()) {
        setGroupNameToChangeSet(groupId, groupName, *store_);
    }
// we store this later when preparing the message
//    store_->insertGroup(groupId, groupName, ownUser_, groupDescription, maxMembers);
//
//    // Add myself to the new group, this saves us a "send to sibling" group function, then inform my sibling about
//    // the new group
//    store_->insertMember(groupId, ownUser_);
//    sendGroupCommand(ownUser_, generateMsgIdTime(), syncNewGroupCommand(groupId, groupName, groupDescription, ownUser_, maxMembers));
//
    LOGGER(INFO, __func__, " <--");
    return groupId;
}

int32_t AppInterfaceImpl::inviteUser(const string& groupUuid, const string& userId)
{
    LOGGER(INFO, __func__, " -->");

    if (groupUuid.empty() || userId.empty()) {
        return DATA_MISSING;
    }
    if (!addAddNameToChangeSet(groupUuid, userId, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::addUser(const string& groupUuid, const string& userId)
{
    return inviteUser(groupUuid, userId);
}

int32_t AppInterfaceImpl::removeUserFromAddUpdate(const string& groupUuid, const string& userId)
{
    LOGGER(INFO, __func__, " -->");

    if (groupUuid.empty() || userId.empty()) {
        return DATA_MISSING;
    }

    unique_lock<mutex> lck(localChangeSetLock);
    if (!removeAddNameFromChangeSet(groupUuid, userId, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}


int32_t AppInterfaceImpl::leaveGroup(const string& groupId, const string& userId) {
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }

    const string &user = userId.empty() ? ownUser_ : userId;

    if (!addRemoveNameToChangeSet(groupId, user, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::removeUserFromRemoveUpdate(const string& groupUuid, const string& userId)
{
    LOGGER(INFO, __func__, " -->");

    if (groupUuid.empty() || userId.empty()) {
        return DATA_MISSING;
    }

    unique_lock<mutex> lck(localChangeSetLock);
    if (!removeRmNameFromChangeSet(groupUuid, userId, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return OK;

}

int32_t AppInterfaceImpl::setGroupName(const string& groupId, const string& groupName)
{
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }

    if (!setGroupNameToChangeSet(groupId, groupName, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
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
    return OK;
}

int32_t AppInterfaceImpl::setGroupAvatar(const string& groupId, const string& avatar)
{
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }

    if (!setGroupAvatarToChangeSet(groupId, avatar, *store_)) {
        return NO_SUCH_ACTIVE_GROUP;
    }
    LOGGER(INFO, __func__, " <--");
    return OK;
}

int32_t AppInterfaceImpl::cancelGroupChanges(const string& groupId)
{
    LOGGER(INFO, __func__, " -->");

    if (groupId.empty()) {
        return DATA_MISSING;
    }
    removeGroupFromChangeSet(groupId);
    LOGGER(INFO, __func__, " <--");
    return OK;
}
