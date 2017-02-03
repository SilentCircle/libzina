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
// Created by werner on 02.02.17.
//

#include <string>

#include "gtest/gtest.h"
#include "../interfaceApp/AppInterfaceImpl.h"
#include "../interfaceApp/GroupProtocol.pb.h"

using namespace std;
using namespace zina;

static const uint8_t keyInData[] = {0,1,2,3,4,5,6,7,8,9,19,18,17,16,15,14,13,12,11,10,20,21,22,23,24,25,26,27,28,20,31,30};

string groupName_1("group_Name_1");
string groupName_2("group_Name_2");

string groupId_1("group_id_1");

// Make each id 8 characters/bytes
string node_1("node_1--");
string node_2("node_2--");
string node_3("node_3--");
string node_4("node_4--");

string updateId_1("update_id_1");

static string memberId_1("uAGroupMember1");
static string longDevId_1("def11fed");
static string apiKey_1("api_key_1");
AppInterfaceImpl* appInterface_1;

static string otherMemberId_1("uAnOtherGroupMember1");
static string otherMemberId_2("uAnOtherGroupMember2");


typedef shared_ptr<GroupChangeset> PtrChangeSet;
PtrChangeSet getGroupChangeSet(const string &groupId, SQLiteStoreConv &store);

class ChangeSetTestsFixtureSimple: public ::testing::Test {
public:
    ChangeSetTestsFixtureSimple( ) {
        LOGGER_INSTANCE setLogLevel(ERROR);
        store = SQLiteStoreConv::getStore();
        store->setKey(std::string((const char*)keyInData, 32));
        store->openStore(std::string());
        appInterface_1 = new AppInterfaceImpl(store, memberId_1, apiKey_1, longDevId_1);

    }

    void SetUp() {
        // code here will execute just before the test ensues
    }

    void TearDown() {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ChangeSetTestsFixtureSimple()  {
        // cleanup any pending stuff, but no exceptions allowed
        store->closeStore();
        delete appInterface_1;
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    // put in any custom data members that you need
    SQLiteStoreConv *store;
};

TEST_F(ChangeSetTestsFixtureSimple, NewGroupTestsEmpty) {
    string groupId = appInterface_1->createNewGroup(Empty, Empty, 0);
    ASSERT_FALSE(groupId.empty());

    PtrChangeSet changeSet = getGroupChangeSet(groupId, *store);
    ASSERT_TRUE((bool)changeSet);

    ASSERT_FALSE(changeSet->has_updatename());
}

TEST_F(ChangeSetTestsFixtureSimple, NewGroupTests) {
    string groupId = appInterface_1->createNewGroup(groupName_1, Empty, 0);
    ASSERT_FALSE(groupId.empty());

    PtrChangeSet changeSet = getGroupChangeSet(groupId, *store);
    ASSERT_TRUE((bool)changeSet);

    ASSERT_TRUE(changeSet->has_updatename());
    ASSERT_EQ(groupName_1, changeSet->updatename().name());

    // cancel and remove the changes
    appInterface_1->cancelGroupChanges(groupId);
    changeSet = getGroupChangeSet(groupId, *store);
    ASSERT_FALSE((bool)changeSet);

}

TEST_F(ChangeSetTestsFixtureSimple, ExistingGroupTests) {
    int32_t result = store->insertGroup(groupId_1, groupName_1, appInterface_1->getOwnUser(), Empty, 0);
    ASSERT_FALSE(SQL_FAIL(result));

    PtrChangeSet changeSet = getGroupChangeSet(groupId_1, *store);
    ASSERT_TRUE((bool)changeSet);

    ASSERT_EQ(OK, appInterface_1->setGroupName(groupId_1, groupName_1));
    ASSERT_TRUE(changeSet->has_updatename());
    ASSERT_EQ(groupName_1, changeSet->updatename().name());

    ASSERT_EQ(OK, appInterface_1->setGroupAvatar(groupId_1, groupName_2));
    ASSERT_TRUE(changeSet->has_updateavatar());
    ASSERT_EQ(groupName_2, changeSet->updateavatar().avatar());
}

class ChangeSetTestsFixtureMembers: public ::testing::Test {
public:
    ChangeSetTestsFixtureMembers( ) {
        LOGGER_INSTANCE setLogLevel(ERROR);
        // initialization code here
        store = SQLiteStoreConv::getStore();
        store->setKey(std::string((const char*)keyInData, 32));
        store->openStore(std::string());
        appInterface_1 = new AppInterfaceImpl(store, memberId_1, apiKey_1, longDevId_1);
        groupId = appInterface_1->createNewGroup(groupName_1, Empty, 0);
    }

    void SetUp() {
        // code here will execute just before the test ensues
    }

    void TearDown() {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
    }

    ~ChangeSetTestsFixtureMembers()  {
        // cleanup any pending stuff, but no exceptions allowed
        store->closeStore();
        delete appInterface_1;
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    // put in any custom data members that you need
    string groupId;
    SQLiteStoreConv *store;

};

TEST_F(ChangeSetTestsFixtureMembers, AddMemberTests) {
    int32_t result = appInterface_1->inviteUser(Empty, Empty);
    ASSERT_EQ(DATA_MISSING, result);

    PtrChangeSet changeSet = getGroupChangeSet(groupId, *store);
    ASSERT_TRUE((bool)changeSet);
    ASSERT_FALSE(changeSet->has_updateaddmember());

    result = appInterface_1->inviteUser(groupId, Empty);
    ASSERT_EQ(DATA_MISSING, result);
    ASSERT_FALSE(changeSet->has_updateaddmember());

    result = appInterface_1->inviteUser(Empty, memberId_1);
    ASSERT_EQ(DATA_MISSING, result);
    ASSERT_FALSE(changeSet->has_updateaddmember());

    result = appInterface_1->inviteUser(groupId, memberId_1);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updateaddmember());
    ASSERT_EQ(1, changeSet->updateaddmember().addmember_size());
    ASSERT_EQ(memberId_1, changeSet->updateaddmember().addmember(0).user_id());

    result = appInterface_1->inviteUser(groupId, otherMemberId_1);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updateaddmember());
    ASSERT_EQ(2, changeSet->updateaddmember().addmember_size());
    ASSERT_EQ(otherMemberId_1, changeSet->updateaddmember().addmember(1).user_id());

    result = appInterface_1->inviteUser(groupId, otherMemberId_2);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updateaddmember());
    ASSERT_EQ(3, changeSet->updateaddmember().addmember_size());
    ASSERT_EQ(otherMemberId_2, changeSet->updateaddmember().addmember(2).user_id());

    // adding a name a second time, ignore silently, no changes in change set
    result = appInterface_1->inviteUser(groupId, otherMemberId_2);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updateaddmember());
    ASSERT_EQ(3, changeSet->updateaddmember().addmember_size());
    ASSERT_EQ(otherMemberId_2, changeSet->updateaddmember().addmember(2).user_id());
}

TEST_F(ChangeSetTestsFixtureMembers, RemoveMemberTests) {

    int32_t result = appInterface_1->leaveGroup(Empty);
    ASSERT_EQ(DATA_MISSING, result);

    PtrChangeSet changeSet = getGroupChangeSet(groupId, *store);
    ASSERT_TRUE((bool)changeSet);
    ASSERT_FALSE(changeSet->has_updatermmember());

    result = appInterface_1->inviteUser(Empty, memberId_1);
    ASSERT_EQ(DATA_MISSING, result);
    ASSERT_FALSE(changeSet->has_updateaddmember());

    result = appInterface_1->leaveGroup(groupId);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updatermmember());
    ASSERT_EQ(1, changeSet->updatermmember().rmmember_size());
    ASSERT_EQ(memberId_1, changeSet->updatermmember().rmmember(0).user_id());

    result = appInterface_1->leaveGroup(groupId, otherMemberId_1);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updatermmember());
    ASSERT_EQ(2, changeSet->updatermmember().rmmember_size());
    ASSERT_EQ(otherMemberId_1, changeSet->updatermmember().rmmember(1).user_id());

    result = appInterface_1->leaveGroup(groupId, otherMemberId_2);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updatermmember());
    ASSERT_EQ(3, changeSet->updatermmember().rmmember_size());
    ASSERT_EQ(otherMemberId_2, changeSet->updatermmember().rmmember(2).user_id());

    // removing a name a second time, ignore silently, no changes in change set
    result = appInterface_1->leaveGroup(groupId, otherMemberId_2);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updatermmember());
    ASSERT_EQ(3, changeSet->updatermmember().rmmember_size());
    ASSERT_EQ(otherMemberId_2, changeSet->updatermmember().rmmember(2).user_id());
}

TEST_F(ChangeSetTestsFixtureMembers, AddRemoveMemberTests) {

    // At first add a member, check data
    int32_t result = appInterface_1->inviteUser(groupId, memberId_1);
    PtrChangeSet changeSet = getGroupChangeSet(groupId, *store);

    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updateaddmember());
    ASSERT_EQ(1, changeSet->updateaddmember().addmember_size());
    ASSERT_EQ(memberId_1, changeSet->updateaddmember().addmember(0).user_id());

    // add a second member
    result = appInterface_1->inviteUser(groupId, otherMemberId_1);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updateaddmember());
    ASSERT_EQ(2, changeSet->updateaddmember().addmember_size());
    ASSERT_EQ(otherMemberId_1, changeSet->updateaddmember().addmember(1).user_id());

    // Now remove the first added member
    // expect that it is in remove update, and removed from add update thus it is down 1
    result = appInterface_1->leaveGroup(groupId, memberId_1);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updatermmember());
    ASSERT_EQ(1, changeSet->updatermmember().rmmember_size());
    ASSERT_EQ(memberId_1, changeSet->updatermmember().rmmember(0).user_id());

    // check the add update data
    ASSERT_TRUE(changeSet->has_updateaddmember());
    ASSERT_EQ(1, changeSet->updateaddmember().addmember_size());
    ASSERT_EQ(otherMemberId_1, changeSet->updateaddmember().addmember(0).user_id());

    // Now remove another member
    result = appInterface_1->leaveGroup(groupId, otherMemberId_2);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updatermmember());
    ASSERT_EQ(2, changeSet->updatermmember().rmmember_size());
    ASSERT_EQ(otherMemberId_2, changeSet->updatermmember().rmmember(1).user_id());

    // now re-add the first member. It should be re-added to add update, removed from
    // remove update
    result = appInterface_1->inviteUser(groupId, memberId_1);
    ASSERT_EQ(OK, result);
    ASSERT_TRUE(changeSet->has_updateaddmember());
    ASSERT_EQ(2, changeSet->updateaddmember().addmember_size());
    ASSERT_EQ(memberId_1, changeSet->updateaddmember().addmember(1).user_id());

    // remove update down to one
    ASSERT_TRUE(changeSet->has_updatermmember());
    ASSERT_EQ(1, changeSet->updatermmember().rmmember_size());
    ASSERT_EQ(otherMemberId_2, changeSet->updatermmember().rmmember(0).user_id());
}