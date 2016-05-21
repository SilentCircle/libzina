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
#ifndef SQLITESTORE_H
#define SQLITESTORE_H

/**
 * @file SQLiteStoreConv.h
 * @brief Implementation of Axolotl store using SQLite
 * @ingroup Axolotl++
 * @{
 */

#include <string>
#include <stdint.h>
#include <list>
#include <memory>

#ifdef ANDROID
#include "android/jni/sqlcipher/sqlite3.h"
#else
#include <sqlcipher/sqlite3.h>
#include <iostream>
#include "../../util/cJSON.h"
#endif

#define DB_CACHE_ERR_BUFF_SIZE  1000
#define OUR_KEY_LENGTH          32

#define SQL_FAIL(code) ((code) > SQLITE_OK && (code) < SQLITE_ROW)

using namespace std;

auto cJSON_deleter = [](cJSON* json) {
    cJSON_Delete(json); json = nullptr;
};

namespace axolotl {

class SQLiteStoreConv
{
public:
    /**
     * @brief Get the Axolotl store instance.
     * 
     * The Axolotl store is a singleton and this call returns the instance.
     * Use @c isReady to check if this store is ready for use.
     * 
     * @return Either a new or an already open Axolotl store.
     */
    static SQLiteStoreConv* getStore();

    /**
     * @brief Close the Axolotl store instance.
     */
    static void closeStore() { delete instance_; instance_ = NULL;}

    /**
     * @brief Is store ready for use?
     */
    bool isReady() { return isReady_; }

    /**
     * @brief Open Axolotl store.
     * 
     * @param filename Filename of the database, including path.
     * @return an SQLite code
     */
    int openStore(const string& filename);

    /**
     * @brief Set key to encrypt sensitive data.
     * 
     * Several functions deal with senisitve data and these functions encrypt the
     * data before they store it in the DB and decrypt it after reading. The
     * @c string is not tread as a string but as a container that hold the
     * key material, i.e. binary data. The length of the key must be 32 bytes
     * 
     * @param keyData a @c string container with the key data
     * @return @c true is key is OK, @c false otherwise.
     */
    bool setKey(const string& keyData) {if (keyData.size() != OUR_KEY_LENGTH) return false; keyData_ = new string(keyData); return true; }

    /**
     * @brief Get the last SQLite error message.
     * 
     * If a functions returns an error code or if the stored SQLite code is
     * not equal @c SQLITE_OK then this function returns a pointer to the last
     * SQLite error message
     * 
     * @return pointer to SQLite error message.
     */
    const char* getLastError() {return lastError_;}

    /**
     * @brief Return the SQLite code of the last SQLite function.
     * 
     * Many functions interally use SQLite which may return an SQLite error.
     * In this case the functions store the SQLite code and the caller can
     * check if all operations were successfull. 
     */
    int32_t getSqlCode() const {return sqlCode_;}


    /**
     * @brief Get a list of all known identities
     * 
     * Assemble a list of names for all known identities. 
     * 
     * @return a new list with the names, an empty list if now identities available,
     *         NULL in case of error
     */
    shared_ptr<list<string> > getKnownConversations(const string& ownName, int32_t* sqlCode = NULL);

    /**
     * @brief Get a list of long device ids for a name.
     * 
     * Returns a list of known devices for a user. A user may have several Axolotl device
     * registered with the account.
     * 
     * @param name the user's name.
     * @return a new list with the long device ids, NULL in case of error
     */
    shared_ptr<list<string> > getLongDeviceIds(const string& name, const string& ownName, int32_t* sqlCode = NULL);


    // ***** Conversation store
    string* loadConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode = NULL) const;

    void storeConversation(const string& name, const string& longDevId, const string& ownName, const string& data, int32_t* sqlCode = NULL);

    bool hasConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode = NULL) const;

    void deleteConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode = NULL);

    void deleteConversationsName(const string& name, const string& ownName, int32_t* sqlCode = NULL);

    // ***** staged message keys store
    shared_ptr<list<string> > loadStagedMks(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode = NULL) const;

    void insertStagedMk(const string& name, const string& longDevId, const string& ownName, const string& MKiv, int32_t* sqlCode = NULL);

    void deleteStagedMk(const string& name, const string& longDevId, const string& ownName, const string& MKiv, int32_t* sqlCode = NULL);

    void deleteStagedMk(time_t timestamp, int32_t* sqlCode = NULL);

    // Pre key storage. The functions encrypt, decrypt and store/retrieve Pre-key JSON strings
    string* loadPreKey(int32_t preKeyId, int32_t* sqlCode = NULL) const;

    void storePreKey(int32_t preKeyId, const string& preKeyData, int32_t* sqlCode = NULL);

    bool containsPreKey(int32_t preKeyId, int32_t* sqlCode = NULL) const;

    void removePreKey(int32_t preKeyId, int32_t* sqlCode = NULL);

    void dumpPreKeys() const;

    // ***** Message hash / time table to detect duplicate message from server
    /**
     * @brief Insert a message hash into the table.
     * 
     * @param msgHash the hash to insert, no duplicates allowed
     * @return SQLite code
     */
    int32_t insertMsgHash( const string& msgHash );

    /**
     * @brief Check if a message hash is in the table.
     * 
     * @param msgHash the hash to insert, no duplicates allowed
     * @return SQLite code, @c SQLITE_ROW indicates the message hash exists in the table
     */
    int32_t hasMsgHash(const string& msgHash);

    /**
     * @brief Delete message hashes older than the timestamp.
     * 
     * @param timestamp the timestamp of oldest hash
     * @return SQLite code
     */
    int32_t deleteMsgHashes(time_t timestamp);

    /**
     * @brief Insert Message Trace record.
     *
     * @param name The message sender's/receiver's name (SC uid)
     * @param messageId The UUID of the message
     * @param deviceId The sender's device id
     * @param attribute The message attribute string which contains status information
     * @param attachment If set the message contained an attachment descriptor
     * @param received If set then this was a received message.
     * @return SQLite code
     */
    int32_t insertMsgTrace(const string& name, const string& messageId, const string& deviceId, const string& convState,
                           const string& attributes, bool attachment, bool received);


    /**
     * @brief Return a list of message trace record.
     *
     * The function selects and returns a list of JSON formatted message trace records, ordered by the
     * sequence of record insertion. The function supports the following selections:
     * <ul>
     * <li>@c name contains data, @c messageId and @c deviceId are empty: return all message trace records
     *     for this name</li>
     * <li>@c messageId contains data, @c name and @c deviceId are empty: return all message trace records
     *     for this messageId</li>
     * <li>@c deviceId contains data, @c name and @c messageId are empty: return all message trace records
     *     for this deviceId</li>
     * <li>@c messageId and @c deviceId contain data, @c name is empty: return all message trace records
     *     that match the messageId AND deviceId</li>
     * </ul>
     * @param name The message sender's/receiver's name (SC uid)
     * @param messageId The UUID of the message
     * @param deviceId The sender's device id
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return list of trace records, maybe empty, never @c NULL
     */
    shared_ptr<list<string> > loadMsgTrace(const string& name, const string& messageId, const string& deviceId, int32_t* sqlCode = NULL);

    /**
     * @brief Delete message trace records older than the timestamp.
     *
     * @param timestamp the timestamp of oldest message trace
     * @return SQLite code, @c SQLITE_ROW indicates the message hash exists in the table
     */
    int32_t deleteMsgTrace(time_t timestamp);

    // Functions to handle groups and group member data

    /**
     * @brief Create a new chat group.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID), must be unique
     * @param name group's human readable name
     * @param ownerUuid the group owner's UUID (SC UID)
     * @parm maxMembers Initial number of member allowed in this group
     * @param description Group description
     * @return SQLite code
     */
    int32_t insertGroup(const string& groupUuid, const string& name, const string& ownerUuid, string& description, int32_t maxMembers);

    /**
     * @brief Delete a group record.
     *
     * Deletes a record only if no member records exist for this group. Enforced by
     * database referential integrity.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @return SQLite code
     */
    int32_t deleteGroup(const string& groupUuid);

    /**
     * @brief List data of all known groups.
     *
     * Creates and returns a list of shared pointers to cJSON data structures that contain
     * the groups' data. The shared pointers have a special deleter that calls @c cJSON_delete
     * to free the data structure.
     *
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return list of cJSON pointers to cJSON data structure, maybe empty, never @c NULL
     */
    shared_ptr<list<shared_ptr<cJSON> > >listAllGroups(int32_t* sqlCode = NULL);

    /**
     * @brief Get data of a group.
     *
     * Returns a shared pointer to a cJSON data structure that contains the group's
     * data. The shared pointer has a special deleter that calls @c cJSON_delete to free
     * the data structure.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return cJSON shared pointer to group data structure, maybe @c NULL (false)
     */
    shared_ptr<cJSON> listGroup(const string& groupUuid, int32_t* sqlCode = NULL);

    /**
     * @brief Set a new maximum number of group members
     *
     * The function just sets the new value in the database group record, it does
     * not the if the number of current group members is already above the new maximum.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param macMembers The new value of maximum group members
     * @return SQLite code
     */
    int32_t modifyGroupMaxMembers(const string& groupUuid, int maxMembers);

    /**
     * @brief Create a group member
     *
     * Create a new member record. The @c memberUuid / @c deviceId combination must
     * match an existing ratchet conversation record. The group member record uses
     * the @memberUuid (aka SC uid), @c deviceId and the @c ownName as foreign keys
     * to refer to the appropriate conversation record which defies these three fields
     * as its primary key.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the new member's UID
     * @param deviceId the new member's device id to support multi-device support
     * @param ownName This is the 'own name' used in the ratchet conversation, not the group owner
     * @return SQLite code
     */
    int32_t insertMember(const string& groupUuid, const string& memberUuid,const string& deviceId, const string& ownName);

    /**
     * @brief Deletes all group records of this member in the specified group.
     *
     * If a group member has several devices, thus more than one group member record,
     * then the function deletes all records.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the new member's UID
     * @return SQLite code
     */
    int32_t deleteMember(const string& groupUuid, const string& memberUuid);

    /**
     * @brief Deletes a device specific group record of this member in the specified group.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the new member's UID
     * @param deviceId the member's device id to support multi-device support
     * @return SQLite code
     */
    int32_t deleteMemberDevice(const string& groupUuid, const string& memberUuid, const string& deviceId);

    /**
     * @brief List all members of a specified group.
     *
     * Creates and returns a list of shared pointers to cJSON data structures that contain the group's
     * members data. The shared pointers have a special deleter that calls @c cJSON_delete
     * to free the data structure.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return list of cJSON pointers to cJSON data structure, maybe empty, never @c NULL
     */
    shared_ptr<list<shared_ptr<cJSON> > >listAllGroupMembers(const string& groupUuid, int32_t* sqlCode = NULL);

    /**
     * @brief List a member of a specified group.
     *
     * Creates and returns a shared pointer to a cJSON data structure that contains the member's
     * data. The member may have more than one record, one for each device. The shared pointer
     * has a special deleter that calls @c cJSON_delete to free the data structure.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the new member's UID
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return list of cJSON pointers to cJSON data structure, maybe empty, never @c NULL
     */
    shared_ptr<cJSON> listGroupMember(const string& groupUuid, const string& memberUuid, int32_t* sqlCode = NULL);

    /*
     * @brief Use for debugging and development only.
     */
    int32_t resetStore() { return createTables(); }

private:
    SQLiteStoreConv();
    ~SQLiteStoreConv();

    SQLiteStoreConv(const SQLiteStoreConv& other) = delete;
    SQLiteStoreConv& operator=(const SQLiteStoreConv& other) = delete;
    bool operator==(const SQLiteStoreConv& other) const = delete;

    /**
     * Create Axolotl tables in database.
     *
     * openCache calls this function if it cannot find the table zrtpId_own. This indicates
     * that Axolotl tables are available in the database.
     */
    int createTables();
    int beginTransaction();
    int commitTransaction();
    int rollbackTransaction();

    /**
     * @brief Update database version.
     * 
     * This function runs in a transaction and any changes are discarded if the
     * function closes the database or returns a code other than SQLITE_OK.
     * 
     * @param oldVersion the current version of the database
     * @param newVersion the target version for the database
     * @return SQLITE_OK to commit any changes, any other code closes the database with rollback.
     */
    int32_t updateDb(int32_t oldVersion, int32_t newVersion);

    static SQLiteStoreConv* instance_;
    sqlite3* db;
    string* keyData_;

    bool isReady_;

    mutable int32_t sqlCode_;
    mutable char lastError_[DB_CACHE_ERR_BUFF_SIZE];
};
} // namespace axolotl

/**
 * @}
 */

#endif // SQLITESTORE_H
