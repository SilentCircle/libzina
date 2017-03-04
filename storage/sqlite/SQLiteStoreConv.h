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
 * @brief Implementation of ZINA store using SQLite
 * @ingroup Zina
 * @{
 */

#include <stdint.h>
#include <list>

#include "../../logging/ZinaLogging.h"
#include "../../util/cJSON.h"

#ifdef ANDROID
#include "android/jni/sqlcipher/sqlite3.h"
#else
#include <sqlcipher/sqlite3.h>
#endif

#define DB_CACHE_ERR_BUFF_SIZE  1000
#define OUR_KEY_LENGTH          32

#define SQL_FAIL(code) ((code) > SQLITE_OK && (code) < SQLITE_ROW)

#ifndef DEPRECATED_ZINA
#ifdef __GNUC__
#define DEPRECATED_ZINA __attribute__((deprecated))
#elif defined(_MSC_VER)
#define DEPRECATED_ZINA __declspec(deprecated)
#else
#pragma message("WARNING: You need to implement DEPRECATED_ZINA for this compiler")
#define DEPRECATED_ZINA
#endif
#endif      // DEPRECATED_ZINA

using namespace std;

auto cJSON_deleter = [](cJSON* json) {
    cJSON_Delete(json); json = nullptr;
};

struct cJsonDeleter_ {
    void operator()(cJSON* json) { cJSON_Delete(json); json = nullptr; }
};

struct charDeleter_ {
    void operator()(char* arg) { free(arg); arg = nullptr; }
};

typedef unique_ptr<cJSON, cJsonDeleter_> JsonUnique;
typedef unique_ptr<char, charDeleter_> CharUnique;

namespace zina {

typedef struct StoredMsgInfo {
    string data1;
    string data2;
    string data3;
    int64_t sequence;
    int32_t int32Data;
} StoredMsgInfo;

// defines to access the info structure when using it for raw message data
#define info_rawMsgData  data1
#define info_uid         data2
#define info_displayName data3

// defines to access the info structure when using it for temp message data
#define info_msgDescriptor   data1
#define info_supplementary   data2
#define info_msgType         int32Data

class SQLiteStoreConv
{
public:
    /**
     * @brief Get the ZINA store instance.
     * 
     * The ZINA store is a singleton and this call returns the instance.
     * Use @c isReady to check if this store is ready for use.
     * 
     * @return Either a new or an already open ZINA store.
     */
    static SQLiteStoreConv* getStore();

    /**
     * @brief Close the ZINA store instance.
     */
    static void closeStore() { delete instance_; instance_ = NULL;}

    /**
     * @brief Is store ready for use?
     */
    bool isReady() { return isReady_; }

    /**
     * @brief Open ZINA store.
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
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return A new list with the, an empty list if now identities available,
     *         NULL in case of error
     */
    shared_ptr<list<string> > getKnownConversations(const string& ownName, int32_t* sqlCode = NULL);

    /**
     * @brief Get a list of long device ids for a name.
     * 
     * Returns a list of known devices of a user. A user may have several Zina device
     * registered with the account. The function returns data only for other devices, not
     * the own client device.
     *
     * @deprecated Use getLongDeviceIds(const string&, const string&, list<string> *) instead.
     * 
     * @param name the user's name.
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return A new list with the long device ids, may be empty.
     */
    DEPRECATED_ZINA shared_ptr<list<string> > getLongDeviceIds(const string& name, const string& ownName, int32_t* sqlCode = NULL);

    /**
     * @brief Get a list of long device ids for a name.
     *
     * Fill a list of known devices of a user. A user may have several Zina devices
     * registered with the account. The function returns data only for other devices, not
     * the own client device.
     *
     * @param name the user's name.
     * @param devIds List of strings
     * @return SQLite code, @c SQLITE_ROW indicates the message hash exists in the table
     */
    int32_t getLongDeviceIds(const string& name, const string& ownName, list<string> &devIds);

    // ***** Conversation store
    string* loadConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode = NULL) const;

    void storeConversation(const string& name, const string& longDevId, const string& ownName, const string& data, int32_t* sqlCode = NULL);

    bool hasConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode = NULL) const;

    void deleteConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode = NULL);

    void deleteConversationsName(const string& name, const string& ownName, int32_t* sqlCode = NULL);

    // ***** staged message keys store
    int32_t loadStagedMks(const string& name, const string& longDevId, const string& ownName, list<string> &keys) const;

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

    /**
     * @brief Insert received message raw data and meta data.
     *
     * @param rawData Encrypted received message raw data
     * @param uid Sender's unique id, if available, maybe empty
     * @param displayName Sender's human readable name, if available, maybe empty
     * @param sequence Pointer to a unsigned 64 bit integer that gets the sequence number of the stored data record
     * @return SQLite code
     */
    int32_t insertReceivedRawData(const string& rawData, const string& uid, const string& displayName, int64_t* sequence);

    /**
     * @brief Retrive stored received message raw data.
     *
     * @param rawMessageData Shared pointer to a list of shared pointer where the function returns the StoredMsgInfo.
     * @return SQLite code
     */
    int32_t loadReceivedRawData(list<unique_ptr<StoredMsgInfo> >* rawMessageData);

    /**
     * @brief Delete a message raw data record.
     *
     * @param sequence The sequence number of the record to delete.
     * @return
     */
    int32_t deleteReceivedRawData(int64_t sequence);

    /**
     * @brief Delete raw message records older than the timestamp.
     *
     * @param timestamp the timestamp of oldest record
     * @return SQLite code
     */
    int32_t cleanReceivedRawData(time_t timestamp);

    /**
     * @brief Insert temporary message data and supplmentary data.
     *
     * @param messageData Message descriptor, JSON formatted string
     * @param supplementData Supplementary data, JSON formatted string
     * @param sequence Pointer to a unsigned 64 bit integer that gets the sequence number of the stored data record
     * @return SQLite code
     */
    int32_t insertTempMsg(const string& messageData, const string& supplementData, int32_t msgType, int64_t* sequence);

    /**
     * @brief Retrive stored temporary message data.
     *
     * @param rawMessageData Pointer to a list of shared pointer where the function returns the StoredMsgInfo.
     * @return SQLite code
     */
    int32_t loadTempMsg(list<unique_ptr<StoredMsgInfo> >* tempMessageData);

    /**
     * @brief Delete a message raw data record.
     *
     * @param sequence The sequence number of the record to delete.
     * @return
     */
    int32_t deleteTempMsg(int64_t sequence);

    /**
     * @brief Delete temporary message records older than the timestamp.
     *
     * @param timestamp the timestamp of oldest record
     * @return SQLite code
     */
    int32_t cleanTempMsg(time_t timestamp);

    /* ***************************************************
     * Functions to handle groups and group member data
     * ************************************************* */

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
     * @brief Check if a group exists.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @return @c true if the group exists, @c false otherwise
     */
    bool hasGroup(const string& groupUuid, int32_t* sqlCode = NULL);

    /**
     * @brief List data of all known groups.
     *
     * Creates and returns a list of shared pointers to cJSON data structures that contain
     * the groups' data. The shared pointers have a special deleter that calls @c cJSON_delete
     * to free the data structure.
     *
     * @deprecated Use listAllGroups(list<JsonUnique> *groups) instead.
     *
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return list of cJSON pointers to cJSON data structure, maybe empty, never @c NULL
     */
    DEPRECATED_ZINA shared_ptr<list<shared_ptr<cJSON> > >listAllGroups(int32_t* sqlCode = NULL);

    /**
     * @brief List data of all known groups.
     *
     * Creates and returns a list of shared pointers to cJSON data structures that contain
     * the groups' data. The shared pointers have a special deleter that calls @c cJSON_delete
     * to free the data structure.
     *
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @param groups pointer to list which get thew unique JSON data pointers
     * @return SQLite code
     */
    int32_t listAllGroups(list<JsonUnique> &groups);

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
     * @param maxMembers The new value of maximum group members
     * @return SQLite code
     */
    int32_t modifyGroupMaxMembers(const string& groupUuid, int32_t maxMembers);

    /**
     * @brief Get the group's attribute bits.
     *
     * The function reads and returns the group's attribute bits.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return A pair containing the attribute bit and the time the group record was last modified
     */
    pair<int32_t, time_t> getGroupAttribute(const string& groupUuid, int32_t* sqlCode = NULL) const;

    /**
     * @brief Set/add the bits in the attribute mask to the group's attribute bits.
     *
     * The function adds the bits in the attribute mask to the existing group's
     * attribute bits
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param attributeMask Attribute bits to set
     * @return SQLite code
     */
    int32_t setGroupAttribute(const string& groupUuid, int32_t attributeMask);

    /**
     * @brief Clears/removes the bits in the attribute mask from the group's attribute bits.
     *
     * The function remove the bits in the attribute mask from the existing group's
     * attribute bits
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param attributeMask Attribute bits to remove
     * @return SQLite code
     */
    int32_t clearGroupAttribute(const string& groupUuid, int32_t attributeMask);

    /**
     * @brief Set the group's name.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param name The new group name
     * @return SQLite code
     */
    int32_t setGroupName(const string& groupUuid, const string& name);

    /**
     * @brief Set the group's burn timer.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param timeInSeconds burn time in seconds
     * @return SQLite code
     */
    int32_t setGroupBurnTime(const string& groupUuid, int64_t timeInSeconds, int32_t mode);

    /**
     * @brief Set the group's avatar information.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param avatarInfo The avatar information
     * @return SQLite code
     */
    int32_t setGroupAvatarInfo(const string& groupUuid, const string& avatarInfo);

    /**
     * @brief Create a group member
     *
     * Create a new member record. The @c memberUuid must unique.
     * The functions sets the new member's attribute to @c ACTIVE.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the new member's UID
     * @return SQLite code
     */
    int32_t insertMember(const string &groupUuid, const string &memberUuid);

    /**
     * @brief Deletes group record of this member in the specified group.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the member's UID
     * @return SQLite code
     */
    int32_t deleteMember(const string& groupUuid, const string& memberUuid);

    /**
     * @brief Deletes all member records of the group.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @return SQLite code
     */
    int32_t deleteAllMembers(const string &groupUuid);

    /**
     * @brief Get all members of a specified group.
     *
     * Creates and returns a list of shared pointers to cJSON data structures that contain the group's
     * members data. The shared pointers have a special deleter that calls @c cJSON_delete
     * to free the data structure.
     *
     * @deprecated use getAllGroupMembers(const string &groupUuid, list<JsonUnique> *members) instead.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return list of cJSON pointers to cJSON data structure, maybe empty, never @c NULL
     */
    DEPRECATED_ZINA shared_ptr<list<shared_ptr<cJSON> > >getAllGroupMembers(const string &groupUuid, int32_t *sqlCode = NULL);

    /**
     * @brief Get all members of a specified group.
     *
     * Creates and returns a list of unique pointers to cJSON data structures that contain the group's
     * members data. The unique pointers have a special deleter that calls @c cJSON_delete
     * to free the data structure.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param members pointer to a list of unique pointer to JSON
     * @return SQLite code
     */
    int32_t getAllGroupMembers(const string &groupUuid, list<JsonUnique> &members);

    /**
     * @brief Get a member of a specified group.
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
    shared_ptr<cJSON> getGroupMember(const string &groupUuid, const string &memberUuid, int32_t *sqlCode = NULL);


    /**
    * @brief Check if this member is in this group.
    *
    * @param groupUuid The group's UUID (RFC4122 time based UUID)
    * @param memberUuid the new member's UID
    * @param sqlCode If not @c NULL returns the SQLite return/error code
    * @return @c true if the group contains this member, @c false otherwise
    */
    bool isMemberOfGroup(const string &groupUuid, const string &memberUuid, int32_t *sqlCode = NULL);

    /**
    * @brief Check if this member of some group.
    *
    * @param groupUuid The group's UUID (RFC4122 time based UUID)
    * @param memberUuid the new member's UID
    * @param sqlCode If not @c NULL returns the SQLite return/error code
    * @return @c true if the member is in some group, @c false otherwise
    */
    bool isGroupMember(const string &memberUuid, int32_t *sqlCode = NULL);

    /**
     * @brief Get the member's attribute bits.
     *
     * The function reads and returns the member's attribute bits.
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the member's UID
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return A pair containing the attribute bit and the time the member record was last modified
     */
    pair<int32_t, time_t> getMemberAttribute(const string& groupUuid, const string& memberUuid, int32_t* sqlCode = NULL);

    /**
     * @brief Set/add the bits in the attribute mask to the member's attribute bits.
     *
     * The function adds the bits in the attribute mask to the existing member's
     * attribute bits
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the member's UID
     * @param attributeMask Attribute bits to set
     * @return SQLite code
     */
    int32_t setMemberAttribute(const string& groupUuid, const string& memberUuid, int32_t attributeMask);

    /**
     * @brief Clears/removes the bits in the attribute mask from the member's attribute bits.
     *
     * The function remove the bits in the attribute mask from the existing member's
     * attribute bits
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param memberUuid the member's UID
     * @param attributeMask Attribute bits to remove
     * @return SQLite code
     */
    int32_t clearMemberAttribute(const string& groupUuid, const string& memberUuid, int32_t attributeMask);

    /**
     * @brief Compute a SHA-256 hash of all member ids in a group.
     *
     * The function remove the bits in the attribute mask from the existing member's
     * attribute bits. To select to member ids the function uses a SQL select statement
     * similar to:
     *
     * SELECT DISTINCT memberId FROM Members WHERE groupId=groupUuid AND attributes&ACTIVE ORDER BY memberId ASC;
     *
     * @param groupUuid The group's UUID (RFC4122 time based UUID)
     * @param hash Pointer to a buffer of at least 32 bytes which receives the computed hash
     * @return SQLite code
     */
    int32_t memberListHash(const string& groupUuid, uint8_t* hash);

    /*
     * @brief Use for debugging and development only.
     */
    int32_t resetStore() { return createTables(); }

    /* ***************************************************
     * Functions to handle vector clock data
     * ************************************************* */

    /**
     * @brief Insert/update a vector clock record.
     *
     * The table stores vector clocks and groups them by an id and an event type. An id could be
     * unique id such as a UUID according to RFC4122, type 4.
     *
     * The event type is a simple 32-bit integer that defines an event. The event type must be unique
     * inside an id.
     *
     * The vector clock data is a blob, thus the table stores serialized data. When inserting data
     * it's always an INSERT OR REPLACE and the table has only one row per (id, event type) tuple.
     *
     * @param id The identifier of the event group
     * @param type The event type in the group
     * @param vectorClock The vector clock data. The string may serve as a container to hold binary data.
     * @return SQLite code
     */
    int32_t insertReplaceVectorClock(const string &id, int32_t type, const string &vectorClock);

    /**
     * @brief Load the serialized data of a vector clock.
     *
     * @param id The identifier of the event group
     * @param type The event type in the group
     * @param vectorClock Where to store the serialized data, empty string if no record found
     * @return SQLite code
     */
    int32_t loadVectorClock(const string& id, int32_t type, string *vectorClock);

    /**
     * @brief Delete a vector clock record.
     *
     * @param id The identifier of the event group
     * @param type The event type in the group
     * @return SQLite code
     */
    int32_t deleteVectorClock(const string& id, int32_t type);

    /**
     * @brief Delete a group of vector clock records.
     *
     * @param id The identifier of the event group
     * @return SQLite code
     */
    int32_t deleteVectorClocks(const string& id);

    /**
     * @brief Insert a wait-for-ack record.
     *
     * The function stores data for an unacknowledged update. The client stores this data for each device
     * to which it sent an update.
     *
     * @param groupId The group id
     * @param deviceId The device id as used in the update data
     * @param updateId The update id as used in the update data
     * @param updateType The update type
     * @return SQLite code
     */
    int32_t insertWaitAck(const string &groupId, const string &deviceId, const string &updateId, int32_t updateType);

    /**
     * @brief Check if a specific wait-for-ack record exists.
     *
     * @param groupId The group id
     * @param deviceId The device id as used in the update data
     * @param updateId The update id as used in the update data
     * @param updateType The update type
     * @param sqlCode Receives SQL return code if not `nullptr`
     * @return `true` if a record exists
     */
    bool hasWaitAck(const string &groupId, const string &deviceId, const string &updateId, int32_t updateType, int32_t *sqlCode);

    /**
     * @brief Check if a wait-for-ack record exists for the specified group and update id.
     *
     * @param groupId The group id
     * @param updateId The update id as used in the update data
     * @param sqlCode Receives SQL return code if not `nullptr`
     * @return `true` if a record exists
     */
    bool hasWaitAckGroupUpdate(const string &groupId, const string &updateId, int32_t *sqlCode);

    /**
     * @brief Check if a device has pending ACKs for a group
     *
     * @param groupId The group id
     * @param deviceId The device to check
     * @param sqlCode sqlCode Receives SQL return code if not `nullptr`
     * @return `true` if a record exists
     */
    bool hasWaitAckGroupDevice(const string &groupId, const string &deviceId, int32_t *sqlCode);

    /**
     * @brief Remove a specific wait-for-ack record.
     *
     * @param groupId The group id
     * @param deviceId The device id as used in the update data
     * @param updateId The update id as used in the update data
     * @param updateType The update type
     * @return SQLite code
     */
    int32_t removeWaitAck(const string &groupId, const string &deviceId, const string &updateId, int32_t updateType);

    /**
     * @brief Remove a group's wait-for-ack records.
     *
     * @param groupId The group id
     * @return SQLite code
     */
    int32_t removeWaitAckWithGroup(const string &groupId);

    /**
     * @brief Remove wait-for-ack records with an update type.
     *
     * Remove all wait-for-ack records of a device with a specific update type.
     *
     * @param groupId The group id
     * @param deviceId The device id as used in the update data
     * @param updateType The update type
     * @return SQLite code
     */
    int32_t removeWaitAckWithType(const string &groupId, const string &deviceId, int32_t updateType);

    /**
     * @brief Clean wait-for-ack record table - remove old records
     *
     * @param timestamp delete all records older than this timestamp (seconds since the epoch)
     * @return SQLite code
     */
    int32_t cleanWaitAck(time_t timestamp);


    int beginTransaction();
    int commitTransaction();
    int rollbackTransaction();

    int32_t getExtendedErrorCode() const { return extendedErrorCode_; }

private:
    SQLiteStoreConv();
    ~SQLiteStoreConv();

    SQLiteStoreConv(const SQLiteStoreConv& other) = delete;
    SQLiteStoreConv& operator=(const SQLiteStoreConv& other) = delete;
    bool operator==(const SQLiteStoreConv& other) const = delete;

    /**
     * Create ZINA tables in database.
     *
     * openCache calls this function if it cannot find the table zrtpId_own. This indicates
     * that ZINA tables are available in the database.
     */
    int createTables();
    int createVectorClockTables();
    int32_t createGroupTables();
    int32_t createWaitForAckTables();
    int32_t createMessageQueuesTables();

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
    int32_t updateVectorClocksDb(int32_t oldVersion);
    int32_t updateGroupDataDb(int32_t oldVersion);
    int32_t updateWaitForAckDb(int32_t oldVersion);
    int32_t updateMessageQueues(int32_t oldVersion);

    static SQLiteStoreConv* instance_;
    sqlite3* db;
    string* keyData_;

    bool isReady_;

    mutable int32_t sqlCode_;
    mutable int32_t extendedErrorCode_;
    mutable char lastError_[DB_CACHE_ERR_BUFF_SIZE];
};
} // namespace zina

/**
 * @}
 */

#endif // SQLITESTORE_H
