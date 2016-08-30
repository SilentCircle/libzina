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
#include "SQLiteStoreConv.h"

#include <cryptcommon/ZrtpRandom.h>
#include <zrtp/crypto/sha256.h>
#include <zrtp/crypto/sha2.h>

#include "../../interfaceApp/JsonStrings.h"
#include "../../Constants.h"


/* *****************************************************************************
 * A few helping macros. 
 * These macros require some names/patterns in the methods that use these 
 * macros:
 * 
 * ERRMSG requires:
 * - a variable with name "db" is the pointer to sqlite3
 * - a char* with name "lastError" points to a buffer of at least SQL_CACHE_ERR_BUFF_SIZE chars
 *
 * SQLITE_CHK requires:
 * - a cleanup label, the macro goes to that label in case of error
 * - an integer (int) variable with name "sqlResult" that stores return codes from sqlite
 * - ERRMSG
 */
#define ERRMSG  {snprintf(lastError_, (size_t)DB_CACHE_ERR_BUFF_SIZE, \
                          "SQLite3 error: %s, line: %d, error message: %s\n", __FILE__, __LINE__, sqlite3_errmsg(db));}

#define SQLITE_CHK(func) {          \
        sqlResult = (func);          \
        if(sqlResult != SQLITE_OK) { \
            ERRMSG;                 \
            goto cleanup;           \
        }                           \
    }

#define SQLITE_PREPARE sqlite3_prepare_v2

#define DB_VERSION 6

static mutex sqlLock;

static void *(*volatile memset_volatile)(void *, int, size_t) = memset;

static const char *beginTransactionSql  = "BEGIN TRANSACTION;";
static const char *commitTransactionSql = "COMMIT;";
static const char *rollbackTransactionSql = "ROLLBACK TRANSACTION;";


/* *****************************************************************************
 * SQL statements to process the sessions table.
 */
static const char* dropConversations = "DROP TABLE Conversations;";
static const char* createConversations = 
    "CREATE TABLE Conversations ("
    "name VARCHAR NOT NULL, longDevId VARCHAR NOT NULL, ownName VARCHAR NOT NULL, secondName VARCHAR,"
    "flags INTEGER, since TIMESTAMP, data BLOB, checkData BLOB,"
    "PRIMARY KEY(name, longDevId, ownName));";

// Storing Session data for a name/deviceId pair first tries to update. If it succeeds then
// the following INSERT OR IGNORE is a no-op. Otherwise the function INSERT a complete new record:
// - Try to update any existing row
// - Make sure it exists
static const char* updateConversation = "UPDATE Conversations SET data=?1 WHERE name=?2 AND longDevId=?3 AND ownName=?4;";
static const char* insertConversation = "INSERT OR IGNORE INTO Conversations (name, secondName, longDevId, data, ownName) VALUES (?1, ?2, ?3, ?4, ?5);";
static const char* selectConversation = "SELECT data FROM Conversations WHERE name=?1 AND longDevId=?2 AND ownName=?3;";

static const char* selectConvNames = "SELECT DISTINCT name FROM Conversations WHERE ownName=?1 ORDER BY name;";
static const char* selectConvDevices = "SELECT longDevId FROM Conversations WHERE name=?1 AND ownName=?2;";

// Delete a specific sessions
static const char* removeConversation = "DELETE FROM Conversations WHERE name=?1 AND longDevId=?2 AND ownName=?3;";
// Delete all sessions for that name
static const char* removeConversations = "DELETE FROM Conversations WHERE name=?1 AND ownName=?2;";

/* *****************************************************************************
 * SQL statments for the staged message key table
 */
static const char* dropStagedMk = "DROP TABLE stagedMk;";
static const char* createStagedMk = 
    "CREATE TABLE stagedMk (name VARCHAR NOT NULL, longDevId VARCHAR NOT NULL, ownName VARCHAR NOT NULL,"
    "since TIMESTAMP, otherkey BLOB, ivkeymk BLOB, ivkeyhdr BLOB);";

static const char* insertStagedMkSql = 
    "INSERT OR REPLACE INTO stagedMk (name, longDevId, ownName, since, otherkey, ivkeymk, ivkeyhdr) "
    "VALUES(?1, ?2, ?3, strftime('%s', ?4, 'unixepoch'), ?5, ?6, ?7);";

static const char* selectStagedMks = "SELECT ivkeymk FROM stagedMk WHERE name=?1 AND longDevId=?2 AND ownName=?3;";
static const char* removeStagedMk = "DELETE FROM stagedMk WHERE name=?1 AND longDevId=?2 AND ownName=?3 AND ivkeymk=?4;";

static const char* removeStagedMkTime = "DELETE FROM stagedMk WHERE since < ?1;";

static const char* hasStagedMkSql =
        "SELECT NULL, CASE EXISTS (SELECT 0 FROM stagedMk WHERE name=?1 AND longDevId=?2 AND ownName=?3 AND ivkeymk=?4) WHEN 1 THEN 1 ELSE 0 END;";

/* *****************************************************************************
 * SQL statements to process the Pre-key table.
 */
static const char* dropPreKeys = "DROP TABLE PreKeys;";
static const char* createPreKeys = "CREATE TABLE PreKeys (keyid INTEGER NOT NULL PRIMARY KEY, preKeyData BLOB, checkData BLOB);";
static const char* insertPreKey = "INSERT INTO PreKeys (keyId, preKeyData) VALUES (?1, ?2);";
static const char* selectPreKey = "SELECT preKeyData FROM PreKeys WHERE keyid=?1;";
static const char* deletePreKey = "DELETE FROM PreKeys WHERE keyId=?1;";
static const char* selectPreKeyAll = "SELECT keyId, preKeyData FROM PreKeys;";

/* *****************************************************************************
 * SQL statements to process the message hash table.
 */
static const char* dropMsgHash = "DROP TABLE MsgHash;";
static const char* createMsgHash = "CREATE TABLE MsgHash (msgHash BLOB NOT NULL PRIMARY KEY, since TIMESTAMP);";
static const char* insertMsgHashSql = "INSERT INTO MsgHash (msgHash, since) VALUES (?1, strftime('%s', ?2, 'unixepoch'));";
static const char* selectMsgHash = "SELECT msgHash FROM MsgHash WHERE msgHash=?1;";
static const char* removeMsgHash = "DELETE FROM MsgHash WHERE since < ?1;";

/* *****************************************************************************
 * SQL statements to process the message trace/state table.
 *
 * Flags: hold the booleans attachment and received
 */
static const int32_t ATTACHMENT = 1;
static const int32_t RECEIVED   = 2;
static const char* dropMsgTrace = "DROP TABLE MsgTrace;";
static const char* createMsgTrace =
        "CREATE TABLE MsgTrace (name VARCHAR NOT NULL, messageId VARCHAR NOT NULL, deviceId VARCHAR NOT NULL, convstate VARCHAR NOT NULL, "
        "attributes VARCHAR NOT NULL, stored TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%dT%H:%M:%f', 'NOW')), flags INTEGER);";
static const char* insertMsgTraceSql =
        "INSERT INTO MsgTrace (name, messageId, deviceId, convstate, attributes, flags) VALUES (?1, ?2, ?3, ?4, ?5, ?6);";
static const char* selectMsgTraceMsgId =
        "SELECT name, messageId, deviceId, convstate, attributes, STRFTIME('%Y-%m-%dT%H:%M:%f', stored), flags FROM MsgTrace WHERE messageId=?1 ORDER BY ROWID ASC ;";
static const char* selectMsgTraceName =
        "SELECT name, messageId, deviceId, convstate, attributes, STRFTIME('%Y-%m-%dT%H:%M:%f', stored), flags FROM MsgTrace WHERE name=?1 ORDER BY ROWID ASC ;";
static const char* selectMsgTraceDevId =
        "SELECT name, messageId, deviceId, convstate, attributes, STRFTIME('%Y-%m-%dT%H:%M:%f', stored), flags FROM MsgTrace WHERE deviceId=?1 ORDER BY ROWID ASC ;";
static const char* selectMsgTraceMsgDevId =
        "SELECT name, messageId, deviceId, convstate, attributes, STRFTIME('%Y-%m-%dT%H:%M:%f', stored), flags FROM MsgTrace WHERE messageId=?1 AND deviceId=?2 ORDER BY ROWID ASC ;";

// See comment in deleteMsgTrace regarding the not fully qualified SQL statement to remove old trace records.
static const char* removeMsgTrace = "DELETE FROM MsgTrace WHERE STRFTIME('%s', stored)";

/* *****************************************************************************
 * SQL statements to process group chat table
 *
 */
static const char* dropGroups = "DROP TABLE groups;";
static const char* createGroups =
        "CREATE TABLE groups (groupId VARCHAR NOT NULL PRIMARY KEY, name VARCHAR NOT NULL, ownerId VARCHAR NOT NULL, "
        "description VARCHAR, memberCount INTEGER, maxMembers INTEGER, attributes INTEGER, lastModified TIMESTAMP DEFAULT(strftime('%s', 'NOW')));";
static const char* insertGroupsSql =
        "INSERT INTO groups (groupId, name, ownerId, description, maxMembers, memberCount, attributes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);";
static const char* selectAllGroups = "SELECT groupId, name, ownerId, description, maxMembers, memberCount, attributes, lastModified FROM groups;";
static const char* selectGroup = "SELECT groupId, name, ownerId, description, maxMembers, memberCount, attributes, lastModified FROM groups WHERE groupId=?1;";
static const char* updateGroupMaxMember = "UPDATE groups SET maxMembers=?1 WHERE groupId=?2;";
static const char* incrementGroupMemberCount = "UPDATE groups SET memberCount=memberCount+1 WHERE groupId=?1;";
static const char* decrementGroupMemberCount = "UPDATE groups SET memberCount=memberCount-1 WHERE groupId=?1;";
static const char* setGroupMemberCount = "UPDATE groups SET memberCount=?1 WHERE groupId=?2;";
static const char* setGroupAttributeSql = "UPDATE groups SET attributes=attributes|?1, lastModified=?2 WHERE groupId=?3;";
static const char* clearGroupAttributeSql = "UPDATE groups SET attributes=attributes&~?1, lastModified=?2 WHERE groupId=?3;";
static const char* selectGroupAttributeSql = "SELECT attributes, lastModified FROM groups WHERE groupId=?1;";
static const char* removeGroup = "DELETE FROM groups WHERE groupId=?1;";
static const char* hasGroupSql = "SELECT NULL, CASE EXISTS (SELECT 0 FROM groups WHERE groupId=?1) WHEN 1 THEN 1 ELSE 0 END;";

/* *****************************************************************************
 * SQL statements to process group member table
 *
 * The columns 'deviceId' and 'ownName' are available for possible future extensions, currently not used.
 */
static const char* dropMembers = "DROP TABLE members;";
static const char* createMembers =
        "CREATE TABLE members (memberId VARCHAR NOT NULL, groupId VARCHAR NOT NULL, deviceId VARCHAR, ownName VARCHAR, "
        "attributes INTEGER, lastModified TIMESTAMP DEFAULT(strftime('%s', 'NOW')), "
        "PRIMARY KEY(memberId, groupId, deviceId), FOREIGN KEY(groupId) REFERENCES groups(groupId));";
static const char* insertMemberSql = "INSERT INTO members (groupId, memberId, attributes) VALUES (?1, ?2, ?3);";
static const char* removeMember = "DELETE FROM members WHERE groupId=?1 AND memberId=?2;";
static const char* removeAllMembers = "DELETE FROM members WHERE groupId=?1;";
static const char* selectGroupMembers = "SELECT groupId, memberId, attributes, lastModified FROM members WHERE groupId=?1 ORDER BY memberId ASC;";
static const char* selectMember =
        "SELECT groupId, memberId, attributes, lastModified FROM members WHERE groupId=?1 AND memberId=?2 ORDER BY memberId ASC;";
static const char* setMemberAttributeSql = "UPDATE members SET attributes=attributes|?1, lastModified=?2 WHERE groupId=?3 AND memberId=?4;";
static const char* clearMemberAttributeSql = "UPDATE members SET attributes=attributes&~?1, lastModified=?2  WHERE groupId=?3 AND memberId=?4;";
static const char* selectMemberAttributeSql = "SELECT attributes, lastModified FROM members WHERE groupId=?1 AND memberId=?2;";
static const char* selectForHash = "SELECT DISTINCT memberId FROM members WHERE groupId=?1 AND attributes&?2 ORDER BY memberId ASC;";
static const char* isMemberOfGroupSql = "SELECT NULL, CASE EXISTS (SELECT 0 FROM members WHERE groupId=?1 AND memberId=?2) WHEN 1 THEN 1 ELSE 0 END;";
static const char* isGroupMemberSql = "SELECT NULL, CASE EXISTS (SELECT 0 FROM members WHERE memberId=?1) WHEN 1 THEN 1 ELSE 0 END;";

/* *****************************************************************************
 * SQL statements to process received raw, encrypted message data
 *
 * Regarding the use of 'AUTOINCREMENT' refer to sqlite documentation: https://www.sqlite.org/autoinc.html
 * It actually guarantees a monotonically increasing sequence number which is important because we like
 * to process messages in order we received them.
 */
static const char* dropReceivedRaw = "DROP TABLE receivedRaw;";
static const char* createReceivedRaw =
        "CREATE TABLE IF NOT EXISTS receivedRaw (sequence INTEGER PRIMARY KEY AUTOINCREMENT, rawData BLOB NOT NULL, "
                "uid VARCHAR, displayName VARCHAR, inserted TIMESTAMP DEFAULT(strftime('%s', 'NOW')));";
static const char* insertReceivedRawSql = "INSERT INTO receivedRaw (rawData, uid, displayName) VALUES (?1, ?2, ?3);";
static const char* selectReceivedRaw = "SELECT sequence, rawData, uid, displayName FROM receivedRaw ORDER BY sequence ASC;";
static const char* removeReceivedRaw = "DELETE FROM receivedRaw WHERE sequence=?1;";
static const char* cleanReceivedRaw = "DELETE FROM receivedRaw WHERE inserted < ?1;";

/* *****************************************************************************
 * SQL statements to process temporarily stored received message data
 *
 */
static const char* dropTempMsg = "DROP TABLE TempMsg;";
static const char* createTempMsg =
        "CREATE TABLE IF NOT EXISTS TempMsg (sequence INTEGER PRIMARY KEY AUTOINCREMENT, messageData VARCHAR NOT NULL, "
                "supplementData VARCHAR, msgType INTEGER, inserted TIMESTAMP DEFAULT(strftime('%s', 'NOW')));";
static const char* insertTempMsgSql = "INSERT INTO TempMsg (messageData, supplementData, msgType) VALUES (?1, ?2, ?3);";
static const char* selectTempMsg = "SELECT sequence, messageData, supplementData, msgType FROM TempMsg ORDER BY sequence ASC;";
static const char* removeTempMsg = "DELETE FROM TempMsg WHERE sequence=?1;";
static const char* cleanTempMsgSql = "DELETE FROM TempMsg WHERE inserted < ?1;";

#ifdef UNITTESTS
// Used in testing and debugging to do in-depth checks
static void hexdump(const char* title, const unsigned char *s, size_t l) {
    size_t n = 0;

    if (s == NULL) return;

    fprintf(stderr, "%s",title);
    for( ; n < l ; ++n)
    {
        if((n%16) == 0)
            fprintf(stderr, "\n%04x", static_cast<int>(n));
        fprintf(stderr, " %02x",s[n]);
    }
    fprintf(stderr, "\n");
}
static void hexdump(const char* title, const std::string& in)
{
    hexdump(title, (uint8_t*)in.data(), in.size());
}
#endif

using namespace axolotl;

void Log(const char* format, ...);

static int32_t getUserVersion(sqlite3* db)
{
    sqlite3_stmt *stmt;

    sqlite3_prepare(db, "PRAGMA user_version", -1, &stmt, NULL);
    int32_t rc = sqlite3_step(stmt);

    int32_t version = 0;
    if (rc == SQLITE_ROW) {
        version = sqlite3_column_int(stmt,  0);
    }
    sqlite3_finalize(stmt);
    return version;
}

static int32_t setUserVersion(sqlite3* db, int32_t newVersion)
{
    sqlite3_stmt *stmt;

    char statement[100];
    snprintf(statement, 90, "PRAGMA user_version = %d", newVersion);

    sqlite3_prepare(db, statement, -1, &stmt, NULL);
    int32_t rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

   return rc;
}

SQLiteStoreConv* SQLiteStoreConv::instance_ = NULL;

SQLiteStoreConv* SQLiteStoreConv::getStore()
{
    unique_lock<mutex> lck(sqlLock);
    if (instance_ == NULL)
        instance_ = new SQLiteStoreConv();
    lck.unlock();
    return instance_;
}

SQLiteStoreConv::SQLiteStoreConv() : db(NULL), keyData_(NULL), isReady_(false) {}

SQLiteStoreConv::~SQLiteStoreConv()
{
    sqlite3_close(db);
    db = NULL;
    delete keyData_; keyData_ = NULL;
}

int SQLiteStoreConv::beginTransaction()
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    SQLITE_CHK(SQLITE_PREPARE(db, beginTransactionSql, -1, &stmt, NULL));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    return sqlResult;
}

int SQLiteStoreConv::commitTransaction()
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    SQLITE_CHK(SQLITE_PREPARE(db, commitTransactionSql, -1, &stmt, NULL));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    return sqlResult;
}

int SQLiteStoreConv::rollbackTransaction()
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    SQLITE_CHK(SQLITE_PREPARE(db, rollbackTransactionSql, -1, &stmt, NULL));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    return sqlResult;
}

static int32_t enableForeignKeys(sqlite3* db)
{
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, "PRAGMA foreign_keys=ON;", -1, &stmt, NULL);
    int32_t rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc;
}

/*
 * SQLite uses the following table structure to manage some internal data
 *
 * CREATE TABLE sqlite_master (
 *   type TEXT,
 *   name TEXT,
 *   tbl_name TEXT,
 *   rootpage INTEGER,
 *   sql TEXT
 * );
 */
int SQLiteStoreConv::openStore(const std::string& name)
{
    LOGGER(INFO, __func__ , " -->");
    if (keyData_ == NULL) {
        LOGGER(ERROR, __func__ , " No password defined.");
        return -1;
    }
    unique_lock<mutex> lck(sqlLock);
    // Don't try to open twice
    if (isReady_)
        return SQLITE_CANTOPEN;

    // If name has size 0 then open im-memory DB, handy for testing
    const char *dbName = name.size() == 0 ? ":memory:" : name.c_str();
    sqlCode_ = sqlite3_open_v2(dbName, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);

    if (sqlCode_) {
        ERRMSG;
        LOGGER(ERROR, __func__, " Failed to open database: ", sqlCode_, ", ", lastError_);
        return(sqlCode_);
    }
    sqlite3_key(db, keyData_->data(), static_cast<int>(keyData_->size()));

    memset_volatile((void*)keyData_->data(), 0, keyData_->size());
    delete keyData_; keyData_ = NULL;

    enableForeignKeys(db);

    int32_t version = getUserVersion(db);
    if (version != 0) {
        beginTransaction();
        if (updateDb(version, DB_VERSION) != SQLITE_OK) {
            sqlite3_close(db);
            LOGGER(ERROR, __func__ , " <-- update failed, existing version: ", version);
            return SQLITE_ERROR;
        }
        commitTransaction();
    }
    else {
        if (createTables() != SQLITE_OK) {
            sqlite3_close(db);
            LOGGER(ERROR, __func__ , " <-- table creation failed.");
            return sqlCode_;
        }
    }
    setUserVersion(db, DB_VERSION);

    isReady_ = true;
    lck.unlock();
    LOGGER(INFO, __func__ , " <-- ");
    return SQLITE_OK;
}


int SQLiteStoreConv::createTables()
{
    LOGGER(INFO, __func__ , " -->");
    sqlite3_stmt* stmt;
    int32_t sqlResult;

    /* First drop them, just to be on the save side
     * Ignore errors, there is nothing to drop on empty DB. If ZrtpIdOwn was
     * deleted using DB admin command then we need to drop the remote id table
     * and names also to have a clean state.
     */

    SQLITE_PREPARE(db, dropConversations, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createConversations, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    SQLITE_PREPARE(db, dropStagedMk, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createStagedMk, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    SQLITE_PREPARE(db, dropPreKeys, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createPreKeys, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    SQLITE_PREPARE(db, dropMsgHash, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createMsgHash, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    SQLITE_PREPARE(db, dropMsgTrace, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createMsgTrace, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    SQLITE_PREPARE(db, dropGroups, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createGroups, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    SQLITE_PREPARE(db, dropMembers, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createMembers, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    SQLITE_PREPARE(db, dropReceivedRaw, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createReceivedRaw, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    SQLITE_PREPARE(db, dropTempMsg, -1, &stmt, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    SQLITE_CHK(SQLITE_PREPARE(db, createTempMsg, -1, &stmt, NULL));
    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
        goto cleanup;
    }
    sqlite3_finalize(stmt);

    LOGGER(INFO, __func__ , " <-- ", sqlResult);
    return SQLITE_OK;

 cleanup:
    sqlite3_finalize(stmt);
    LOGGER(ERROR, __func__, ", SQL error: ", sqlResult, ", ", lastError_);
    return sqlResult;
}

/* *****************************************************************************
 * The SQLite master table.
 *
 * Used to check if we have valid message hash table.
 */
static const char *lookupTables = "SELECT name FROM sqlite_master WHERE type='table' AND name='MsgHash';";

int32_t SQLiteStoreConv::updateDb(int32_t oldVersion, int32_t newVersion) {
    sqlite3_stmt *stmt;

    LOGGER(INFO, __func__, " -->");

    // Version 2 adds the message hash table
    if (oldVersion == 1) {
        // check if MsgHash table is already available
        SQLITE_PREPARE(db, lookupTables, -1, &stmt, NULL);
        int32_t rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // If not then create it
        if (rc != SQLITE_ROW) {
            sqlCode_ = SQLITE_PREPARE(db, createMsgHash, -1, &stmt, NULL);
            sqlCode_ = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            if (sqlCode_ != SQLITE_DONE) {
                LOGGER(ERROR, __func__, ", SQL error adding hash table: ", sqlCode_);
                return sqlCode_;
            }
        }
        oldVersion = 2;
    }

    // Version 3 adds the message trace table
    const char* traceTable =
            "CREATE TABLE MsgTrace (name VARCHAR NOT NULL, messageId VARCHAR NOT NULL, deviceId VARCHAR NOT NULL, "
                    "attributes VARCHAR NOT NULL, stored TIMESTAMP DEFAULT(STRFTIME('%Y-%m-%dT%H:%M:%f', 'NOW')), flags INTEGER);";

    if (oldVersion == 2) {
        SQLITE_PREPARE(db, traceTable, -1, &stmt, NULL);
        sqlCode_ = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (sqlCode_ != SQLITE_DONE) {
            LOGGER(ERROR, __func__, ", SQL error adding trace table: ", sqlCode_);
            return sqlCode_;
        }
        oldVersion = 3;
    }

    // Version 4 adds the conversation state column to the trace table
    if (oldVersion == 3) {
        SQLITE_PREPARE(db, "ALTER TABLE MsgTrace ADD COLUMN convstate VARCHAR;", -1, &stmt, NULL);
        sqlCode_ = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (sqlCode_ != SQLITE_DONE) {
            LOGGER(ERROR, __func__, ", SQL error adding convstate column: ", sqlCode_);
            return sqlCode_;
        }
        oldVersion = 4;
    }

    if (oldVersion == 4) {
        SQLITE_PREPARE(db, createGroups, -1, &stmt, NULL);
        sqlCode_ = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (sqlCode_ != SQLITE_DONE) {
            LOGGER(ERROR, __func__, ", SQL error adding groups table: ", sqlCode_);
            return sqlCode_;
        }
        SQLITE_PREPARE(db, createMembers, -1, &stmt, NULL);
        sqlCode_ = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (sqlCode_ != SQLITE_DONE) {
            LOGGER(ERROR, __func__, ", SQL error adding members table: ", sqlCode_);
            return sqlCode_;
        }
        oldVersion = 5;
    }

    if (oldVersion == 5) {
        SQLITE_PREPARE(db, createReceivedRaw, -1, &stmt, NULL);
        sqlCode_ = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (sqlCode_ != SQLITE_DONE) {
            LOGGER(ERROR, __func__, ", SQL error adding receive raw table: ", sqlCode_);
            return sqlCode_;
        }

        SQLITE_PREPARE(db, createTempMsg, -1, &stmt, NULL);
        sqlCode_ = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (sqlCode_ != SQLITE_DONE) {
            LOGGER(ERROR, __func__, ", SQL error adding temporary message table: ", sqlCode_);
            return sqlCode_;
        }
        oldVersion = 6;
    }
    if (oldVersion != newVersion) {
        LOGGER(ERROR, __func__, ", Version numbers mismatch");
        return SQLITE_ERROR;
    }
    LOGGER(INFO, __func__ , " <-- ", sqlCode_);
    return SQLITE_OK;
}


// If the result is a BLOB or UTF-8 string then the sqlite3_column_bytes() routine returns the number of bytes in that BLOB or string.
const static char* dummyId = "__DUMMY__";


shared_ptr<list<string> > SQLiteStoreConv::getKnownConversations(const string& ownName, int32_t* sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t nameLen;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");
    shared_ptr<list<string> > names = make_shared<list<string> >();

    // selectConvNames = "SELECT name FROM Conversations WHERE ownName=?1 ORDER BY name;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectConvNames, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));

    while ((sqlResult = sqlite3_step(stmt)) == SQLITE_ROW) {
        nameLen = sqlite3_column_bytes(stmt, 0);
        string name((const char*)sqlite3_column_text(stmt, 0), static_cast<size_t>(nameLen));
        names->push_back(name);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return names;

}

shared_ptr<list<string> > SQLiteStoreConv::getLongDeviceIds(const string& name, const string& ownName, int32_t* sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t idLen;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");
    shared_ptr<list<string> > devIds = make_shared<list<string> >();

    // selectConvDevices = "SELECT longDevId FROM Conversations WHERE name=?1 AND ownName=?2;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectConvDevices, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));

    while ((sqlResult = sqlite3_step(stmt)) == SQLITE_ROW) {
        idLen = sqlite3_column_bytes(stmt, 0);
        string id((const char*)sqlite3_column_text(stmt, 0), static_cast<size_t>(idLen));
        if (id.compare(0, id.size(), dummyId, id.size()) == 0)
            continue;
        devIds->push_back(id);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return devIds;
}


// ***** Session store
string* SQLiteStoreConv::loadConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode) const
{ 
    sqlite3_stmt *stmt;
    int32_t len;
    string* data = NULL;
    int32_t sqlResult;

    const char* devId;
    int32_t devIdLen;

    LOGGER(INFO, __func__, " -->");
    if (longDevId.size() > 0) {
        devId = longDevId.c_str();
        devIdLen = static_cast<int32_t>(longDevId.size());
    }
    else {
        devId = dummyId;
        devIdLen = static_cast<int32_t>(strlen(dummyId));
    }

    // selectConversation = "SELECT sessionData FROM Conversations WHERE name=?1 AND longDevId=?2 AND ownName=?3;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectConversation, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, devId, devIdLen, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));

    sqlResult = sqlite3_step(stmt);
    ERRMSG;
    if (sqlResult == SQLITE_ROW) {        // session found, return session record
        // Get the session data
        LOGGER(DEBUGGING, __func__, " Conversation session found");
        len = sqlite3_column_bytes(stmt, 0);
        data = new string((const char*)sqlite3_column_blob(stmt, 0), len);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return data;
}

void SQLiteStoreConv::storeConversation(const string& name, const string& longDevId, const string& ownName, const string& data, int32_t* sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    const char* devId;
    int32_t devIdLen;

    LOGGER(INFO, __func__, " -->");
    if (longDevId.size() > 0) {
        devId = longDevId.c_str();
        devIdLen = static_cast<int32_t>(longDevId.size());
    }
    else {
        devId = dummyId;
        devIdLen = static_cast<int32_t>(strlen(dummyId));
    }
    // Lock the DB in this case because it's a two-step procedure where we use
    // some data from the shared DB pointer (sqlite3_changes(db))
    // Also protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);

    // updateConversation = "UPDATE Conversations SET data=?1, WHERE name=?2 AND longDevId=?3 AND ownName=?4;";
    SQLITE_CHK(SQLITE_PREPARE(db, updateConversation, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_blob(stmt, 1, data.data(), static_cast<int32_t>(data.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, devId, devIdLen, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 4, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));

    beginTransaction();
    sqlResult = sqlite3_step(stmt);
    ERRMSG;
    sqlite3_finalize(stmt);
    stmt = NULL;

    if (!SQL_FAIL(sqlResult) && sqlite3_changes(db) <= 0) {
        // insertConversation = "INSERT OR IGNORE INTO Conversations (name, secondName, longDevId, data, ownName) VALUES (?1, ?2, ?3, ?4, ?5);";
        SQLITE_CHK(SQLITE_PREPARE(db, insertConversation, -1, &stmt, NULL));
        SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
        SQLITE_CHK(sqlite3_bind_null(stmt, 2));
        SQLITE_CHK(sqlite3_bind_text(stmt, 3, devId, devIdLen, SQLITE_STATIC));
        SQLITE_CHK(sqlite3_bind_blob(stmt, 4, data.data(), static_cast<int32_t>(data.size()), SQLITE_STATIC));
        SQLITE_CHK(sqlite3_bind_text(stmt, 5, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));
        sqlResult = sqlite3_step(stmt);
        ERRMSG;
    }
    if (!SQL_FAIL(sqlResult)) {
        commitTransaction();
    }
    else {
        LOGGER(ERROR, __func__, " Store conversation failed, rolling back transaction");
        rollbackTransaction();
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    lck.unlock();
    LOGGER(INFO, __func__, " <-- ", sqlResult);
}

bool SQLiteStoreConv::hasConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode) const 
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    bool retVal = false;

    const char* devId;
    int32_t devIdLen;

    LOGGER(INFO, __func__, " -->");
    if (longDevId.size() > 0) {
        devId = longDevId.c_str();
        devIdLen = static_cast<int32_t>(longDevId.size());
    }
    else {
        devId = dummyId;
        devIdLen = static_cast<int32_t>(strlen(dummyId));
    }
    // selectConversation = "SELECT iv, data FROM Conversations WHERE name=?1 AND longDevId=?2 AND ownName=?3;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectConversation, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, devId, devIdLen, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));

    sqlResult = sqlite3_step(stmt);
    ERRMSG;
    retVal = sqlResult == SQLITE_ROW;
    LOGGER(DEBUGGING, __func__, " Found conversation: ", retVal);

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return retVal;
}

void SQLiteStoreConv::deleteConversation(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode)
{
    sqlite3_stmt *stmt = NULL;
    int32_t sqlResult;

    const char* devId;
    int32_t devIdLen;

    LOGGER(INFO, __func__, " -->");
    if (longDevId.size() > 0) {
        devId = longDevId.c_str();
        devIdLen = static_cast<int32_t>(longDevId.size());
    }
    else {
        devId = dummyId;
        devIdLen = static_cast<int32_t>(strlen(dummyId));
    }
    if (isGroupMember(name)) {
        sqlResult = SQLITE_CONSTRAINT;
        goto cleanup;
    }

    //removeConversation = "DELETE FROM Conversations WHERE name=?1 AND longDevId=?2 AND ownName=?3;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeConversation, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, devId, devIdLen, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
}

void SQLiteStoreConv::deleteConversationsName(const string& name, const string& ownName, int32_t* sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");
    // removeConversations = "DELETE FROM Conversations WHERE name=?1 AND ownName=?2;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeConversations, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
}

shared_ptr<list<string> > SQLiteStoreConv::loadStagedMks(const string& name, const string& longDevId, const string& ownName, int32_t* sqlCode) const
{
    sqlite3_stmt *stmt;
    int32_t len;
    int32_t sqlResult;
    shared_ptr<list<string> > keys = make_shared<list<string> >();

    const char* devId;
    int32_t devIdLen;

    LOGGER(INFO, __func__, " -->");
    if (longDevId.size() > 0) {
        devId = longDevId.c_str();
        devIdLen = static_cast<int32_t>(longDevId.size());
    }
    else {
        devId = dummyId;
        devIdLen = static_cast<int32_t>(strlen(dummyId));
    }
    // selectStagedMks = "SELECT ivkeymk FROM stagedMk WHERE name=?1 AND longDevId=?2 AND ownName=?3;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectStagedMks, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, devId, devIdLen, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    ERRMSG;

    while (sqlResult == SQLITE_ROW) {
        // Get the MK and its iv
        len = sqlite3_column_bytes(stmt, 0);
        if (len > 0) {
            string mkivenc((const char *) sqlite3_column_blob(stmt, 0), static_cast<size_t>(len));
            keys->push_back(mkivenc);
        }
        sqlResult = sqlite3_step(stmt);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return keys;
}

static bool hasStagedMk(sqlite3* db, const string& name, const string& longDevId, const string& ownName, const string& MKiv)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    int32_t exists = 0;

    // char* hasStagedMkSql = "SELECT NULL, CASE EXISTS (SELECT 0 FROM stagedMk WHERE name=?1 AND longDevId=?2 AND ownName=?3 AND ivkeymk=?4) WHEN 1 THEN 1 ELSE 0 END;";
    SQLITE_PREPARE(db, hasStagedMkSql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt,  1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt,  2, longDevId.data(), static_cast<int32_t>(longDevId.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt,  3, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt,  4, MKiv.data(), static_cast<int32_t>(MKiv.size()), SQLITE_STATIC);

    sqlResult = sqlite3_step(stmt);

    if (sqlResult == SQLITE_ROW) {
        exists = sqlite3_column_int(stmt, 1);
    }
    else
        LOGGER(INFO, __func__, " SQL error: ", sqlResult);


    sqlite3_finalize(stmt);
    LOGGER(INFO, __func__, " <-- ", exists);
    return exists == 1;
}

void SQLiteStoreConv::insertStagedMk(const string& name, const string& longDevId, const string& ownName, const string& MKiv, int32_t* sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult = SQLITE_OK;

    const char* devId;
    int32_t devIdLen;

    LOGGER(INFO, __func__, " -->");
    if (longDevId.size() > 0) {
        devId = longDevId.c_str();
        devIdLen = static_cast<int32_t>(longDevId.size());
    }
    else {
        devId = dummyId;
        devIdLen = static_cast<int32_t>(strlen(dummyId));
    }

    if (hasStagedMk(db, name, string(devId), ownName, MKiv)) {
        if (sqlCode != NULL)
            *sqlCode = sqlResult;
        sqlCode_ = sqlResult;
        LOGGER(INFO, __func__, " <-- MK exists in DB, skip");
        return;
    }

    // Protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);
//     insertStagedMkSql =
//     "INSERT OR REPLACE INTO stagedMk (name, longDevId, ownName, since, otherkey, ivkeymk, ivkeyhdr) "
//     "VALUES(?1, ?2, ?3, strftime('%s', ?4, 'unixepoch'), ?5, ?6, ?7);";
    SQLITE_CHK(SQLITE_PREPARE(db, insertStagedMkSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt,  1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt,  2, devId, devIdLen, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt,  3, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int64(stmt, 4, time(0)));
    SQLITE_CHK(sqlite3_bind_null(stmt,  5));
    SQLITE_CHK(sqlite3_bind_blob(stmt,  6, MKiv.data(), static_cast<int32_t>(MKiv.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_null(stmt,  7));

    sqlResult = sqlite3_step(stmt);
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
}

void SQLiteStoreConv::deleteStagedMk(const string& name, const string& longDevId, const string& ownName, const string& MKiv, int32_t* sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    const char* devId;
    int32_t devIdLen;

    LOGGER(INFO, __func__, " -->");
    if (longDevId.size() > 0) {
        devId = longDevId.c_str();
        devIdLen = static_cast<int32_t>(longDevId.size());
    }
    else {
        devId = dummyId;
        devIdLen = static_cast<int32_t>(strlen(dummyId));
    }
    // removeStagedMk = "DELETE FROM stagedMk WHERE name=?1 AND longDevId=?2 AND ownName=?3 AND ivkeymk=?4;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeStagedMk, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, devId, devIdLen, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, ownName.data(), static_cast<int32_t>(ownName.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_blob(stmt, 4, MKiv.data(), static_cast<int32_t>(MKiv.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
}

void SQLiteStoreConv::deleteStagedMk(time_t timestamp, int32_t* sqlCode)
{
    sqlite3_stmt *stmt;
//    int32_t cleaned;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");
    // removeStagedMkTime = "DELETE FROM stagedMk WHERE since < ?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeStagedMkTime, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int64(stmt, 1, timestamp));

    sqlResult= sqlite3_step(stmt);
//    cleaned = sqlite3_changes(db);
//    LOGGER(ERROR, "Number of removed old MK: ", cleaned);
    ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
}

// ******** PreKey store
string* SQLiteStoreConv::loadPreKey(int32_t preKeyId, int32_t* sqlCode) const 
{
    sqlite3_stmt *stmt;
    int32_t len;
    string* preKeyData = NULL;
    int32_t sqlResult;

    // selectPreKey = "SELECT preKeyData FROM PreKeys WHERE keyid=?1;";

    // SELECT iv, preKeyData FROM PreKeys WHERE keyid=?1 ;
    LOGGER(INFO, __func__, " -->");
    SQLITE_CHK(SQLITE_PREPARE(db, selectPreKey, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt, 1, preKeyId));

    sqlResult= sqlite3_step(stmt);
    ERRMSG;
    if (sqlResult == SQLITE_ROW) {        // No such pre key
        // Get the pre key data
        len = sqlite3_column_bytes(stmt, 0);
        preKeyData = new string((const char*)sqlite3_column_blob(stmt, 0), len);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return preKeyData;
}

void SQLiteStoreConv::storePreKey(int32_t preKeyId, const string& preKeyData, int32_t* sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // insertPreKey = "INSERT INTO PreKeys (keyId, preKeyData) VALUES (?1, ?2);";
    LOGGER(INFO, __func__, " -->");

    // Protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);
    SQLITE_CHK(SQLITE_PREPARE(db, insertPreKey, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt, 1, preKeyId));
    SQLITE_CHK(sqlite3_bind_blob(stmt, 2, preKeyData.data(), static_cast<int32_t>(preKeyData.size()), SQLITE_STATIC));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
}

bool SQLiteStoreConv::containsPreKey(int32_t preKeyId, int32_t* sqlCode) const
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    bool retVal = false;

    LOGGER(INFO, __func__, " -->");

    // SELECT preKeyData FROM PreKeys WHERE keyid=?1 ;
    SQLITE_CHK(SQLITE_PREPARE(db, selectPreKey, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt, 1, preKeyId));

    sqlResult= sqlite3_step(stmt);
    ERRMSG;
    retVal = (sqlResult == SQLITE_ROW);
    LOGGER(DEBUGGING, __func__, " Found preKey: ", retVal);

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return retVal;
}

void SQLiteStoreConv::removePreKey(int32_t preKeyId, int32_t* sqlCode) 
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // DELETE FROM PreKeys WHERE keyId=?1
    SQLITE_CHK(SQLITE_PREPARE(db, deletePreKey, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt, 1, preKeyId));

    sqlResult = sqlite3_step(stmt);
    ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <--", sqlResult);
}

void SQLiteStoreConv::dumpPreKeys() const
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    //  selectPreKeyAll = "SELECT keyId, preKeyData FROM PreKeys;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectPreKeyAll, -1, &stmt, NULL));

    while ((sqlResult = sqlite3_step(stmt)) == SQLITE_ROW) {
        sqlite3_column_int(stmt, 0);
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
}

// ***** Message hash / time table to detect duplicate message from server

int32_t SQLiteStoreConv::insertMsgHash(const string& msgHash)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // Protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);

    // char* insertMsgHashSql = "INSERT INTO MsgHash (msgHash, since) VALUES (?1, strftime('%s', ?2, 'unixepoch'));";
    SQLITE_CHK(SQLITE_PREPARE(db, insertMsgHashSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_blob(stmt,  1, msgHash.data(), static_cast<int32_t>(msgHash.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int64(stmt, 2, time(0)));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::hasMsgHash(const string& msgHash)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // char* selectMsgHash = "SELECT msgHash FROM MsgHash WHERE msgHash=?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectMsgHash, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_blob(stmt, 1, msgHash.data(), static_cast<int32_t>(msgHash.size()), SQLITE_STATIC));

    sqlResult = sqlite3_step(stmt);

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::deleteMsgHashes(time_t timestamp)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // char* removeMsgHash = "DELETE FROM MsgHash WHERE since < ?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeMsgHash, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int64(stmt, 1, timestamp));

    sqlResult= sqlite3_step(stmt);
//    cleaned = sqlite3_changes(db);
//    Log("Number of removed old MK: %d", cleaned);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::insertMsgTrace(const string &name, const string &messageId, const string &deviceId,
                                        const string& convState, const string &attributes, bool attachment, bool received)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    int32_t flag = attachment ? ATTACHMENT : 0;
    flag = received ? flag | RECEIVED : flag;
    // Protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);

    // char* insertMsgTraceSql = "INSERT INTO MsgTrace (name, messageId, deviceId, convstate, attributes, flags) VALUES (?1, ?2, ?3, ?4, ?5);";
    SQLITE_CHK(SQLITE_PREPARE(db, insertMsgTraceSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, messageId.data(), static_cast<int32_t>(messageId.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, deviceId.data(), static_cast<int32_t>(deviceId.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 4, convState.data(), static_cast<int32_t>(convState.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 5, attributes.data(), static_cast<int32_t>(attributes.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int(stmt,  6, flag));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

shared_ptr<list<string> > SQLiteStoreConv::loadMsgTrace(const string &name, const string &messageId, const string &deviceId, int32_t* sqlCode)
{
    sqlite3_stmt *stmt = NULL;
    int32_t sqlResult;
    shared_ptr<list<string> > traceRecords = make_shared<list<string> >();

    LOGGER(INFO, __func__, " -->");

    int32_t selection = 0;
    if (!messageId.empty() && !deviceId.empty())
        selection = 1;
    else if (!name.empty())
        selection = 2;
    else if (!messageId.empty())
        selection = 3;
    else if (!deviceId.empty())
        selection = 4;

    switch (selection) {
        case 1:
            // char* selectMsgTraceMsgDevId =
            //"SELECT name, messageId, deviceId, convstate, attributes, STRFTIME('%Y-%m-%dT%H:%M:%f', stored), flags FROM MsgTrace WHERE messageId=?1 AND deviceId=?2 ORDER BY ROWID ASC ;";
            SQLITE_CHK(SQLITE_PREPARE(db, selectMsgTraceMsgDevId, -1, &stmt, NULL));
            SQLITE_CHK(sqlite3_bind_text(stmt, 1, messageId.data(), static_cast<int32_t>(messageId.size()), SQLITE_STATIC));
            SQLITE_CHK(sqlite3_bind_text(stmt, 2, deviceId.data(), static_cast<int32_t>(deviceId.size()), SQLITE_STATIC));
            break;
        case 2:
            // char* selectMsgTraceName =
            //      "SELECT name, messageId, deviceId, convstate, attributes, STRFTIME('%Y-%m-%dT%H:%M:%f', stored), flags FROM MsgTrace WHERE name=?1 ORDER BY ROWID ASC ;";
            SQLITE_CHK(SQLITE_PREPARE(db, selectMsgTraceName, -1, &stmt, NULL));
            SQLITE_CHK(sqlite3_bind_text(stmt, 1, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
            break;
        case 3:
            // char* selectMsgTraceMsgId =
            //     "SELECT name, messageId, deviceId, convstate, attributes, STRFTIME('%Y-%m-%dT%H:%M:%f', stored), flags FROM MsgTrace WHERE messageId=?1 ORDER BY ROWID ASC ;";
            SQLITE_CHK(SQLITE_PREPARE(db, selectMsgTraceMsgId, -1, &stmt, NULL));
            SQLITE_CHK(sqlite3_bind_text(stmt, 1, messageId.data(), static_cast<int32_t>(messageId.size()), SQLITE_STATIC));
            break;
        case 4:
            // char* selectMsgTraceDevId =
            //     "SELECT name, messageId, deviceId, convstate, attributes, STRFTIME('%Y-%m-%dT%H:%M:%f', stored), flags FROM MsgTrace WHERE deviceId=?1 ORDER BY ROWID ASC ;";
            SQLITE_CHK(SQLITE_PREPARE(db, selectMsgTraceDevId, -1, &stmt, NULL));
            SQLITE_CHK(sqlite3_bind_text(stmt, 1, deviceId.data(), static_cast<int32_t>(deviceId.size()), SQLITE_STATIC));
            break;
        default:
            sqlResult = SQLITE_ERROR;
            goto cleanup;
            break;
    }

    sqlResult= sqlite3_step(stmt);
    ERRMSG;
    if (sqlResult != SQLITE_ROW) {        // No stored records for this selection
        LOGGER(INFO, __func__, " <-- No message trace records for: ", name, messageId, deviceId);
        goto cleanup;
    }
    while (sqlResult == SQLITE_ROW) {
        // Get trace fields and create a JSON formatted string
        cJSON* root = cJSON_CreateObject();
        // name is usually the SC UID string
        cJSON_AddStringToObject(root, "name", (const char*)sqlite3_column_text(stmt, 0));
        cJSON_AddStringToObject(root, "msgId", (const char*)sqlite3_column_text(stmt, 1));
        cJSON_AddStringToObject(root, "devId", (const char*)sqlite3_column_text(stmt, 2));
        cJSON_AddStringToObject(root, "state", (const char*)sqlite3_column_text(stmt, 3));
        cJSON_AddStringToObject(root, "attr", (const char*)sqlite3_column_text(stmt, 4));
        cJSON_AddStringToObject(root, "time", (const char*)sqlite3_column_text(stmt, 5));

        int32_t flag = sqlite3_column_int(stmt, 6);
        cJSON_AddNumberToObject(root, "received", ((flag & RECEIVED) == RECEIVED) ? 1 : 0);
        cJSON_AddNumberToObject(root, "attachment", ((flag & ATTACHMENT) == ATTACHMENT) ? 1 : 0);

        char *out = cJSON_PrintUnformatted(root);
        string traceRecord(out);
        cJSON_Delete(root); free(out);
        traceRecords->push_back(traceRecord);
        LOGGER(INFO, __func__, " record : ", traceRecord);

        sqlResult = sqlite3_step(stmt);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);

    return traceRecords;
}


int32_t SQLiteStoreConv::deleteMsgTrace(time_t timestamp)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    int cleaned;

    LOGGER(INFO, __func__, " -->");

    // Bind with two strftime functions and compar them with < doesn't seem to work. Thus
    // we use the trick and compile the full SQL statement as string and then prepare it.
    // This is also required because for the trace records we strote the timestamp in ISO
    // format with fractions of a second to get a more precise timestamp. Otherwise we would
    // have a timestamp with a precision of a full second. To remove old trace records it's
    // OK to use a second based timestamp.

    // char* removeMsgTrace = "DELETE FROM MsgTrace WHERE STRFTIME('%s', stored)";
    char strfTime[400];
    snprintf(strfTime, sizeof(strfTime)-1, "%s < strftime('%%s', %ld, 'unixepoch');", removeMsgTrace, timestamp);

    SQLITE_CHK(SQLITE_PREPARE(db, strfTime, -1, &stmt, NULL));

    // The following sequence somehow doesn't work even if the removeMsgTrace terminates with ' <?1;'
//    SQLITE_CHK(SQLITE_PREPARE(db, removeMsgTrace, -1, &stmt, NULL));
//    SQLITE_CHK(sqlite3_bind_text(stmt, 1, strfTime, -1, SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
//    cleaned = sqlite3_changes(db);
//    LOGGER(INFO, __func__, " Number of removed old traces: ", cleaned);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::insertReceivedRawData(const string& rawData, const string& uid, const string& displayName, int64_t* sequence)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");
    // Protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);

    // char* insertReceivedRawSql = "INSERT INTO receivedRaw (rawData, uid, displayName) VALUES (?1, ?2, ?3);";
    SQLITE_CHK(SQLITE_PREPARE(db, insertReceivedRawSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_blob(stmt, 1, rawData.data(), static_cast<int32_t>(rawData.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, uid.data(), static_cast<int32_t>(uid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, displayName.data(), static_cast<int32_t>(displayName.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    *sequence = sqlite3_last_insert_rowid(db);  // This call is not thread-save for multi-thread insert with same db connection
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::loadReceivedRawData(shared_ptr<list<shared_ptr<StoredMsgInfo> > > rawMessageData)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    int32_t len;

    LOGGER(INFO, __func__, " -->");

    // char* selectReceivedRaw = "SELECT sequence, rawData, uid, displayName FROM receivedRaw ORDER BY sequence ASC;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectReceivedRaw, -1, &stmt, NULL));

    sqlResult= sqlite3_step(stmt);
    while (sqlResult == SQLITE_ROW) {
        auto msgInfo = make_shared<StoredMsgInfo>();
        msgInfo->sequence = sqlite3_column_int64(stmt, 0);

        // Get raw message data
        len = sqlite3_column_bytes(stmt, 1);
        msgInfo->info_rawMsgData = string((const char*)sqlite3_column_blob(stmt, 1), static_cast<size_t>(len));
        msgInfo->info_uid = (const char*)sqlite3_column_text(stmt, 2);
        msgInfo->info_displayName = (const char*)sqlite3_column_text(stmt, 3);
        rawMessageData->push_back(msgInfo);

        sqlResult = sqlite3_step(stmt);
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::deleteReceivedRawData(int64_t sequence)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // char* removeReceivedRaw = "DELETE FROM receivedRaw WHERE sequence=?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeReceivedRaw, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int64(stmt, 1, sequence));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <--", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::cleanReceivedRawData(time_t timestamp)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // char* cleanReceivedRaw = "DELETE FROM receivedRaw WHERE inserted < ?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, cleanReceivedRaw, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int64(stmt, 1, timestamp));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

/*
static const char* selectTempMsg = "SELECT sequence, messageData, supplementData, msgType FROM TempMsg ORDER BY sequence ASC;";

 */
int32_t SQLiteStoreConv::insertTempMsg(const string& messageData, const string& supplementData, int32_t msgType, int64_t* sequence)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");
    // Protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);

    // char* insertTempMsgSql = "INSERT INTO TempMsg (messageData, supplementData, msgType) VALUES (?1, ?2, ?3);";
    SQLITE_CHK(SQLITE_PREPARE(db, insertTempMsgSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, messageData.data(), static_cast<int32_t>(messageData.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, supplementData.data(), static_cast<int32_t>(supplementData.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int(stmt, 3, msgType));

    sqlResult= sqlite3_step(stmt);
    *sequence = sqlite3_last_insert_rowid(db);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::loadTempMsg(shared_ptr<list<shared_ptr<StoredMsgInfo> > > tempMessageData)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // char* selectTempMsg = "SELECT sequence, messageData, supplementData, msgType FROM TempMsg ORDER BY sequence ASC;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectTempMsg, -1, &stmt, NULL));

    sqlResult= sqlite3_step(stmt);
    while (sqlResult == SQLITE_ROW) {
        auto msgInfo = make_shared<StoredMsgInfo>();
        msgInfo->sequence = sqlite3_column_int64(stmt, 0);
        msgInfo->info_msgDescriptor = (const char*)sqlite3_column_text(stmt, 1);
        msgInfo->info_supplementary = (const char*)sqlite3_column_text(stmt, 2);
        msgInfo->info_msgType = sqlite3_column_int(stmt, 3);
        tempMessageData->push_back(msgInfo);

        sqlResult = sqlite3_step(stmt);
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::deleteTempMsg(int64_t sequence)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // char* removeTempMsg = "DELETE FROM TempMsg WHERE sequence=?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeTempMsg, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int64(stmt, 1, sequence));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <--", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::cleanTempMsg(time_t timestamp)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // char* cleanTempMsgSql = "DELETE FROM TempMsg WHERE inserted < ?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, cleanTempMsgSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int64(stmt, 1, timestamp));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE) {
        ERRMSG;
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}


int32_t SQLiteStoreConv::insertGroup(const string &groupUuid, const string &name, const string &ownerUuid, string& description, int32_t maxMembers)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");
    // Protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);

    // char* insertGroupsSql = "INSERT INTO groups (groupId, name, ownerId, description, maxMembers, memberCount, attribute) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);";
    SQLITE_CHK(SQLITE_PREPARE(db, insertGroupsSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, name.data(), static_cast<int32_t>(name.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, ownerUuid.data(), static_cast<int32_t>(ownerUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 4, description.data(), static_cast<int32_t>(description.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int(stmt,  5, maxMembers));
    SQLITE_CHK(sqlite3_bind_int(stmt,  6, 0));
    SQLITE_CHK(sqlite3_bind_int(stmt,  7, ACTIVE));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::deleteGroup(const string &groupUuid)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    LOGGER(INFO, __func__, " -->");

    // char* removeGroup = "DELETE FROM groups WHERE groupId=?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeGroup, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}


bool SQLiteStoreConv::hasGroup(const string &groupUuid, int32_t *sqlCode) {
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    int32_t exists = 0;

    LOGGER(INFO, __func__, " -->");

    // char* hasGroupSql = "SELECT NULL, CASE EXISTS (SELECT 0 FROM groups WHERE groupId=?1) WHEN 1 THEN 1 ELSE 0 END;";
    SQLITE_CHK(SQLITE_PREPARE(db, hasGroupSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_ROW)
        ERRMSG;

    exists = sqlite3_column_int(stmt, 1);

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return exists == 1;
}


static cJSON* createGroupJson(sqlite3_stmt *stmt)
{
    cJSON* root = cJSON_CreateObject();

    // name is usually the SC UID string
    cJSON_AddStringToObject(root, GROUP_ID, (const char*)sqlite3_column_text(stmt, 0));
    cJSON_AddStringToObject(root, GROUP_NAME, (const char*)sqlite3_column_text(stmt, 1));
    cJSON_AddStringToObject(root, GROUP_OWNER, (const char*)sqlite3_column_text(stmt, 2));
    cJSON_AddStringToObject(root, GROUP_DESC, (const char*)sqlite3_column_text(stmt, 3));
    cJSON_AddNumberToObject(root, GROUP_MAX_MEMBERS, sqlite3_column_int(stmt, 4));
    cJSON_AddNumberToObject(root, GROUP_MEMBER_COUNT, sqlite3_column_int(stmt, 5));
    cJSON_AddNumberToObject(root, GROUP_ATTRIBUTE, sqlite3_column_int(stmt, 6));
    cJSON_AddNumberToObject(root, GROUP_MOD_TIME, sqlite3_column_int64(stmt, 7));

    return root;
}

shared_ptr<list<shared_ptr<cJSON> > > SQLiteStoreConv::listAllGroups(int32_t *sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    shared_ptr<list<shared_ptr<cJSON> > > groups = make_shared<list<shared_ptr<cJSON> > >();

    LOGGER(INFO, __func__, " -->");

    // char* selectAllGroups = "SELECT groupId, name, ownerId, description, maxMembers, memberCount, attributes, lastModified FROM groups;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectAllGroups, -1, &stmt, NULL));

    sqlResult= sqlite3_step(stmt);
        ERRMSG;

    while (sqlResult == SQLITE_ROW) {
        // Get group records and create a JSON object, wrap it in a shared_ptr with a custom delete
        shared_ptr<cJSON> sharedRoot(createGroupJson(stmt), cJSON_deleter);
        groups->push_back(sharedRoot);

        sqlResult = sqlite3_step(stmt);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);

    return groups;
}

shared_ptr<cJSON>SQLiteStoreConv::listGroup(const string &groupUuid, int32_t *sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    shared_ptr<cJSON> sharedJson;

    // char* selectGroup = "SELECT groupId, name, ownerId, description, maxMembers, memberCount, attributes, lastModified FROM groups WHERE groupId=?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectGroup, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    ERRMSG;

    if (sqlResult == SQLITE_ROW) {
        sharedJson = shared_ptr<cJSON>(createGroupJson(stmt), cJSON_deleter);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);

    return sharedJson;
}

int32_t SQLiteStoreConv::modifyGroupMaxMembers(const string &groupUuid, int32_t maxMembers)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // char* updateGroupMaxMember = "UPDATE groups SET maxMembers=?1 WHERE groupId=?2;";
    SQLITE_CHK(SQLITE_PREPARE(db, updateGroupMaxMember, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt,  1, maxMembers));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

pair<int32_t, time_t> SQLiteStoreConv::getGroupAttribute(const string& groupUuid, int32_t* sqlCode) const
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    int32_t attributes = 0;
    time_t lastModified = 0;
    pair<int32_t, time_t> result;

    // char* selectGroupAttributeSql = "SELECT attributes, lastModified FROM groups WHERE groupId=?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectGroupAttributeSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

    if (sqlResult == SQLITE_ROW) {
        attributes = sqlite3_column_int(stmt, 0);
        lastModified = sqlite3_column_int64(stmt, 1);
        result = pair<int32_t, time_t>(attributes, lastModified);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return result;
}

int32_t SQLiteStoreConv::setGroupAttribute(const string& groupUuid, int32_t attributeMask)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // char* setGroupAttributeSql = "UPDATE groups SET attributes=attributes|?1, lastModified=?2 WHERE groupId=?3;";
    SQLITE_CHK(SQLITE_PREPARE(db, setGroupAttributeSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt,  1, attributeMask));
    SQLITE_CHK(sqlite3_bind_int64(stmt,2, time(nullptr)));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::clearGroupAttribute(const string& groupUuid, int32_t attributeMask)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // char* clearGroupAttributeSql = "UPDATE groups SET attributes=attributes&~?1, lastModified=?2 WHERE groupId=?2;";
    SQLITE_CHK(SQLITE_PREPARE(db, clearGroupAttributeSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt,  1, attributeMask));
    SQLITE_CHK(sqlite3_bind_int64(stmt,2, time(nullptr)));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

static int32_t incrementMemberCount(sqlite3* db, const string& groupUuid) {
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // char* incrementGroupMemberCount = "UPDATE groups SET memberCount=memberCount+1 WHERE groupId=?1;";
    sqlResult = SQLITE_PREPARE(db, incrementGroupMemberCount, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC);
    if (sqlResult != SQLITE_OK)
        goto cleanup;
    sqlResult = sqlite3_step(stmt);

cleanup:
    sqlite3_finalize(stmt);
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

static int32_t decrementMemberCount(sqlite3* db, const string& groupUuid) {
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // char* decrementGroupMemberCount = "UPDATE groups SET memberCount=memberCount-1 WHERE groupId=?1;";
    sqlResult = SQLITE_PREPARE(db, decrementGroupMemberCount, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC);
    if (sqlResult != SQLITE_OK)
        goto cleanup;
    sqlResult = sqlite3_step(stmt);

cleanup:
    sqlite3_finalize(stmt);
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

static int32_t setMemberCount(sqlite3* db, const string& groupUuid, int32_t count) {
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // char* setGroupMemberCount = "UPDATE groups SET memberCount=?1 WHERE groupId=?2;";
    sqlResult = SQLITE_PREPARE(db, setGroupMemberCount, -1, &stmt, NULL);
    sqlite3_bind_int(stmt,  1, count);
    sqlite3_bind_text(stmt, 2, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC);
    if (sqlResult != SQLITE_OK)
        goto cleanup;
    sqlResult = sqlite3_step(stmt);

cleanup:
    sqlite3_finalize(stmt);
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::insertMember(const string &groupUuid, const string &memberUuid)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult, sqlResultIncrement;
    // Protect against multi-thread inserts because of auto-increment handling that we use in some tables
    unique_lock<mutex> lck(sqlLock);

    // char* insertMemberSql = "INSERT INTO members (groupId, memberId, attributes) VALUES (?1, ?2, ?3);";
    SQLITE_CHK(SQLITE_PREPARE(db, insertMemberSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, memberUuid.data(), static_cast<int32_t>(memberUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int(stmt,  3, ACTIVE));

    beginTransaction();
    sqlResultIncrement = incrementMemberCount(db, groupUuid);
    sqlResult = sqlite3_step(stmt);

    if (sqlResult != SQLITE_DONE || sqlResultIncrement != SQLITE_DONE) {
        ERRMSG;
        rollbackTransaction();
    }
    else {
        commitTransaction();
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::deleteMember(const string &groupUuid, const string &memberUuid)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult, sqlResultDecrement;

    // char* removeMember = "DELETE FROM members WHERE groupId=?1 AND memberId=?2;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeMember, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, memberUuid.data(), static_cast<int32_t>(memberUuid.size()), SQLITE_STATIC));

    beginTransaction();
    sqlResult= sqlite3_step(stmt);
    sqlResultDecrement = decrementMemberCount(db, groupUuid);

    if (sqlResult != SQLITE_DONE || sqlResultDecrement != SQLITE_DONE) {
        ERRMSG;
        rollbackTransaction();
    }
    else {
        commitTransaction();
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}


int32_t SQLiteStoreConv::deleteAllMembers(const string &groupUuid) {
    sqlite3_stmt *stmt;
    int32_t sqlResult, sqlResultDecrement;

    // char* removeAllMembers = "DELETE FROM members WHERE groupId=?1;";
    SQLITE_CHK(SQLITE_PREPARE(db, removeAllMembers, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    beginTransaction();
    sqlResult= sqlite3_step(stmt);
    sqlResultDecrement = setMemberCount(db, groupUuid, 0);

    if (sqlResult != SQLITE_DONE || sqlResultDecrement != SQLITE_DONE) {
        ERRMSG;
        rollbackTransaction();
    }
    else {
        commitTransaction();
    }

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}


static cJSON* createMemberJson(sqlite3_stmt *stmt)
{
    cJSON* root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, GROUP_ID,  (const char*)sqlite3_column_text(stmt, 0));
    cJSON_AddStringToObject(root, MEMBER_ID, (const char*)sqlite3_column_text(stmt, 1));
    cJSON_AddNumberToObject(root, MEMBER_ATTRIBUTE, sqlite3_column_int(stmt, 2));
    cJSON_AddNumberToObject(root, MEMBER_MOD_TIME, sqlite3_column_int64(stmt, 3));

    return root;
}

shared_ptr<list<shared_ptr<cJSON> > > SQLiteStoreConv::getAllGroupMembers(const string &groupUuid, int32_t *sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    shared_ptr<list<shared_ptr<cJSON> > > members = make_shared<list<shared_ptr<cJSON> > >();

    // char* selectGroupMembers = "SELECT groupId, memberId, attributes, lastModified FROM members WHERE groupId=?1 ORDER BY memberId ASC;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectGroupMembers, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
        ERRMSG;

    while (sqlResult == SQLITE_ROW) {
        // Get member records and create a JSON object, wrap it in a shared_ptr with a custom delete
        shared_ptr<cJSON> sharedRoot(createMemberJson(stmt), cJSON_deleter);
        members->push_back(sharedRoot);
        sqlResult = sqlite3_step(stmt);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);

    return members;
}

shared_ptr<cJSON>SQLiteStoreConv::getGroupMember(const string &groupUuid, const string &memberUuid, int32_t *sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    shared_ptr<cJSON> sharedJson;

    // char* selectMember = "SELECT groupId, memberId, attributes, lastModified FROM members WHERE groupId=?1 AND memberId=?2 ORDER BY memberId ASC;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectMember, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, memberUuid.data(), static_cast<int32_t>(memberUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
        ERRMSG;

    if (sqlResult == SQLITE_ROW) {
        sharedJson = shared_ptr<cJSON>(createMemberJson(stmt), cJSON_deleter);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);

    return sharedJson;
}

pair<int32_t, time_t> SQLiteStoreConv::getMemberAttribute(const string &groupUuid, const string &memberUuid, int32_t *sqlCode)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    int32_t attributes = 0;
    time_t lastModified = 0;
    pair<int32_t, time_t> result;

    // char* selectMemberAttributeSql = "SELECT attributes, lastModified FROM members WHERE groupId=?1 AND memberId=?2;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectMemberAttributeSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, memberUuid.data(), static_cast<int32_t>(memberUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

    if (sqlResult == SQLITE_ROW) {
        attributes = sqlite3_column_int(stmt, 0);
        lastModified = sqlite3_column_int64(stmt, 1);
        result = pair<int32_t, time_t>(attributes, lastModified);
    }

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return result;
}

int32_t SQLiteStoreConv::setMemberAttribute(const string &groupUuid, const string &memberUuid, int32_t attributeMask)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // char* setMemberAttributeSql = "UPDATE members SET attributes=attributes|?1, lastModified=?2 WHERE groupId=?2 AND memberId=?3;";
    SQLITE_CHK(SQLITE_PREPARE(db, setMemberAttributeSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt,  1, attributeMask));
    SQLITE_CHK(sqlite3_bind_int64(stmt,2, time(nullptr)));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 4, memberUuid.data(), static_cast<int32_t>(memberUuid.size()), SQLITE_STATIC));

    sqlResult= sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}

int32_t SQLiteStoreConv::clearMemberAttribute(const string &groupUuid, const string &memberUuid, int32_t attributeMask)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;

    // char* clearMemberAttributeSql = "UPDATE members SET attributes=attributes&~?1lastModified=?2 WHERE groupId=?2 AND memberId=?3;";
    SQLITE_CHK(SQLITE_PREPARE(db, clearMemberAttributeSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_int(stmt, 1, attributeMask));
    SQLITE_CHK(sqlite3_bind_int64(stmt,2, time(nullptr)));
    SQLITE_CHK(sqlite3_bind_text(stmt, 3, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 4, memberUuid.data(), static_cast<int32_t>(memberUuid.size()), SQLITE_STATIC));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_DONE)
        ERRMSG;

cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}


int32_t SQLiteStoreConv::memberListHash(const string &groupUuid, uint8_t *hash)
{
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    sha256_ctx* ctx;

    // char* selectForHash = "SELECT DISTINCT memberId FROM members WHERE groupId=?1 AND attributes&?2 ORDER BY memberId ASC;";
    SQLITE_CHK(SQLITE_PREPARE(db, selectForHash, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int(stmt,  2, ACTIVE));
    sqlResult = sqlite3_step(stmt);

    ctx = reinterpret_cast<sha256_ctx*>(createSha256Context());

    while (sqlResult == SQLITE_ROW) {
        const uint8_t* data = sqlite3_column_text(stmt, 0);
        int32_t length = sqlite3_column_bytes(stmt, 0);
        sha256Ctx(ctx, const_cast<uint8_t *>(data), static_cast<uint32_t >(length));
        sqlResult = sqlite3_step(stmt);
    }
    closeSha256Context(ctx, hash);


cleanup:
    sqlite3_finalize(stmt);
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);
    return sqlResult;
}


bool SQLiteStoreConv::isMemberOfGroup(const string &groupUuid, const string &memberUuid, int32_t *sqlCode) {
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    int32_t exists = 0;

    // char* isMemberOfGroupSql = "SELECT NULL, CASE EXISTS (SELECT 0 FROM members WHERE groupId=?1 AND memberId=?2) WHEN 1 THEN 1 ELSE 0 END;";
    SQLITE_CHK(SQLITE_PREPARE(db, isMemberOfGroupSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, groupUuid.data(), static_cast<int32_t>(groupUuid.size()), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, memberUuid.data(), static_cast<int32_t>(memberUuid.size()), SQLITE_STATIC));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_ROW)
        ERRMSG;

    exists = sqlite3_column_int(stmt, 1);

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);

    return exists == 1;
}


bool SQLiteStoreConv::isGroupMember(const string &memberUuid, int32_t *sqlCode) {
    sqlite3_stmt *stmt;
    int32_t sqlResult;
    int32_t exists = 0;

    // char* isGroupMember = "SELECT NULL, CASE EXISTS (SELECT 0 FROM members WHERE memberId=?1) WHEN 1 THEN 1 ELSE 0 END;";
    SQLITE_CHK(SQLITE_PREPARE(db, isGroupMemberSql, -1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, memberUuid.data(), static_cast<int32_t>(memberUuid.size()), SQLITE_STATIC));

    sqlResult = sqlite3_step(stmt);
    if (sqlResult != SQLITE_ROW)
        ERRMSG;

    exists = sqlite3_column_int(stmt, 1);

cleanup:
    sqlite3_finalize(stmt);
    if (sqlCode != NULL)
        *sqlCode = sqlResult;
    sqlCode_ = sqlResult;
    LOGGER(INFO, __func__, " <-- ", sqlResult);

    return exists == 1;
}


