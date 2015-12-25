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
#endif

#define DB_CACHE_ERR_BUFF_SIZE  1000
#define OUR_KEY_LENGTH          32

#define SQL_FAIL(code) ((code) > SQLITE_OK && (code) < SQLITE_ROW)

using namespace std;

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

    // Pre key storage. The functions encrypt, decrypt and store/retrive Pre-key JSON strings
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
     * @return SQLite code
     */
    int32_t hasMsgHash(const string& msgHash);

    /**
     * @brief Delete message hashes old than the timestamp.
     * 
     * @param timestamp the timestamp of oldest hash
     * @return SQLite code, @c SQLITE_ROW indicates the message hash exists in the table
     */
    int32_t deleteMsgHashes(time_t timestamp);

    /*
     * @brief For use for debugging and development only
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
