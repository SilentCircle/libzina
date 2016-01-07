//
// Created by werner on 30.10.15.
//

#ifndef LIBAXOLOTL_NAMELOOKUP_H
#define LIBAXOLOTL_NAMELOOKUP_H

#include <string>
#include <map>
#include <memory>
#include <utility>
#include <list>

/**
 * @file NameLookup.h
 * @brief Perform lookup and cahing of alias names and return the UID
 *
 * @ingroup Axolotl++
 * @{
 */

using namespace std;

namespace axolotl {

    class UserInfo {
    public:
        string uniqueId;        //!< User's unique name, canonical name, not human readable
        string displayName;     //!< User's full/display name as stored in the provisioning server
        string alias0;          //!< Primary alias, aka preferred alias, aka alias0
    };

    class NameLookup {
    public:
        enum AliasAdd {
            MissingParameter = -3,
            InsertFailed = -2,  //!< Insert in name Map failed
            UserDataError = -1, //!< User data has incorrect format or misses data
            AliasExisted = 1,   //!< Alias name already exists in the name map
            UuidAdded = 2,      //!< UUID, alias and user data added
            AliasAdded = 3      //!< Alias name added to existing UUID
        };

        static NameLookup* getInstance();

        /**
         * @brief Get UUID of an alias, e.g. a name or number.
         *
         * @param alias the alias name/number
         * @authorization the authorization data
         *
         * @return A UUID string or empty shared pointer if alias is not known.
         */
        const string getUid(const string& alias, const string& authorization);

        /**
         * @brief Get UserInfo of an alias, e.g. a name or number.
         *
         * @param alias the alias name/number
         * @authorization the authorization data
         * @return A JSON string containing the UserInfo or empty shared pointer if alias is not known.
         */
        const shared_ptr<UserInfo> getUserInfo(const string& alias, const string& authorization);

        /**
         * @brief Return a list of the alias names of a UUID.
         *
         * This function does no trigger any network actions, save to run from UI thread.

         * @param uuid the UUID
         * @authorization the authorization data
         * @return List of strings or empty shared pointer if alias is not known.
         */
        const shared_ptr<list<string> > getAliases(const string& uuid, const string& authorization);

        /**
         * @brief Add an alias name and user info to an UUID.
         *
         * If the alias name already exists in the map the function is a no-op and returns
         * immediately.
         *
         * The function first performs a lookup on the UUID. If it exists then it simply
         * adds the alias name for this UUID and uses the already existing user info, thus
         * ignores the provided user info.
         *
         * If the UUID does not exist the functions creates a UUID entry and links the
         * user info to the new entry. Then it adds the alias name to the UUID.
         *
         * This function does no trigger any network actions, save to run from UI thread.
         *
         * @param alias the alias name/number
         * @param uuid the UUID
         * @param userInfo a JSON formatted string with the user information
         * @authorization the authorization data
         * @return a value > 0 to indicate success, < 0 on failure.
         */
        AliasAdd addAliasToUuid(const string& alias, const string& uuid, const string& userInfo, const string& authorization);

        void clearNameCache() { nameMap_.clear(); }

    private:
        int32_t parseUserInfo(const string& json, shared_ptr<UserInfo> userInfo);

        map<string, shared_ptr<UserInfo> > nameMap_;
        static NameLookup* instance_;
    };
}
/**
 * @}
 */

#endif //LIBAXOLOTL_NAMELOOKUP_H
