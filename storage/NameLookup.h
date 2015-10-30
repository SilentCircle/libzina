//
// Created by werner on 30.10.15.
//

#ifndef LIBAXOLOTL_NAMELOOKUP_H
#define LIBAXOLOTL_NAMELOOKUP_H

#include <string>
#include <map>
#include <memory>
#include <utility>

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
        string fullName;        //!< User's full name as stored with the provisioning server
        string alias0;          //!< Primary alias, aka preferred alias
    };

    class NameLookup {
    public:
        static NameLookup* getInstance();

        const string getUid(const string& alias, const string& authorization);

        const shared_ptr<UserInfo> getUserInfo(const string& alias, const string& authorization);

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
