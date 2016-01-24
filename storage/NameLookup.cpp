//
// Created by werner on 30.10.15.
//

#include <iostream>
#include "NameLookup.h"
#include <mutex>          // std::mutex, std::unique_lock
#include "../util/cJSON.h"
#include "../axolotl/Constants.h"
#include "../provisioning/Provisioning.h"
#include "../logging/AxoLogging.h"


using namespace axolotl;

static mutex nameLock;           // mutex for critical section

NameLookup* NameLookup::instance_ = NULL;

NameLookup* NameLookup::getInstance()
{
    unique_lock<mutex> lck(nameLock);
    if (instance_ == NULL)
        instance_ = new NameLookup();
    lck.unlock();
    return instance_;
}

static string USER_NULL_NAME("_!NULL!_");
static const char* nullData =
                "{\"display_name\": \"%s\",\"uuid\": \"%s\",\"default_alias\": \"%s\"}";



const string NameLookup::getUid(const string &alias, const string& authorization) {

    LOGGER(INFO, __func__ , " -->");
    shared_ptr<UserInfo> userInfo = getUserInfo(alias, authorization);
    LOGGER(INFO, __func__ , " <--");
    return (userInfo) ? userInfo->uniqueId : Empty;
}

/*
 * Structure of the user info JSON that the provisioning server returns:
 * {
    "last_name": "",
    "hash": "2f8f64dd8e3da11cd25f4148f242377bc5bb6c67",
    "keys": [],
    "active_st_device": "a2563336fd7435701fc3cb77ffee312f",
    "country_code": "",
    "silent_text": true,
    "display_name": "nodid2",
    "permissions":
    {
        "can_send_media": true,
        "silent_text": true,
        "outbound_messaging": true,
        "can_receive_voicemail": false,
        "silent_desktop": true,
        "outbound_calling": true,
        "silent_phone": true,
        "inbound_messaging": true,
        "has_oca": false,
        "inbound_calling": true
    },
    "first_name": "",
    "force_password_change": false,
    "user_id": "uq2et4rhvj9kgxlud3eh0kp74j",
    "primary_alias": "nodid2",
    "avatar_url": null,
    "silent_phone": true,
    "subscription":
    {
        "state": "paying",
        "expires": "2016-07-08T00:00:00Z",
        "has_expired": false,
        "handles_own_billing": true
    }
 * }
 *
 */
int32_t NameLookup::parseUserInfo(const string& json, shared_ptr<UserInfo> userInfo)
{
    LOGGER(INFO, __func__ , " -->");
    cJSON* root = cJSON_Parse(json.c_str());
    if (root == NULL) {
        LOGGER(ERROR, __func__ , " JSON data not parseable: ", json);
        return CORRUPT_DATA;
    }

    cJSON* tmpData = cJSON_GetObjectItem(root, "uuid");
    if (tmpData == NULL) {
        cJSON_Delete(root);
        LOGGER(ERROR, __func__ , " Missing 'uuid' field.");
        return JS_FIELD_MISSING;
    }
    userInfo->uniqueId.assign(tmpData->valuestring);

    tmpData = cJSON_GetObjectItem(root, "default_alias");
    if (tmpData == NULL) {
        tmpData = cJSON_GetObjectItem(root, "display_alias");
        if (tmpData == NULL) {
            cJSON_Delete(root);
            LOGGER(ERROR, __func__, " Missing 'default_alias' or 'display_alias' field.");
            return JS_FIELD_MISSING;
        }
    }
    userInfo->alias0.assign(tmpData->valuestring);

    tmpData = cJSON_GetObjectItem(root, "display_name");
    if (tmpData != NULL) {
        userInfo->displayName.assign(tmpData->valuestring);
    }
    tmpData = cJSON_GetObjectItem(root, "lookup_uri");
    if (tmpData != NULL) {
        userInfo->contactLookupUri.assign(tmpData->valuestring);
    }
    cJSON_Delete(root);
    LOGGER(INFO, __func__ , " <--");
    return OK;
}

const shared_ptr<UserInfo> NameLookup::getUserInfo(const string &alias, const string &authorization, bool cacheOnly) {

    LOGGER(INFO, __func__ , " -->");
    if (alias.empty() || authorization.empty()) {
        LOGGER(ERROR, __func__ , " <-- empty data");
        return shared_ptr<UserInfo>();
    }

    // Check if this alias name already exists in the name map
    unique_lock<mutex> lck(nameLock);
    map<string, shared_ptr<UserInfo> >::iterator it;
    it = nameMap_.find(alias);
    if (it != nameMap_.end()) {
        LOGGER(INFO, __func__ , " <-- cached data");
        if (it->second->displayName == USER_NULL_NAME) {
            return shared_ptr<UserInfo>();
        }
        return it->second;
    }
    if (cacheOnly) {
        return shared_ptr<UserInfo>();
    }
    string result;
    int32_t code = Provisioning::getUserInfo(alias, authorization, &result);

    // Return empty pointer in case of HTTP error
    char temp[1000];
    if (code >= 400) {
        // If server returns "not found" then add a invalid user data structure. Thus
        // another lookup with the same name will have a cache hit, avoiding a network
        // round trip but still returning an empty pointer signaling a non-existing name.
        if (code == 404) {
            snprintf(temp, 990, nullData, USER_NULL_NAME.c_str(), alias.c_str(), alias.c_str());
            result = temp;
        }
        else {
            LOGGER(ERROR, __func__ , " Error return from server: ", code);
            return shared_ptr<UserInfo>();
        }
    }

    shared_ptr<UserInfo> userInfo = make_shared<UserInfo>();
    code = parseUserInfo(result, userInfo);
    if (code != OK) {
        LOGGER(ERROR, __func__ , " Error return from parsing.");
        return shared_ptr<UserInfo>();
    }

    pair<map<string, shared_ptr<UserInfo> >::iterator, bool> ret;

    // Check if we already have the user's UID in the map. If not then cache the
    // userInfo with the UID
    it = nameMap_.find(userInfo->uniqueId);
    if (it == nameMap_.end()) {
        ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(userInfo->uniqueId, userInfo));
        if (!ret.second) {
            LOGGER(ERROR, __func__ , " Insert in cache list failed. ", 0);
            return shared_ptr<UserInfo>();
        }
        // For existing account (old accounts) the UUID and the primary alias could be identical
        // Don't add an alias entry in this case
        if (alias.compare(userInfo->uniqueId) != 0) {
            ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(alias, userInfo));
            if (!ret.second) {
                LOGGER(ERROR, __func__ , " Insert in cache list failed. ", 1);
                return shared_ptr<UserInfo>();
            }
        }
    }
    else {
        ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(alias, it->second));
        if (!ret.second) {
            LOGGER(ERROR, __func__ , " Insert in cache list failed. ", 2);
            return shared_ptr<UserInfo>();
        }
        userInfo = it->second;
    }
    lck.unlock();
    if (userInfo->displayName == USER_NULL_NAME) {
        LOGGER(INFO, __func__ , " <-- return null name");
        return shared_ptr<UserInfo>();
    }
    LOGGER(INFO, __func__ , " <-- ", userInfo->displayName);
    return userInfo;
}

const shared_ptr<list<string> > NameLookup::getAliases(const string& uuid, const string& authorization)
{
    LOGGER(INFO, __func__ , " -->");
    shared_ptr<list<string> > aliasList = make_shared<list<string> >();
    if (uuid.empty() || authorization.empty()) {
        LOGGER(ERROR, __func__ , " <-- empty data");
        return shared_ptr<list<string> >();
    }
    unique_lock<mutex> lck(nameLock);

    if (nameMap_.size() == 0) {
        LOGGER(INFO, __func__ , " <-- empty name map");
        return shared_ptr<list<string> >();
    }
    for (map<string, shared_ptr<UserInfo> >::iterator it=nameMap_.begin(); it != nameMap_.end(); ++it) {
        shared_ptr<UserInfo> userInfo = (*it).second;
        // Add aliases to the result. If the map entry if the UUID entry then add the default alias
        if (uuid == userInfo->uniqueId) {
            if (uuid != (*it).first) {
                aliasList->push_back((*it).first);
            }
            else {
                if (!(*it).second->alias0.empty())
                    aliasList->push_back((*it).second->alias0);
            }
        }
    }
    lck.unlock();
    LOGGER(INFO, __func__ , " <--");
    return aliasList;
}

NameLookup::AliasAdd NameLookup::addAliasToUuid(const string& alias, const string& uuid, const string& userData,
                                                const string& authorization)
{
    LOGGER(INFO, __func__ , " -->");

    // Check if this alias name already exists in the name map, if yes just return.
    unique_lock<mutex> lck(nameLock);
    map<string, shared_ptr<UserInfo> >::iterator it;
    it = nameMap_.find(alias);
    if (it != nameMap_.end()) {
        LOGGER(INFO, __func__ , " <-- alias already exists");
        return AliasExisted;
    }

    pair<map<string, shared_ptr<UserInfo> >::iterator, bool> ret;

    // Check if we already have the user's UID in the map. If not then cache the
    // userInfo with the UID
    AliasAdd retValue;
    it = nameMap_.find(uuid);
    if (it == nameMap_.end()) {
        shared_ptr<UserInfo> userInfo = make_shared<UserInfo>();
        int32_t code = parseUserInfo(userData, userInfo);
        if (code != OK) {
            LOGGER(ERROR, __func__ , " Error return from parsing.");
            return UserDataError;
        }
        ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(userInfo->uniqueId, userInfo));
        if (!ret.second) {
            LOGGER(ERROR, __func__ , " Insert in cache list failed. ", 0);
            return InsertFailed;
        }
        // For existing account (old accounts) the UUID and the primary alias could be identical
        // Don't add an alias entry in this case
        if (alias.compare(userInfo->uniqueId) != 0) {
            ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(alias, userInfo));
            if (!ret.second) {
                LOGGER(ERROR, __func__ , " Insert in cache list failed. ", 1);
                return InsertFailed;
            }
        }
        retValue = UuidAdded;
    }
    else {
        ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(alias, it->second));
        if (!ret.second) {
            LOGGER(ERROR, __func__ , " Insert in cache list failed. ", 2);
            return InsertFailed;
        }
        retValue = AliasAdded;
    }
    LOGGER(INFO, __func__ , " <--");
    return retValue;
}

const shared_ptr<string> NameLookup::getDisplayName(const string& uuid, const string& authorization)
{
    LOGGER(INFO, __func__ , " -->");
    shared_ptr<string> displayName = make_shared<string>();

    if (uuid.empty() || authorization.empty()) {
        LOGGER(ERROR, __func__ , " <-- empty data");
        return shared_ptr<string>();
    }
    unique_lock<mutex> lck(nameLock);

    if (nameMap_.size() == 0) {
        LOGGER(INFO, __func__ , " <-- empty name map");
        return shared_ptr<string>();
    }
    map<string, shared_ptr<UserInfo> >::iterator it;
    it = nameMap_.find(uuid);
    if (it != nameMap_.end()) {
        *displayName = (*it).second->displayName;
    }
    lck.unlock();
    LOGGER(INFO, __func__ , " <--");
    return displayName;
}

