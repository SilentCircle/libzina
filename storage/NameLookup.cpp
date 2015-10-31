//
// Created by werner on 30.10.15.
//

#include <common/Thread.h>
#include <iostream>
#include "NameLookup.h"
#include "../util/cJSON.h"
#include "../axolotl/Constants.h"
#include "../provisioning/Provisioning.h"

using namespace axolotl;

static string Empty;
static CMutexClass nameLock;

NameLookup* NameLookup::instance_ = NULL;

NameLookup* NameLookup::getInstance()
{
    nameLock.Lock();
    if (instance_ == NULL)
        instance_ = new NameLookup();
    nameLock.Unlock();
    return instance_;
}


const string NameLookup::getUid(const string &alias, const string& authorization) {

    shared_ptr<UserInfo> userInfo = getUserInfo(alias, authorization);
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
    cJSON* root = cJSON_Parse(json.c_str());
    if (root == NULL)
        return CORRUPT_DATA;

    cJSON* tmpData = cJSON_GetObjectItem(root, "user_id");
    if (tmpData == NULL) {
        cJSON_Delete(root);
        return JS_FIELD_MISSING;
    }
    userInfo->uniqueId.assign(tmpData->valuestring);

    tmpData = cJSON_GetObjectItem(root, "primary_alias");
    if (tmpData == NULL) {
        cJSON_Delete(root);
        return JS_FIELD_MISSING;
    }
    userInfo->alias0.assign(tmpData->valuestring);

    tmpData = cJSON_GetObjectItem(root, "display_name");
    if (tmpData != NULL) {
        userInfo->displayName.assign(tmpData->valuestring);
    }
    cJSON_Delete(root);
    return OK;
}

const shared_ptr<UserInfo> NameLookup::getUserInfo(const string &alias, const string &authorization) {

    if (alias.empty() || authorization.empty())
        return shared_ptr<UserInfo>();

    // Check is an alias name already exists in the name map
    map<string, shared_ptr<UserInfo> >::iterator it;
    it = nameMap_.find(alias);
    if (it != nameMap_.end()) {
        return it->second;
    }
    string result;
    int32_t code = Provisioning::getUserInfo(alias, authorization, &result);

    // Return empty pointer in case of HTTP error
    if (code >= 400) {
        return shared_ptr<UserInfo>();
    }
    shared_ptr<UserInfo> userInfo = make_shared<UserInfo>();
    code = parseUserInfo(result, userInfo);

    pair<map<string, shared_ptr<UserInfo> >::iterator, bool> ret;

    // Check if we already have the user's UID in the map. If not then cache the
    // userInfo with the UID
    it = nameMap_.find(userInfo->uniqueId);
    if (it == nameMap_.end()) {
        ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(userInfo->uniqueId, userInfo));
        if (!ret.second) {
            return shared_ptr<UserInfo>();
        }
        ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(alias, userInfo));
        if (!ret.second) {
            return shared_ptr<UserInfo>();
        }
    }
    else {
        ret = nameMap_.insert(pair<string, shared_ptr<UserInfo> >(alias, it->second));
        if (!ret.second) {
            return shared_ptr<UserInfo>();
        }
        userInfo = it->second;
    }
    return userInfo;
}
