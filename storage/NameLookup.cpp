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
        userInfo->fullName.assign(tmpData->valuestring);
    }
    cJSON_Delete(root);
    return OK;
}

const shared_ptr<UserInfo> NameLookup::getUserInfo(const string &alias, const string &authorization) {
    // Check is an alias name already exists in the alias name map
    map<string, shared_ptr<UserInfo> >::iterator it;
    it = nameMap_.find(alias);
    if (it != nameMap_.end()) {
        return it->second;
    }

    string result;
    int32_t code = Provisioning::getUserInfo(alias, authorization, &result);

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
