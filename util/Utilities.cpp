//
// Created by werner on 07.06.16.
//

#include "Utilities.h"

using namespace axolotl;


int32_t Utilities::getJsonInt(const cJSON* const root, const char* const name, int32_t error) {
    if (root == nullptr)
        return error;
    cJSON* jsonItem = cJSON_GetObjectItem(const_cast<cJSON*>(root), name);
    if (jsonItem == nullptr)
        return error;
    return jsonItem->valueint;
}


const char *const Utilities::getJsonString(const cJSON* const root, const char* const name, const char *error) {
    if (root == nullptr)
        return error;
    cJSON* jsonItem = cJSON_GetObjectItem(const_cast<cJSON*>(root), name);
    if (jsonItem == nullptr)
        return error;
    return jsonItem->valuestring;
}


bool Utilities::getJsonBool(const cJSON *const root, const char *const name, bool error) {
    if (root == nullptr)
        return error;
    cJSON* jsonItem = cJSON_GetObjectItem(const_cast<cJSON*>(root), name);
    if (jsonItem == nullptr)
        return error;
    if (jsonItem->type == cJSON_True || jsonItem->type == cJSON_False)
        return jsonItem->type;
    return error;
}

