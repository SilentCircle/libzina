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

/**
 * @brief Splits a string around matches of the given delimiter character.
 *
 * Trailing empty strings are not included in the resulting array.
 * This function works similar to the Java string split function, however it does
 * not support regular expressions, only a simple delimiter character.
 *
 * @param data The std::string to split
 * @param delimiter The delimiter character
 * @return A vector of strings
 */
shared_ptr<vector<string> >
Utilities::splitString(const string& data, const string delimiter)
{
    shared_ptr<vector<string> > result = make_shared<vector<string> >();

    if (data.empty() || (delimiter.empty() || delimiter.size() > 1)) {
        return result;
    }
    string copy(data);

    size_t pos = 0;
    while ((pos = copy.find(delimiter)) != string::npos) {
        string token = copy.substr(0, pos);
        copy.erase(0, pos + 1);
        result->push_back(token);
    }
    if (!copy.empty()) {
        result->push_back(copy);
    }

    size_t idx = result->size() - 1;
    while (idx >= 0) {
        if (result->at(idx).empty()) {
            result->pop_back();
            if (idx == 0) {
                break;
            }
            idx--;
        }
        else
            break;
    }
    return result;
}
