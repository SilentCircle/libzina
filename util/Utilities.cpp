//
// Created by werner on 07.06.16.
//

#include <sys/time.h>
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
        return jsonItem->type == cJSON_True;
    return error;
}

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

    size_t idx = result->empty() ? 0: result->size() - 1;
    while (idx != 0) {
        if (result->at(idx).empty()) {
            result->pop_back();
            idx--;
        }
        else
            break;
    }
    return result;
}

string Utilities::currentTimeMsISO8601()
{
    char buffer[80];
    char outbuf[80];
    struct timeval tv;
    struct tm timeinfo;

    gettimeofday(&tv, NULL);
    time_t currentTime = tv.tv_sec;

    const char* format = "%FT%T";
    strftime(buffer, 80, format ,gmtime_r(&currentTime, &timeinfo));
    snprintf(outbuf, 80, "%s.%03dZ\n", buffer, static_cast<int>(tv.tv_usec / 1000));
    return string(outbuf);
}

string Utilities::currentTimeISO8601()
{
    char outbuf[80];
    struct tm timeinfo;

    time_t currentTime = time(NULL);

    const char* format = "%FT%TZ";
    strftime(outbuf, 80, format, gmtime_r(&currentTime, &timeinfo));
    return string(outbuf);
}