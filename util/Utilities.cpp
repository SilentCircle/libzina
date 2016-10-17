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

//
// Created by werner on 07.06.16.
//

#include <sys/time.h>
#include <string.h>
#include "Utilities.h"

using namespace zina;


bool Utilities::hasJsonKey(const cJSON* const root, const char* const key) {
    if (root == nullptr)
        return false;
    cJSON* jsonItem = cJSON_GetObjectItem(const_cast<cJSON*>(root), key);
    if (jsonItem == nullptr)
        return false;

    return true;
}


int32_t Utilities::getJsonInt(const cJSON* const root, const char* const name, int32_t error) {
    if (root == nullptr)
        return error;
    cJSON* jsonItem = cJSON_GetObjectItem(const_cast<cJSON*>(root), name);
    if (jsonItem == nullptr)
        return error;
    return jsonItem->valueint;
}


double Utilities::getJsonDouble(const cJSON* const root, const char* const name, double error) {
    if (root == nullptr)
        return error;
    cJSON* jsonItem = cJSON_GetObjectItem(const_cast<cJSON*>(root), name);
    if (jsonItem == nullptr)
        return error;
    return jsonItem->valuedouble;
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

static void *(*volatile memset_volatile)(void*, int, size_t) = memset;

void Utilities::wipeString(string toWipe)
{
    memset_volatile((void*)toWipe.data(), 0, toWipe.size());
}
