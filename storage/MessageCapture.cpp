//
// Created by werner on 05.05.16.
//

#include "MessageCapture.h"
#include "sqlite/SQLiteStoreConv.h"
#include "../util/cJSON.h"
#include "../logging/AxoLogging.h"
#include "../axolotl/Constants.h"

const static char* FIELD_LATITUDE = "la";
const static char* FIELD_LONGITUDE = "lo";
const static char* FIELD_TIME = "t";
const static char* FIELD_ALTITUDE = "a";
const static char* FIELD_ACCURACY_HORIZONTAL = "v";
const static char* FIELD_ACCURACY_VERTICAL = "h";

using namespace std;
using namespace axolotl;

static int32_t filterAttributes(const string& attributes, shared_ptr<string> filteredAttributes)
{
    LOGGER(INFO, __func__, " -->");
    cJSON* cjTemp;
    char* jsString;

    cJSON* root = cJSON_Parse(attributes.c_str());
    if (root == NULL) {
        return CORRUPT_DATA;
    }
    cJSON_DeleteItemFromObject(root, FIELD_LATITUDE);
    cJSON_DeleteItemFromObject(root, FIELD_LONGITUDE);
    cJSON_DeleteItemFromObject(root, FIELD_TIME);
    cJSON_DeleteItemFromObject(root, FIELD_ALTITUDE);
    cJSON_DeleteItemFromObject(root, FIELD_ACCURACY_HORIZONTAL);
    cJSON_DeleteItemFromObject(root, FIELD_ACCURACY_VERTICAL);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    filteredAttributes->append(out);
    free(out);
    LOGGER(INFO, __func__ , " <-- ");

}

int32_t MessageCapture::captureReceivedMessage(const string &sender, const string &messageId, const string &deviceId,
                                               const string &attributes, bool attachments)
{
    LOGGER(INFO, __func__ , " -->");
    shared_ptr<string> filteredAttributes = make_shared<string>();
    int32_t result = filterAttributes(attributes, filteredAttributes);
    if (result < 0)
        return result;
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    result = store->insertMsgTrace(sender, messageId, deviceId, *filteredAttributes, attachments, true);
    if (SQL_FAIL(result)) {
        LOGGER(ERROR, __func__, " <-- Cannot store message trace data.", result);
        return result;
    }
    LOGGER(INFO, __func__ , " <-- ");
    return OK;
}

int32_t MessageCapture::captureSendMessage(const string &receiver, const string &messageId,const string &deviceId,
                                           const string &attributes, bool attachments)
{
    LOGGER(INFO, __func__ , " -->");
    shared_ptr<string> filteredAttributes = make_shared<string>();
    int32_t result = filterAttributes(attributes, filteredAttributes);
    if (result < 0)
        return result;

    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    result = store->insertMsgTrace(receiver, messageId, deviceId, *filteredAttributes, attachments, false);
    if (SQL_FAIL(result)) {
        LOGGER(ERROR, __func__, " <-- Cannot store message trace data.", result);
        return result;
    }
    LOGGER(INFO, __func__ , " <-- ");
    return OK;
}

shared_ptr<list<string> > MessageCapture::loadCapturedMsgs(const string &name, const string &messageId,
                                                           const string &deviceId, int32_t *sqlCode)
{
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    return store->loadMsgTrace(name, messageId, deviceId, sqlCode);
}


