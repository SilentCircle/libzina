//
// Created by werner on 05.05.16.
//

#include "MessageCapture.h"
#include "sqlite/SQLiteStoreConv.h"
#include "../util/cJSON.h"
#include "../logging/ZinaLogging.h"
#include "../Constants.h"

const static char* FIELD_LATITUDE = "la";
const static char* FIELD_LONGITUDE = "lo";
const static char* FIELD_TIME = "t";
const static char* FIELD_ALTITUDE = "a";
const static char* FIELD_ACCURACY_HORIZONTAL = "v";
const static char* FIELD_ACCURACY_VERTICAL = "h";

using namespace std;
using namespace zina;

static int32_t filterAttributes(const string& attributes, string *filteredAttributes)
{
    LOGGER(DEBUGGING, __func__, " -->");

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
    LOGGER(DEBUGGING, __func__ , " <-- ");
    return OK;
}

static void cleanupTrace(SQLiteStoreConv* store )
{
    // Cleanup old traces, currently using the same time as for the Message Key cleanup
    time_t timestamp = time(0) - MK_STORE_TIME;
    store->deleteMsgTrace(timestamp);
}

int32_t MessageCapture::captureReceivedMessage(const string &sender, const string &messageId, const string &deviceId,
                                               const string &convState, const string &attributes, bool attachments)
{
    LOGGER(DEBUGGING, __func__ , " -->");

    SQLiteStoreConv *store = SQLiteStoreConv::getStore();
    LOGGER_BEGIN(INFO)
        string filteredAttributes;
        int32_t result = filterAttributes(attributes, &filteredAttributes);
        if (result < 0) {
            LOGGER(ERROR, __func__, " Cannot parse received message attributes: ", attributes);
            return result;
        }

        result = store->insertMsgTrace(sender, messageId, deviceId, convState, filteredAttributes, attachments, true);
        if (SQL_FAIL(result)) {
            LOGGER(ERROR, __func__, " <-- Cannot store received message trace data.", result);
            return result;
        }
    LOGGER_END
    cleanupTrace(store);
    LOGGER(DEBUGGING, __func__ , " <-- ");
    return OK;
}

int32_t MessageCapture::captureSendMessage(const string &receiver, const string &messageId,const string &deviceId,
                                           const string &convState, const string &attributes, bool attachments)
{
    LOGGER(DEBUGGING, __func__, " -->");

    SQLiteStoreConv *store = SQLiteStoreConv::getStore();
    LOGGER_BEGIN(INFO)
        string filteredAttributes;
        int32_t result = filterAttributes(attributes, &filteredAttributes);
        if (result < 0) {
            LOGGER(ERROR, __func__, " Cannot parse sent message attributes: ", attributes);
            return result;
        }

        result = store->insertMsgTrace(receiver, messageId, deviceId, convState, filteredAttributes, attachments, false);
        if (SQL_FAIL(result)) {
            LOGGER(ERROR, __func__, " <-- Cannot store sent message trace data.", result);
            return result;
        }
    LOGGER_END
    cleanupTrace(store);
    LOGGER(DEBUGGING, __func__ , " <-- ");
    return OK;
}

shared_ptr<list<string> > MessageCapture::loadCapturedMsgs(const string &name, const string &messageId,
                                                           const string &deviceId, int32_t *sqlCode)
{
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
    return store->loadMsgTrace(name, messageId, deviceId, sqlCode);
}


