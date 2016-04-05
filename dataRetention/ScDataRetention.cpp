#include "ScDataRetention.h"

#include "../util/cJSON.h"
#include "../util/b64helper.h"
#include "../logging/AxoLogging.h"
#include "../appRepository/AppRepository.h"

#include <memory>
#include <zlib.h>

using namespace axolotl;
using namespace std;

namespace {
static const string GET("GET");
static const string PUT("PUT");
static const string POST("POST");
static const string DELETE("DELETE");

typedef unique_ptr<cJSON, void (*)(cJSON*)> cjson_ptr;

std::string get_cjson_string(cJSON* root, const std::string& key)
{
    cJSON* cj = cJSON_GetObjectItem(root, key.c_str());
    if (!cj) {
        return "";
    }

    const char* jsString = cj->valuestring;
    if (!jsString) {
        return "";
    }
    std::string r(jsString);
    return r;
}

time_t get_cjson_time(cJSON* root, const std::string& key)
{
    cJSON* cj = cJSON_GetObjectItem(root, key.c_str());
    if (!cj) {
        return 0;
    }

    return static_cast<time_t>(cj->valuedouble);
}

std::string time_to_string(time_t time)
{
    char buf[40];
    strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", gmtime(&time));
    return std::string(buf);
}

#define USE_GZIP_FORMAT 16
#define ZLIB_DEFAULT_WINDOW_BITS 15
#define ZLIB_DEFAULT_MEMLEVEL 8

std::string compress(const std::string& input)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED,
                     ZLIB_DEFAULT_WINDOW_BITS + USE_GZIP_FORMAT, ZLIB_DEFAULT_MEMLEVEL,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        LOGGER(ERROR, "gzip compression of data retention data failed.");
      return "";
    }

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    zs.avail_in = input.size();

    const int buffer_size = 4096;
    unique_ptr<char> buffer(new char[buffer_size]);
    std::string output;
    int r = Z_OK;

    do {
        zs.next_out = reinterpret_cast<Bytef*>(buffer.get());
        zs.avail_out = buffer_size;

        r = deflate(&zs, Z_FINISH);

        if (output.size() < zs.total_out) {
            output.append(buffer.get(),
                          zs.total_out - output.size());
        }
    } while (r == Z_OK);

    deflateEnd(&zs);
    if (r != Z_STREAM_END) {
        LOGGER(ERROR, "gzip compression of data retention data failed.");
        return "";
    }

    return output;
}
}

DrRequest::DrRequest(HTTP_FUNC httpHelper, const std::string& authorization) :
    httpHelper_(httpHelper),
    authorization_(authorization)
{
}

int DrRequest::getPresignedUrl(const std::string& callid, const std::string& recipient, time_t startTime, DrRequest::MessageMetadata* metadata)
{
    LOGGER(INFO, __func__, " -->");

    static const char* requestUrl = "/drbroker/event";

    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);

    cJSON_AddStringToObject(root.get(), "api_key", authorization_.c_str());
    cJSON_AddStringToObject(root.get(), "call_id", callid.c_str());
    cJSON_AddStringToObject(root.get(), "dst_alias", recipient.c_str());
    cJSON_AddNumberToObject(root.get(), "start_time", static_cast<double>(startTime));
    cJSON_AddBoolToObject  (root.get(), "compressed", true);

    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());

    string result;
    int rc = httpHelper_(requestUrl, POST, request, &result);
    if (rc != 200) {
        LOGGER(ERROR, "Could not access data retention broker.");
        return -1;
    }

    root.reset(cJSON_Parse(result.c_str()));
    if (!root) {
        LOGGER(ERROR, "Invalid result from data retention broker.");
        return -1;
    }

    string url = get_cjson_string(root.get(), "url");
    string src_uuid = get_cjson_string(root.get(), "src_uuid");
    string src_alias = get_cjson_string(root.get(), "src_alias");
    string dst_uuid = get_cjson_string(root.get(), "dst_uuid");
    string dst_alias = get_cjson_string(root.get(), "dst_alias");

    if (url.empty() ||
        src_uuid.empty() ||
        src_alias.empty() ||
        dst_uuid.empty() ||
        dst_alias.empty()) {
        LOGGER(ERROR, "Missing data from data retention broker.");
        return -1;
    }

    metadata->url = url;
    metadata->callid = callid;
    metadata->src_uuid = src_uuid;
    metadata->src_alias = src_alias;
    metadata->dst_uuid = dst_uuid;
    metadata->dst_alias = dst_alias;

    LOGGER(INFO, __func__, " <--");
    return 0;
}


MessageMetadataRequest::MessageMetadataRequest(HTTP_FUNC httpHelper,
                                               const std::string& authorization,
                                               const std::string& callid,
                                               const std::string& recipient,
                                               time_t composed,
                                               time_t sent) :
    DrRequest(httpHelper, authorization),
    callid_(callid),
    recipient_(recipient),
    composed_(composed),
    sent_(sent)
{
}

MessageMetadataRequest::MessageMetadataRequest(HTTP_FUNC httpHelper, const std::string& authorization, cJSON* json) :
    DrRequest(httpHelper, authorization)
{
    callid_ = get_cjson_string(json, "callid");
    recipient_ = get_cjson_string(json, "recipient");
    composed_ = get_cjson_time(json, "composed");
    sent_ = get_cjson_time(json, "sent");
}

std::string MessageMetadataRequest::toJSON()
{
    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);
    cJSON_AddStringToObject(root.get(), "type", "MessageMetadataRequest");
    cJSON_AddStringToObject(root.get(), "callid", callid_.c_str());
    cJSON_AddStringToObject(root.get(), "recipient", recipient_.c_str());
    cJSON_AddNumberToObject(root.get(), "composed", static_cast<double>(composed_));
    cJSON_AddNumberToObject(root.get(), "sent", static_cast<double>(sent_));
    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());
    return request;
}

bool MessageMetadataRequest::run()
{
    LOGGER(INFO, __func__, " -->");
    MessageMetadata metadata;
    int rc = getPresignedUrl(callid_, recipient_, sent_, &metadata);
    if (rc < 0) {
      LOGGER(ERROR, "Invalid presigned URL returned from data retention broker.");
      return false;
    }

    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);

    cJSON_AddStringToObject(root.get(), "type", "message");
    cJSON_AddStringToObject(root.get(), "call_id", metadata.callid.c_str());
    cJSON_AddStringToObject(root.get(), "src_uuid", metadata.src_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "src_alias", metadata.src_alias.c_str());
    cJSON_AddStringToObject(root.get(), "dst_uuid", metadata.dst_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "dst_alias", metadata.dst_alias.c_str());
    cJSON_AddStringToObject(root.get(), "composed_on", time_to_string(composed_).c_str());
    cJSON_AddStringToObject(root.get(), "sent_on", time_to_string(sent_).c_str());

    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());
    request = compress(request);
    if (request.empty()) {
        LOGGER(ERROR, "Could not compress data retention data");
        return false;
    }

    string result;
    rc = httpHelper_(metadata.url.c_str(), PUT, request, &result);
    if (rc != 200) {
        LOGGER(ERROR, "Could not store message metadata.");
        return false;
    }

    LOGGER(INFO, __func__, " <--");
    return true;
}

InCircleCallMetadataRequest::InCircleCallMetadataRequest(HTTP_FUNC httpHelper,
                                                         const std::string& authorization,
                                                         const std::string& callid,
                                                         const std::string direction,
                                                         const std::string recipient,
                                                         time_t start,
                                                         time_t end) :
    DrRequest(httpHelper, authorization),
    callid_(callid),
    direction_(direction),
    recipient_(recipient),
    start_(start),
    end_(end)
{
}

InCircleCallMetadataRequest::InCircleCallMetadataRequest(HTTP_FUNC httpHelper, const std::string& authorization, cJSON* json) :
    DrRequest(httpHelper, authorization)
{
    callid_ = get_cjson_string(json, "callid");
    direction_ = get_cjson_string(json, "direction");
    recipient_ = get_cjson_string(json, "recipient");
    start_ = get_cjson_time(json, "start");
    end_ = get_cjson_time(json, "end");
}

std::string InCircleCallMetadataRequest::toJSON()
{
    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);
    cJSON_AddStringToObject(root.get(), "type", "InCircleCallMetadataRequest");
    cJSON_AddStringToObject(root.get(), "callid", callid_.c_str());
    cJSON_AddStringToObject(root.get(), "direction", direction_.c_str());
    cJSON_AddStringToObject(root.get(), "recipient", recipient_.c_str());
    cJSON_AddNumberToObject(root.get(), "start", static_cast<double>(start_));
    cJSON_AddNumberToObject(root.get(), "end", static_cast<double>(end_));
    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());
    return request;
}

bool InCircleCallMetadataRequest::run()
{
    LOGGER(INFO, __func__, " -->");
    MessageMetadata metadata;
    int rc = getPresignedUrl(callid_, recipient_, start_, &metadata);
    if (rc < 0) {
      LOGGER(ERROR, "Invalid presigned URL returned from data retention broker.");
      return false;
    }

    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);

    cJSON_AddStringToObject(root.get(), "type", "call");
    cJSON_AddStringToObject(root.get(), "call_id", metadata.callid.c_str());
    cJSON_AddStringToObject(root.get(), "call_type", "peer");
    cJSON_AddStringToObject(root.get(), "call_direction", direction_.c_str());
    cJSON_AddStringToObject(root.get(), "src_uuid", metadata.src_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "src_alias", metadata.src_alias.c_str());
    cJSON_AddStringToObject(root.get(), "dst_uuid", metadata.dst_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "dst_alias", metadata.dst_alias.c_str());
    cJSON_AddStringToObject(root.get(), "start_on", time_to_string(start_).c_str());
    cJSON_AddStringToObject(root.get(), "end_on", time_to_string(end_).c_str());

    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());
    request = compress(request);
    if (request.empty()) {
        LOGGER(ERROR, "Could not compress data retention data");
        return false;
    }

    string result;
    rc = httpHelper_(metadata.url.c_str(), PUT, request, &result);
    if (rc != 200) {
        LOGGER(ERROR, "Could not store in call metadata.");
        return false;
    }

    LOGGER(INFO, __func__, " <--");
    return true;
}

int32_t (*ScDataRetention::httpHelper_)(const std::string&, const std::string&, const std::string&, std::string*) = NULL;
std::string ScDataRetention::authorization_;

void ScDataRetention::setHttpHelper(int32_t (*httpHelper)( const std::string&, const std::string&, const std::string&, std::string* ))
{
    httpHelper_ = httpHelper;
}

void ScDataRetention::setAuthorization(const std::string& authorization)
{
    authorization_ = authorization;
}

DrRequest* ScDataRetention::requestFromJSON(const std::string& json)
{
    unique_ptr<DrRequest> request;
    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);
    root.reset(cJSON_Parse(json.c_str()));
    if (!root) {
        LOGGER(ERROR, "Invalid JSON.");
        return nullptr;
    }

    string type = get_cjson_string(root.get(), "type");
    if (type == "MessageMetadataRequest") {
        request.reset(new MessageMetadataRequest(httpHelper_, authorization_, root.get()));
    }
    else if (type == "InCircleCallMetadataRequest") {
        request.reset(new InCircleCallMetadataRequest(httpHelper_, authorization_, root.get()));
    }
    else {
        LOGGER(ERROR, "Invalid DrRequest type.");
        return nullptr;
    }

    return request.release();
}


void ScDataRetention::sendMessageMetadata(const std::string& callid, const std::string& recipient, time_t composed, time_t sent)
{
    LOGGER(INFO, __func__, " -->");
    AppRepository* store = AppRepository::getStore();
    unique_ptr<DrRequest> request(new MessageMetadataRequest(httpHelper_, authorization_, callid, recipient, composed, sent));
    store->storeDrPendingEvent(time(NULL), request->toJSON().c_str());
    processRequests();
    LOGGER(INFO, __func__, " <--");
}

void ScDataRetention::sendInCircleCallMetadata(const std::string& callid, const std::string& direction, const std::string& recipient, time_t start, time_t end)
{
    LOGGER(INFO, __func__, " -->");
    AppRepository* store = AppRepository::getStore();
    unique_ptr<DrRequest> request(new InCircleCallMetadataRequest(httpHelper_, authorization_, callid, direction, recipient, start, end));
    store->storeDrPendingEvent(time(NULL), request->toJSON().c_str());
    processRequests();
    LOGGER(INFO, __func__, " <--");
}

void ScDataRetention::processRequests()
{
    LOGGER(INFO, __func__, " -->");

    bool enabled = false;
    if (ScDataRetention::isEnabled(&enabled) != 200) {
        LOGGER(ERROR, "Could not determine if data retention is enabled.");
        return;
    }

    AppRepository* store = AppRepository::getStore();
    list<pair<int64_t, string>> objects;
    vector<int64_t> rowsToDelete;

    store->loadDrPendingEvents(objects);
    for (auto object : objects) {
        int64_t row = object.first;

        // If data retention is not enabled we don't submit the data but we do
        // delete the pending event from our local database table.
        if (enabled) {
            string json(object.second);
            unique_ptr<DrRequest> request(requestFromJSON(json));
            if (!request) {
                LOGGER(ERROR, "Could not parse data retention pending request JSON");
                continue;
            }
            if (!request->run()) {
                LOGGER(ERROR, "Could not run data retention pending request");
                // If the request failed to run we don't run any further requests. This
                // is to avoid multiple failures if the drbroker service is down
                // or network access isn't available. They'll be retried on the next
                // message send.
                break;
            }
        }

        rowsToDelete.push_back(row);
    }

    store->deleteDrPendingEvents(rowsToDelete);
    LOGGER(INFO, __func__, " <--");
}

int ScDataRetention::isEnabled(bool* enabled)
{
    LOGGER(INFO, __func__, " -->");

    static const char* baseUrl = "/drbroker/check?api_key=";

    std::string requestUrl(baseUrl);
    requestUrl += authorization_;

    string result;
    int rc = httpHelper_(requestUrl, GET, "", &result);

    if (rc != 200) {
        LOGGER(ERROR, "Could not access data retention broker.");
        LOGGER(INFO, __func__, " <--");
        return rc;
    }

    // Trim trailing whitespace
    result.erase(result.find_last_not_of("\f\n\r\t\v") + 1);

    if (result == "true") {
        *enabled = true;
    }
    else if (result == "false") {
        *enabled = false;
    }
    else {
        LOGGER(ERROR, "Invalid data returned from data retention broker.");
        rc = 500;
    }

    return rc;
}