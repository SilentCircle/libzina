#include "ScDataRetention.h"

#include "../util/cJSON.h"
#include "../logging/ZinaLogging.h"
#include "../appRepository/AppRepository.h"
#include "../ratchet/state/ZinaConversation.h"

#include <zlib.h>

using namespace zina;
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
    memset_volatile(&zs, 0, sizeof(zs));

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

DrRequest::DrRequest(HTTP_FUNC httpHelper, S3_FUNC s3Helper, const std::string& authorization) :
    httpHelper_(httpHelper),
    s3Helper_(s3Helper),
    authorization_(authorization)
{
}

int DrRequest::getPresignedUrl(const std::string& url_suffix, const std::string& callid, const std::string& recipient, time_t startTime, DrRequest::MessageMetadata* metadata)
{
    LOGGER(INFO, __func__, " -->");

    static const char* requestUrl = "/drbroker/event/";

    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);

    cJSON_AddStringToObject(root.get(), "api_key", authorization_.c_str());
    cJSON_AddStringToObject(root.get(), "call_id", callid.c_str());
    cJSON_AddStringToObject(root.get(), "dst_alias", recipient.c_str());
    cJSON_AddStringToObject(root.get(), "url_suffix", url_suffix.c_str());
    cJSON_AddNumberToObject(root.get(), "start_time", static_cast<double>(startTime));
    cJSON_AddBoolToObject  (root.get(), "compressed", true);

    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());

    string result;
    int rc = httpHelper_(requestUrl, POST, request, &result);
    if (rc == 422) {
        // An Unprocessable Entity error means we sent invalid data. This isn't
        // correctable by us so we shouldn't retry the request.
        LOGGER(ERROR, "Unprocessable Entity error using data retention broker: ", result.c_str());
        return -2;
    }

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

MessageRequest::MessageRequest(HTTP_FUNC httpHelper,
                               S3_FUNC s3Helper,
                               const std::string& authorization,
                               const std::string& callid,
                               const std::string& direction,
                               const std::string& recipient,
                               time_t composed,
                               time_t sent,
                               const std::string& message) :
    DrRequest(httpHelper, s3Helper, authorization),
    callid_(callid),
    direction_(direction),
    recipient_(recipient),
    composed_(composed),
    sent_(sent),
    message_(message)
{
}

MessageRequest::MessageRequest(HTTP_FUNC httpHelper, S3_FUNC s3Helper, const std::string& authorization, cJSON* json) :
    DrRequest(httpHelper, s3Helper, authorization)
{
    callid_ = get_cjson_string(json, "callid");
    direction_ = get_cjson_string(json, "direction");
    recipient_ = get_cjson_string(json, "recipient");
    composed_ = get_cjson_time(json, "composed");
    sent_ = get_cjson_time(json, "sent");
    message_ = get_cjson_string(json, "message");
}

std::string MessageRequest::toJSON()
{
    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);
    cJSON_AddStringToObject(root.get(), "type", "MessageRequest");
    cJSON_AddStringToObject(root.get(), "callid", callid_.c_str());
    cJSON_AddStringToObject(root.get(), "direction", direction_.c_str());
    cJSON_AddStringToObject(root.get(), "recipient", recipient_.c_str());
    cJSON_AddNumberToObject(root.get(), "composed", static_cast<double>(composed_));
    cJSON_AddNumberToObject(root.get(), "sent", static_cast<double>(sent_));
    cJSON_AddStringToObject(root.get(), "message", message_.c_str());
    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());
    return request;
}

bool MessageRequest::run()
{
    LOGGER(INFO, __func__, " -->");
    if (!httpHelper_ || !s3Helper_) {
      LOGGER(ERROR, "HTTP Helper or S3 Helper not set.");
      return false;
    }
    MessageMetadata metadata;
    int rc = getPresignedUrl("message.txt", callid_, recipient_, sent_, &metadata);
    if (rc < 0) {
      LOGGER(ERROR, "Invalid presigned URL returned from data retention broker.");
      // Remove the request from the queue if the error is a failure that cannot be retried.
      return rc == -2;
    }

    std::string request = compress(message_);
    if (request.empty()) {
        LOGGER(ERROR, "Could not compress data retention data");
        return false;
    }

    string result;
    rc = s3Helper_(metadata.url.c_str(), request, &result);
    if (rc != 200) {
        LOGGER(ERROR, "Could not store message metadata.");
        return false;
    }

    LOGGER(INFO, __func__, " <--");
    return true;
}


MessageMetadataRequest::MessageMetadataRequest(HTTP_FUNC httpHelper,
                                               S3_FUNC s3Helper,
                                               const std::string& authorization,
                                               const std::string& callid,
                                               const std::string& direction,
                                               const std::string& recipient,
                                               time_t composed,
                                               time_t sent) :
    DrRequest(httpHelper, s3Helper, authorization),
    callid_(callid),
    direction_(direction),
    recipient_(recipient),
    composed_(composed),
    sent_(sent)
{
}

MessageMetadataRequest::MessageMetadataRequest(HTTP_FUNC httpHelper, S3_FUNC s3Helper, const std::string& authorization, cJSON* json) :
    DrRequest(httpHelper, s3Helper, authorization)
{
    callid_ = get_cjson_string(json, "callid");
    direction_ = get_cjson_string(json, "direction");
    recipient_ = get_cjson_string(json, "recipient");
    composed_ = get_cjson_time(json, "composed");
    sent_ = get_cjson_time(json, "sent");
}

std::string MessageMetadataRequest::toJSON()
{
    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);
    cJSON_AddStringToObject(root.get(), "type", "MessageMetadataRequest");
    cJSON_AddStringToObject(root.get(), "callid", callid_.c_str());
    cJSON_AddStringToObject(root.get(), "direction", direction_.c_str());
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
    if (!httpHelper_ || !s3Helper_) {
      LOGGER(ERROR, "HTTP Helper or S3 Helper not set.");
      return false;
    }
    MessageMetadata metadata;
    int rc = getPresignedUrl("event.json", callid_, recipient_, sent_, &metadata);
    if (rc < 0) {
      LOGGER(ERROR, "Invalid presigned URL returned from data retention broker.");
      // Remove the request from the queue if the error is a failure that cannot be retried.
      return rc == -2;
    }

    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);

    const bool sent = direction_ == "sent";
    cJSON_AddStringToObject(root.get(), "type", "message");
    cJSON_AddStringToObject(root.get(), "call_id", metadata.callid.c_str());
    cJSON_AddStringToObject(root.get(), "src_uuid", sent ?  metadata.src_uuid.c_str() : metadata.dst_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "src_alias", sent ?  metadata.src_alias.c_str() : metadata.dst_alias.c_str());
    cJSON_AddStringToObject(root.get(), "dst_uuid", sent ? metadata.dst_uuid.c_str() : metadata.src_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "dst_alias", sent ? metadata.dst_alias.c_str() : metadata.src_alias.c_str());
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
    rc = s3Helper_(metadata.url.c_str(), request, &result);
    if (rc != 200) {
        LOGGER(ERROR, "Could not store message metadata.");
        return false;
    }

    LOGGER(INFO, __func__, " <--");
    return true;
}

InCircleCallMetadataRequest::InCircleCallMetadataRequest(HTTP_FUNC httpHelper,
                                                         S3_FUNC s3Helper,
                                                         const std::string& authorization,
                                                         const std::string& callid,
                                                         const std::string direction,
                                                         const std::string recipient,
                                                         time_t start,
                                                         time_t end) :
    DrRequest(httpHelper, s3Helper, authorization),
    callid_(callid),
    direction_(direction),
    recipient_(recipient),
    start_(start),
    end_(end)
{
}

InCircleCallMetadataRequest::InCircleCallMetadataRequest(HTTP_FUNC httpHelper, S3_FUNC s3Helper, const std::string& authorization, cJSON* json) :
    DrRequest(httpHelper, s3Helper, authorization)
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
    if (!httpHelper_ || !s3Helper_) {
      LOGGER(ERROR, "HTTP Helper or S3 Helper not set.");
      return false;
    }
    MessageMetadata metadata;
    int rc = getPresignedUrl("event.json", callid_, recipient_, start_, &metadata);
    if (rc < 0) {
      LOGGER(ERROR, "Invalid presigned URL returned from data retention broker.");
      // Remove the request from the queue if the error is a failure that cannot be retried.
      return rc == -2;
    }

    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);

    const bool outgoing = direction_ == "placed";
    cJSON_AddStringToObject(root.get(), "type", "call");
    cJSON_AddStringToObject(root.get(), "call_id", metadata.callid.c_str());
    cJSON_AddStringToObject(root.get(), "call_type", "peer");
    cJSON_AddStringToObject(root.get(), "call_direction", direction_.c_str());
    cJSON_AddStringToObject(root.get(), "src_uuid", outgoing ? metadata.src_uuid.c_str() : metadata.dst_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "src_alias", outgoing ? metadata.src_alias.c_str() : metadata.dst_alias.c_str());
    cJSON_AddStringToObject(root.get(), "dst_uuid", outgoing ? metadata.dst_uuid.c_str() : metadata.src_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "dst_alias", outgoing ? metadata.dst_alias.c_str() : metadata.src_alias.c_str());
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
    rc = s3Helper_(metadata.url.c_str(), request, &result);
    if (rc != 200) {
        LOGGER(ERROR, "Could not store in call metadata.");
        return false;
    }

    LOGGER(INFO, __func__, " <--");
    return true;
}

SilentWorldCallMetadataRequest::SilentWorldCallMetadataRequest(HTTP_FUNC httpHelper,
                                                               S3_FUNC s3Helper,
                                                               const std::string& authorization,
                                                               const std::string& callid,
                                                               const std::string direction,
                                                               const std::string srctn,
                                                               const std::string dsttn,
                                                               time_t start,
                                                               time_t end) :
    DrRequest(httpHelper, s3Helper, authorization),
    callid_(callid),
    direction_(direction),
    srctn_(srctn),
    dsttn_(dsttn),
    start_(start),
    end_(end)
{
}

SilentWorldCallMetadataRequest::SilentWorldCallMetadataRequest(HTTP_FUNC httpHelper, S3_FUNC s3Helper, const std::string& authorization, cJSON* json) :
    DrRequest(httpHelper, s3Helper, authorization)
{
    callid_ = get_cjson_string(json, "callid");
    direction_ = get_cjson_string(json, "direction");
    srctn_ = get_cjson_string(json, "srctn");
    dsttn_ = get_cjson_string(json, "dsttn");
    start_ = get_cjson_time(json, "start");
    end_ = get_cjson_time(json, "end");
}

std::string SilentWorldCallMetadataRequest::toJSON()
{
    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);
    cJSON_AddStringToObject(root.get(), "type", "SilentWorldCallMetadataRequest");
    cJSON_AddStringToObject(root.get(), "callid", callid_.c_str());
    cJSON_AddStringToObject(root.get(), "direction", direction_.c_str());
    cJSON_AddStringToObject(root.get(), "srctn", srctn_.c_str());
    cJSON_AddStringToObject(root.get(), "dsttn", dsttn_.c_str());
    cJSON_AddNumberToObject(root.get(), "start", static_cast<double>(start_));
    cJSON_AddNumberToObject(root.get(), "end", static_cast<double>(end_));
    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());
    return request;
}

bool SilentWorldCallMetadataRequest::run()
{
    LOGGER(INFO, __func__, " -->");
    if (!httpHelper_ || !s3Helper_) {
      LOGGER(ERROR, "HTTP Helper or S3 Helper not set.");
      return false;
    }
    MessageMetadata metadata;
    int rc = getPresignedUrl("event.json", callid_, dsttn_, start_, &metadata);
    if (rc < 0) {
      LOGGER(ERROR, "Invalid presigned URL returned from data retention broker.");
      // Remove the request from the queue if the error is a failure that cannot be retried.
      return rc == -2;
    }

    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);

    cJSON_AddStringToObject(root.get(), "type", "call");
    cJSON_AddStringToObject(root.get(), "call_id", metadata.callid.c_str());
    cJSON_AddStringToObject(root.get(), "call_type", "pstn");
    cJSON_AddStringToObject(root.get(), "call_direction", direction_.c_str());
    cJSON_AddStringToObject(root.get(), "src_uuid", metadata.src_uuid.c_str());
    cJSON_AddStringToObject(root.get(), "src_tn", srctn_.c_str());
    cJSON_AddStringToObject(root.get(), "dst_tn", dsttn_.c_str());
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
    rc = s3Helper_(metadata.url.c_str(), request, &result);
    if (rc != 200) {
        LOGGER(ERROR, "Could not store in call metadata.");
        return false;
    }

    LOGGER(INFO, __func__, " <--");
    return true;
}

HTTP_FUNC ScDataRetention::httpHelper_ = nullptr;
S3_FUNC ScDataRetention::s3Helper_ = nullptr;
std::string ScDataRetention::authorization_;

void ScDataRetention::setHttpHelper(HTTP_FUNC httpHelper)
{
    httpHelper_ = httpHelper;
}

void ScDataRetention::setS3Helper(S3_FUNC s3Helper)
{
    s3Helper_ = s3Helper;
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
        request.reset(new MessageMetadataRequest(httpHelper_, s3Helper_, authorization_, root.get()));
    }
    else if (type == "InCircleCallMetadataRequest") {
        request.reset(new InCircleCallMetadataRequest(httpHelper_, s3Helper_, authorization_, root.get()));
    }
    else if (type == "SilentWorldCallMetadataRequest") {
        request.reset(new SilentWorldCallMetadataRequest(httpHelper_, s3Helper_, authorization_, root.get()));
    }
    else if (type == "MessageRequest") {
        request.reset(new MessageRequest(httpHelper_, s3Helper_, authorization_, root.get()));
    }
    else {
        LOGGER(ERROR, "Invalid DrRequest type.");
        return nullptr;
    }

    return request.release();
}


void ScDataRetention::sendMessageData(const std::string& callid, const std::string& direction, const std::string& recipient, time_t composed, time_t sent, const std::string& message)
{
    LOGGER(INFO, __func__, " -->");
    AppRepository* store = AppRepository::getStore();
    unique_ptr<DrRequest> request(new MessageRequest(httpHelper_, s3Helper_, authorization_, callid, direction, recipient, composed, sent, message));
    store->storeDrPendingEvent(time(NULL), request->toJSON().c_str());
    processRequests();
    LOGGER(INFO, __func__, " <--");
}

void ScDataRetention::sendMessageMetadata(const std::string& callid, const std::string& direction, const std::string& recipient, time_t composed, time_t sent)
{
    LOGGER(INFO, __func__, " -->");
    AppRepository* store = AppRepository::getStore();
    unique_ptr<DrRequest> request(new MessageMetadataRequest(httpHelper_, s3Helper_, authorization_, callid, direction, recipient, composed, sent));
    store->storeDrPendingEvent(time(NULL), request->toJSON().c_str());
    processRequests();
    LOGGER(INFO, __func__, " <--");
}

void ScDataRetention::sendInCircleCallMetadata(const std::string& callid, const std::string& direction, const std::string& recipient, time_t start, time_t end)
{
    LOGGER(INFO, __func__, " -->");
    AppRepository* store = AppRepository::getStore();
    unique_ptr<DrRequest> request(new InCircleCallMetadataRequest(httpHelper_, s3Helper_, authorization_, callid, direction, recipient, start, end));
    store->storeDrPendingEvent(time(NULL), request->toJSON().c_str());
    processRequests();
    LOGGER(INFO, __func__, " <--");
}

void ScDataRetention::sendSilentWorldCallMetadata(const std::string& callid, const std::string& direction, const std::string& srctn, const std::string& dsttn, time_t start, time_t end)
{
    LOGGER(INFO, __func__, " -->");
    AppRepository* store = AppRepository::getStore();
    unique_ptr<DrRequest> request(new SilentWorldCallMetadataRequest(httpHelper_, s3Helper_, authorization_, callid, direction, srctn, dsttn, start, end));
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
                LOGGER(ERROR, "Could not run data retention pending request - remaining in the queue to retry later");
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

    static const char* baseUrl = "/drbroker/check/?api_key=";

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

int ScDataRetention::isEnabled(const string& user, bool* enabled)
{
    LOGGER(INFO, __func__, " -->");

    static const char* baseUrl = "/drbroker/check-user/";

    std::string requestUrl(baseUrl);

    cjson_ptr root(cJSON_CreateObject(), cJSON_Delete);

    cJSON_AddStringToObject(root.get(), "api_key", authorization_.c_str());
    cJSON_AddStringToObject(root.get(), "alias", user.c_str());

    unique_ptr<char, void (*)(void*)> out(cJSON_PrintUnformatted(root.get()), free);
    std::string request(out.get());

    string result;
    int rc = httpHelper_(requestUrl, POST, request, &result);
    if (rc == 422) {
        // An Unprocessable Entity error means we sent invalid data. This isn't
        // correctable by us so we shouldn't retry the request.
        LOGGER(ERROR, "Unprocessable Entity error using data retention broker: ", result.c_str());
        return -2;
    }

    if (rc != 200) {
        LOGGER(ERROR, "Could not access data retention broker.");
        return -1;
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
