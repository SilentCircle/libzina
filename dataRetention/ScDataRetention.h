#ifndef SCDATARETENTION_H
#define SCDATARETENTION_H

/**
 * @file ScDataRetention.h
 * @brief Implementation of the data retention interface for Silent Circle.
 * @ingroup Axolotl++
 * @{
 */

#include <string>
#include <memory>
#include <time.h>

typedef int32_t (*HTTP_FUNC)(const std::string& requestUri, const std::string& method, const std::string& requestData, std::string* response);

struct cJSON;

namespace axolotl {

class DrRequest {
private:
    std::string authorization_;
protected:
    HTTP_FUNC httpHelper_;

    struct MessageMetadata {
      std::string url;
      std::string callid;
      std::string src_uuid;
      std::string src_alias;
      std::string dst_uuid;
      std::string dst_alias;
    };

    /**
     * @brief Requests a presigned Amazon S3 URL and other associated metadata for the user.
     *
     * This uses httpHelper to make a request to the Data Retention Broker.
     *
     * @param callid The callid of the message or call.
     * @param recipient The userid of the recipient of the message.
     * @param startTime The start time of the message or call.
     * @param metadata The data returned by the data retention broker.
     * @return zero on success, negative number on failure.
     */
    int getPresignedUrl(const std::string& callid,
                        const std::string& recipient,
                        time_t startTime,
                        MessageMetadata* metadata);

public:
    /**
     * @brief Base constructor for a Data Retention request
     *
     * @param httpHelper HTTP helper function used to make HTTP requests.
     * @param authorization API Key for making AW requests.
     */
    explicit DrRequest(HTTP_FUNC httpHelper, const std::string& authorization);
    virtual ~DrRequest() { }

    /**
     * @brief Convert request to a serialized JSON format for storage in pending events database.
     *
     * @return Serialized request in a JSON string.
     */
    virtual std::string toJSON() = 0;

    /**
     * @brief Run the request. Makes HTTP requests via HTTP helper.
     *
     * @return Serialized request in a JSON string.
     */
    virtual bool run() = 0;

    DrRequest(DrRequest const&); // = delete;
    void operator=(DrRequest const&); // = delete;
};

class MessageMetadataRequest : public DrRequest {
private:
    std::string callid_;
    std::string recipient_;
    time_t composed_;
    time_t sent_;

public:
    /**
     * @brief Construct a Message data retention request
     *
     * @param httpHelper HTTP helper function used to make HTTP requests.
     * @param authorization API Key for making AW requests.
     * @param callid Callid for the message.
     * @param recipient Userid of the recipient of the message.
     * @param composed Time that the message was composed.
     * @param sent Time that the message was sent.
     */
    MessageMetadataRequest(HTTP_FUNC httpHelper,
                           const std::string& authorization,
                           const std::string& callid,
                           const std::string& recipient,
                           time_t composed,
                           time_t sent);
    MessageMetadataRequest(HTTP_FUNC httpHelper, const std::string& authorization, cJSON* json);
    virtual std::string toJSON() override;
    virtual bool run() override;
};

class InCircleCallMetadataRequest : public DrRequest {
private:
    std::string callid_;
    std::string direction_;
    std::string recipient_;
    time_t start_;
    time_t end_;

public:
    /**
     * @brief Construct an in circle call data retention request
     *
     * @param httpHelper HTTP helper function used to make HTTP requests.
     * @param authorization API Key for making AW requests.
     * @param callid Callid for the message.
     * @param direction "placed" or "received" indicating direction of call.
     * @param recipient Userid of the recipient of the call.
     * @param start Time that the call started.
     * @param end Time that the call ended.
     */
    InCircleCallMetadataRequest(HTTP_FUNC httpHelper,
                                const std::string& authorization_,
                                const std::string& callid,
                                const std::string direction,
                                const std::string recipient,
                                time_t start,
                                time_t end);
    InCircleCallMetadataRequest(HTTP_FUNC httpHelper, const std::string& authorization, cJSON* json);
    virtual std::string toJSON() override;
    virtual bool run() override;
};

class ScDataRetention
{
public:
    /**
     * @brief Initialization code must set a HTTP helper function
     *
     * @param httpHelper Pointer to the helper functions
     */
    static void setHttpHelper(HTTP_FUNC httpHelper);

    /**
     * @brief Initialization code must set the API Key for AW calls.
     *
     * @param authorization API key for AW calls.
     */
    static void setAuthorization(const std::string& authorization);

private:
    /**
     * @brief function pointer to the HTTP helper function
     *
     * This is a blocking function and returns after the server answered the HTTP request.
     * The @c requestUri includes the protocol specifier, e.g. HTTP or HTTPS, and 
     * the domain name. The helper function should not add a protocol or domain as it
     * usually does for internal AW requests if one is already provided.
     *
     * @param requestUri This is the request URL.
     * @param method the method to use, for example PUT or GET
     * @param requestData This is data for the request, JSON string, not every request has data
     * @param response This string receives the response, usually a JSON formatted string
     * @return the request return code, usually a HTTP code like 200 or something like that.
     */
    static HTTP_FUNC httpHelper_;

    static std::string authorization_;

public:
    ScDataRetention() {}
    ~ScDataRetention() {}

    /**
     * @brief Convert a serialized request in JSON format back to a DrRequest object
     *
     * @param json A serialized DrRequest object in JSON format.
     * @return The DrRequest object deserialized from JSON.
     */
    static DrRequest* requestFromJSON(const std::string& json);

    /**
     * @brief Store a message data retention event in the customers Amazon S3 bucket.
     *
     * If the request fails it is stored in a sqlite table and will be retried
     * on the next message or call send.
     *
     * @param callid Callid for the message.
     * @param recipient Userid of the recipient of the message.
     * @param composed Time that the message was composed.
     * @param sent Time that the message was sent.
     */
    static void sendMessageMetadata(const std::string& callid,
                                    const std::string& recipient,
                                    time_t composed,
                                    time_t sent);
    /**
     * @brief Store an in circle call data retention event in the customers Amazon S3 bucket.
     *
     * If the request fails it is stored in a sqlite table and will be retried
     * on the next message or call send.
     *
     * @param callid Callid for the message.
     * @param direction "placed" or "received" indicating direction of call.
     * @param recipient Userid of the recipient of the call.
     * @param start Time that the call started.
     * @param end Time that the call ended.
     */
    static void sendInCircleCallMetadata(const std::string& callid,
                                         const std::string& direction,
                                         const std::string& recipient,
                                         time_t start,
                                         time_t end);
    /**
     * @brief Run all stored pending data retention requests.
     *
     * Iterates over stored pending requests and executes them. They
     * are removed from the pending request table if they succeed. If
     * a request fails then none of the remaining pending requests are
     * executed. They'll be retried next time a message or call happens.
     *
     * This is run after any message or call data retention request is
     * made. It can also be called by a client to send outstanding
     * requests on resumption of network connection or startup.
     */
    static void processRequests();

    /**
     * @brief Get status of whether the user has data retention enabled on their account.
     *
     * This will make an HTTP request using httpHelper to the Data Retention broker.
     *
     * @param enabled Will contain true or false depending if data retention is enabled
     *        on the account. If the request fails then it is unchanged.
     * @return HTTP status code of AW request to determine if data retention is enabled.
     */
    static int isEnabled(bool* enabled);

    ScDataRetention(const ScDataRetention& other)  = delete;
    ScDataRetention& operator=(const ScDataRetention& other)  = delete;
    bool operator==(const ScDataRetention& other) const = delete;

};
} // namespace

/**
 * @}
 */

#endif // SCDATARETENTION_H