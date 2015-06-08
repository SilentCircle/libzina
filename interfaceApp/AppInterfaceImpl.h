#ifndef UIINTERFACEIMPL_H
#define UIINTERFACEIMPL_H

/**
 * @file UiInterfaceImpl.h
 * @brief Implementation of the UI interface methods
 * @ingroup Axolotl++
 * @{
 * 
 * The implementation of this class is not thread safe.
 */

#include <stdint.h>

#include "AppInterface.h"
#include "../storage/sqlite/SQLiteStoreConv.h"

// Same as in ScProvisioning, keep in sync
typedef int32_t (*HTTP_FUNC)(const std::string& requestUri, const std::string& requestData, const std::string& method, std::string* response);

namespace axolotl {
class SipTransport;

class AppInterfaceImpl : public AppInterface
{
public:
#ifdef UNITTESTS
    AppInterfaceImpl(SQLiteStoreConv* store) : AppInterface(), tempBuffer_(NULL), store_(store), transport_(NULL) {}
    AppInterfaceImpl(SQLiteStoreConv* store, const std::string& ownUser, const std::string& authorization, const std::string& scClientDevId) : 
                    AppInterface(), tempBuffer_(NULL), ownUser_(ownUser), authorization_(authorization), scClientDevId_(scClientDevId), 
                    store_(store), transport_(NULL) {}
#endif
    AppInterfaceImpl(const std::string& ownUser, const std::string& authorization, const std::string& scClientDevId, 
                     RECV_FUNC receiveCallback, STATE_FUNC stateReportCallback);

    ~AppInterfaceImpl();

    // Documentation see AppInterface.h
    void setTransport(Transport* transport) { transport_ = transport; }

    Transport* getTransport()               { return transport_; }

    std::vector<int64_t>* sendMessage(const std::string& messageDescriptor, 
                                      const std::string& attachementDescriptor, 
                                      const std::string& messageAttributes);

    int32_t receiveMessage(const std::string& messageEnvelope);

    void messageStateReport(int64_t messageIdentfier, int32_t statusCode, const std::string& stateInformation);

    std::string* getKnownUsers();

    int32_t registerAxolotlDevice(std::string* result);

    int32_t newPreKeys(int32_t number);

    /**
     * @brief Return the stored error code.
     * 
     * Functions of this implementation store error code in case they detect
     * a problem and return @c NULL, for example. In this case the caller should
     * get the error code and the additional error information for detailled error
     * data.
     * 
     * Functions overwrite the stored error code only if they return @c NULL or some
     * other error indicator.
     * 
     * @return The stored error code.
     */
    int32_t getErrorCode()            { return errorCode_; }

    /**
     * @brief Return the stored error information.
     * 
     * Functions of this implementation store error information in case they detect
     * a problem and return @c NULL, for example. In this case the caller should
     * get the error code and the additional error information for detailed error
     * data.
     * 
     * Functions overwrite the stored error information only if they return @c NULL 
     * or some other error indicator.
     * 
     * @return The stored error information string.
     */
    const std::string& getErrorInfo() { return errorInfo_; }

    /**
     * @brief Initialization code must set a HTTP helper function
     * 
     * @param httpHelper Pointer to the helper functions
     */
    static void setHttpHelper(HTTP_FUNC httpHelper);


private:
    // not support for copy, assignment and equals
    AppInterfaceImpl ( const AppInterfaceImpl& other ) {}
    AppInterfaceImpl& operator= ( const AppInterfaceImpl& other ) {}
    bool operator== ( const AppInterfaceImpl& other ) const {}

    std::vector<std::pair<std::string, std::string> >* sendMessagePreKeys(const std::string& messageDescriptor,
                                                                          const std::string& attachementDescriptor,
                                                                          const std::string& messageAttributes);

    int32_t parseMsgDescriptor(const std::string& messageDescriptor, std::string* recipient, std::string* message);

    int32_t createPreKeyMsg(string& recipient,  const std::string& recipientDeviceId, 
                            const std::string& message, const std::string& supplements, 
                            std::vector<std::pair<std::string, std::string> >* msgPairs);
    char* tempBuffer_;
    size_t tempBufferSize_;
    std::string ownUser_;
    std::string authorization_;
    std::string scClientDevId_;

    int32_t errorCode_;
    std::string errorInfo_;
    SQLiteStoreConv* store_;
    Transport* transport_;
};
} // namespace

/**
 * @}
 */

#endif // UIINTERFACEIMPL_H
