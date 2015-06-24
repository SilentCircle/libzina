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

using namespace std;

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

    string* getKnownUsers();

    string getOwnIdentityKey() const;

    list<string>* getIdentityKeys(string& user) const;

    int32_t registerAxolotlDevice(string* result);

    int32_t removeAxolotlDevice(string& scClientDevId, string* result);

    int32_t newPreKeys(int32_t number);

    int32_t getNumPreKeys() const;

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
    int32_t getErrorCode() const             { return errorCode_; }

    /**
     * @brief Get name of local user for this Axolotl conversation.
     */
    const string& getOwnUser() const         { return ownUser_; }

    /**
     * @brief Get authorization data of local user.
     */
    const string& getOwnAuthrization() const { return authorization_; }

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

    void setFlags(int32_t flags)  { flags_ = flags; }

    bool isRegistered()           {return ((flags_ & 0x1) == 1); }

private:
    // not support for copy, assignment and equals
    AppInterfaceImpl ( const AppInterfaceImpl& other ) {}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type"
    AppInterfaceImpl& operator= ( const AppInterfaceImpl& other ) { }
    bool operator== ( const AppInterfaceImpl& other ) const { }
#pragma clang diagnostic pop

    std::vector<std::pair<std::string, std::string> >* sendMessagePreKeys(const std::string& messageDescriptor,
                                                                          const std::string& attachementDescriptor,
                                                                          const std::string& messageAttributes);

    int32_t parseMsgDescriptor( const string& messageDescriptor, string* recipient, string* msgId, string* message );

    int32_t createPreKeyMsg( string& recipient, const string& recipientDeviceId, const string& message, const string& supplements, const string& msgId, vector< pair< string, string > >* msgPairs );
    char* tempBuffer_;
    size_t tempBufferSize_;
    std::string ownUser_;
    std::string authorization_;
    std::string scClientDevId_;

    int32_t errorCode_;
    std::string errorInfo_;
    SQLiteStoreConv* store_;
    Transport* transport_;
    int32_t flags_;
};
} // namespace

/**
 * @}
 */

#endif // UIINTERFACEIMPL_H
