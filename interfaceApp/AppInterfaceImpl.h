#ifndef UIINTERFACEIMPL_H
#define UIINTERFACEIMPL_H

/**
 * @file AppInterfaceImpl.h
 * @brief Implementation of the UI interface methods
 * @ingroup Axolotl++
 * @{
 */

#include <stdint.h>

#include "AppInterface.h"
#include "../storage/sqlite/SQLiteStoreConv.h"

// Same as in ScProvisioning, keep in sync
typedef int32_t (*HTTP_FUNC)(const string& requestUri, const string& requestData, const string& method, string* response);

using namespace std;

namespace axolotl {
class SipTransport;

class AppInterfaceImpl : public AppInterface
{
public:
#ifdef UNITTESTS
    AppInterfaceImpl(SQLiteStoreConv* store) : AppInterface(), tempBuffer_(NULL), store_(store), transport_(NULL) {}
    AppInterfaceImpl(SQLiteStoreConv* store, const string& ownUser, const string& authorization, const string& scClientDevId) : 
                    AppInterface(), tempBuffer_(NULL), ownUser_(ownUser), authorization_(authorization), scClientDevId_(scClientDevId), 
                    store_(store), transport_(NULL), ownChecked_(false) {}
#endif
    AppInterfaceImpl(const string& ownUser, const string& authorization, const string& scClientDevId, 
                     RECV_FUNC receiveCallback, STATE_FUNC stateReportCallback, NOTIFY_FUNC notifyCallback);

    ~AppInterfaceImpl();

    // Documentation see AppInterface.h
    void setTransport(Transport* transport) { transport_ = transport; }

    Transport* getTransport()               { return transport_; }

    vector<int64_t>* sendMessage(const string& messageDescriptor, const string& attachementDescriptor, const string& messageAttributes);

    vector<int64_t>* sendMessageToSiblings(const string& messageDescriptor, const string& attachementDescriptor, const string& messageAttributes);

    int32_t receiveMessage(const string& messageEnvelope);

    int32_t receiveMessage(const string& messageEnvelope, const string& uid, const string& alias);

    void messageStateReport(int64_t messageIdentfier, int32_t statusCode, const string& stateInformation);

    string* getKnownUsers();

    /**
     * @brief Get own identity key and device name.
     *
     * The returned string contains the B64 encoded data of the own public identity key
     * followed by a colon and the device name. Thus the returned string:
     *
     *   @c identityKey:deviceName
     *
     * @return formatted string, device name part may be empty if no device name was defined.
     */
    string getOwnIdentityKey() const;

    /**
     * @brief Get a list of all identity keys a remote parts.
     *
     * The remote partner may have more than one device. This function returns the identity
     * keys of remote user's devices that this client knows of. The client sends messages only
     * to these known device of the remote user.
     *
     * The returned strings in the list contain the B64 encoded data of the public identity keys
     * of the known devices, followed by a colon and the device name, followed by a colon and the
     * the device id, followed by a colon and the ZRTP verify state. Format of the returned string:
     *
     *   @c identityKey:deviceName:deviceId:verifyState
     *
     * The device name part may be empty if no device name was defined.
     *
     * @param user the name of the user
     * @return list of formatted strings, empty list if no information is available for that user.
     */
    list<string>* getIdentityKeys(string& user) const;

    int32_t registerAxolotlDevice(string* result);

    int32_t removeAxolotlDevice(string& scClientDevId, string* result);

    int32_t newPreKeys(int32_t number);

    int32_t getNumPreKeys() const;

    void rescanUserDevices(string& userName);

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
    const string& getErrorInfo() { return errorInfo_; }

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

    vector<int64_t>* sendMessageInternal(const string& recipient, const string& msgId, const string& message,
                                         const string& attachementDescriptor, const string& messageAttributes);

    vector<pair<string, string> >* sendMessagePreKeys(const string& recipient, const string& msgId, const string& message,
                                                      const string& attachementDescriptor, const string& messageAttributes);

    int32_t parseMsgDescriptor(const string& messageDescriptor, string* recipient, string* msgId, string* message );

    int32_t createPreKeyMsg(const string& recipient, const string& recipientDeviceId, const string& recipientDeviceName, const string& message, 
                            const string& supplements, const string& msgId, vector< pair< string, string > >* msgPairs );
    char* tempBuffer_;
    size_t tempBufferSize_;
    string ownUser_;
    string authorization_;
    string scClientDevId_;

    int32_t errorCode_;
    string errorInfo_;
    SQLiteStoreConv* store_;
    Transport* transport_;
    int32_t flags_;
    // If this is true then we checked own devices and see only one device for
    // own account it's the sending device. If another device registers for this
    // account it sends out a sync message, the client receives this and we have
    // a second device
    bool ownChecked_;
};
} // namespace

/**
 * @}
 */

#endif // UIINTERFACEIMPL_H
