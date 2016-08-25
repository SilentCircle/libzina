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
#ifndef ZRTPCONNECTOR_H
#define ZRTPCONNECTOR_H
/**
 * @file AxoZrtpConnector.h
 * @brief Functions to link the Axolotl protocol with a ZRTP client
 * @ingroup Axolotl++
 * @{
 */

#include <string>
#include <stdint.h>

#include "state/AxoConversation.h"
#include "crypto/DhKeyPair.h"

/**
 * @brief Get the public keys to use for the remote user.
 * 
 * If a public key pair already exists then this functions returns its public
 * part. If no key pair exist yet the function calls createAxoKeyPair to
 * create a new key pair and to store it.
 * 
 * The functions also returns the public part of the own identity key.
 * 
 * The functions stores the remote conversation in a staging area.
 * 
 * @param localUser name of local user/account
 * @param user Name of the remote user
 * @param deviceId The remote user's device id if it is available
 * @return the serialized data of the public keys.
 */
const string getAxoPublicKeyData( const string& localUser, const string& user, const string& deviceId );

/**
 * @brief Set public keys of a remote user.
 * 
 * The ZRTP client calls this function after it got the public key data of the
 * remote user during the ZRTP negotiation. 
 * 
 * The function gets the remote conversation from the staging area, determines
 * the Alice and Bob roles, stores the public key data according the the Axolotl
 * specification and stores the prepared conversation in the staging area.
 * 
 * @param localUser name of local user/account
 * @param pubKeyData The serialized data of the public keys
 * @param user the remote user's name
 * @param deviceId The remote user's device id if it is available
 */
void setAxoPublicKeyData(const string& localUser, const string& user, const string& deviceId, const string& pubKeyData);

/**
 * @brief Receive the exported key data.
 * 
 * The ZRTP client call this functions to hand over the created exported key
 * data. The ZRTP based Axolotl protocol uses this data as it's master secret
 * and dervies other keys from this master secret, refer to the Axolotl specification.
 * 
 * The function gets the remote conversation from the staging area, derives the 
 * various keys and finishes the setup of the remote conversation state.
 * In the last setp the function commits the new remote conversation to persitent store.
 * 
 * @param localUser name of local user/account
 * @param user Name of the remote user
 * @param deviceId The remote user's device id if it is available
 * @param exportedKey The raw data of the exported key from ZRTP
 * @param role the current client ZRTP role, Initiator or Responder
 */
void setAxoExportedKey( const string& localUser, const string& user, const string& deviceId, const string& exportedKey );


const string getOwnIdKey();

void checkRemoteIdKey(const string user, const string deviceId, const string pubKey, int32_t verifyState);

/*
 * To get some information from the SIP engine we need to something like this:

void *pEng = getAccountByID(0);

if (pEng) {
    user = (char*)sendEngMsg(pEng, "cfg.un");
    devId = (char*)sendEngMsg(pEng, "device_id");
}
*/
static const int32_t None = 1;
static const int32_t Alice = 1;
static const int32_t Bob   = 2;

using namespace axolotl;
class AxoZrtpConnector
{
public:
    /**
     * @brief Constructor
     * 
     * @param conv Pointer to a remote AxoConversation.
     * @param localConv Pointer to local Axolotl state
     */
    AxoZrtpConnector(shared_ptr<AxoConversation> conv, shared_ptr<AxoConversation> localConv): conv_(conv), localConv_(localConv), ratchetKey_(NULL),
                     remoteRatchetKey_(NULL), remoteIdKey_(NULL), role_(None) {}
    ~AxoZrtpConnector() { delete ratchetKey_; ratchetKey_ = NULL; delete remoteRatchetKey_; remoteRatchetKey_ = NULL; }


    /**
     * @brief Set pointer of staged Ratchet key pair.
     */
    void setRatchetKey(const DhKeyPair* ratchetKey) { ratchetKey_ = ratchetKey; }

    /**
     * @brief Get pointer of staged Ratchet key pair.
     */
    const DhKeyPair* getRatchetKey() const          { return ratchetKey_; }

    /**
     * @brief Set pointer of staged remote Ratchet key.
     */
    void setRemoteRatchetKey(const DhPublicKey* ratchetKey) { remoteRatchetKey_ = ratchetKey; }

    void setRemoteIdKey(const DhPublicKey* idKey)           { remoteIdKey_ = idKey; }

    /**
     * @brief Get pointer of staged remote Ratchet key.
     */
    const DhPublicKey* getRemoteRatchetKey() const  { return remoteRatchetKey_; }

    const DhPublicKey* getRemoteIdKey() const       { return remoteIdKey_; }

    void setRole(int32_t role)                { role_ = role; }
    int32_t getRole()                         { return role_; }

    shared_ptr<AxoConversation> getRemoteConversation()  { return conv_; }
    shared_ptr<AxoConversation> getLocalConversation()   { return localConv_; }

private:
    AxoZrtpConnector (const AxoZrtpConnector& other) = delete;
    AxoZrtpConnector& operator= (const AxoZrtpConnector& other) = delete;
    bool operator== (const AxoZrtpConnector& other) const = delete;

    shared_ptr<AxoConversation> conv_;
    shared_ptr<AxoConversation> localConv_;
    const DhKeyPair* ratchetKey_;
    const DhPublicKey* remoteRatchetKey_;
    const DhPublicKey* remoteIdKey_;
    int32_t role_;
};
/**
 * @}
 */


#endif // ZRTPCONNECTOR_H
