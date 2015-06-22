#include "AxoZrtpConnector.h"
#include "state/AxoConversation.h"
#include "crypto/EcCurve.h"
#include "crypto/EcCurveTypes.h"
#include "crypto/HKDF.h"
#include "Constants.h"

#include <common/Thread.h>
#include <iostream>
#include <map>
#include <utility>

#ifdef UNITTESTS
// Used in testing and debugging to do in-depth checks
static void hexdump(const char* title, const unsigned char *s, int l) {
    int n=0;

    if (s == NULL) return;

    fprintf(stderr, "%s",title);
    for( ; n < l ; ++n)
    {
        if((n%16) == 0)
            fprintf(stderr, "\n%04x",n);
        fprintf(stderr, " %02x",s[n]);
    }
    fprintf(stderr, "\n");
}
static void hexdump(const char* title, const std::string& in)
{
    hexdump(title, (uint8_t*)in.data(), in.size());
}
#endif

static CMutexClass sessionLock;

static map<string, AxoZrtpConnector*>* stagingList = new map<string, AxoZrtpConnector*>;

using namespace axolotl;
void Log(const char* format, ...);

const std::string getAxoPublicKeyData(const std::string& localUser, const std::string& user, const std::string& deviceId)
{
    sessionLock.Lock();
    AxoConversation* conv = AxoConversation::loadConversation(localUser, user, deviceId);
    if (conv != NULL) {              // Already a conversation available, no setup necessary
        sessionLock.Unlock();
        return emptyString;
    }
    AxoConversation* localConv = AxoConversation::loadLocalConversation(localUser);
    const DhKeyPair* idKey = localConv->getDHIs();

    conv = new AxoConversation(localUser, user, deviceId);
    AxoZrtpConnector* staging = new AxoZrtpConnector(conv, localConv);

    pair<string, AxoZrtpConnector*> stage(localUser, staging);
    stagingList->insert(stage);

    const DhKeyPair* ratchetKey = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);
    staging->setRatchetKey(ratchetKey);

    std::string combinedKeys;

    // First: length and data of local identity key
    const std::string key = idKey->getPublicKey().serialize();
    char keyLength = key.size();
    combinedKeys.assign(&keyLength, 1).append(key);

    // second: ratchet key
    const std::string rkey = ratchetKey->getPublicKey().serialize();
    keyLength = rkey.size();
    combinedKeys.append(&keyLength, 1).append(rkey);
    sessionLock.Unlock();

    return combinedKeys;
}

void setAxoPublicKeyData(const std::string& localUser, const std::string& user, const std::string& deviceId, const std::string& pubKeyData)
{
    sessionLock.Lock();

    std::map<string, AxoZrtpConnector*>::iterator it;
    it = stagingList->find(localUser);
    AxoZrtpConnector* staging = it->second;

    if (staging == NULL) {
        sessionLock.Unlock();
        // TODO: some error message: illegal state
        return;
    }
    AxoConversation* localConv = staging->getLocalConversation();
    const DhKeyPair* localIdKey = localConv->getDHIs();
    const char* data = pubKeyData.data();

    // Get remote id key
    char keyLength = *data++;
    std::string keyData(data, keyLength);

    data += keyLength;
    const DhPublicKey* remoteIdKey = EcCurve::decodePoint((const uint8_t*)keyData.data());

    int32_t cmp = memcmp(localIdKey->getPublicKey().getPublicKeyPointer(), remoteIdKey->getPublicKeyPointer(), localIdKey->getPublicKey().getSize());
    staging->setRole((cmp < 0) ? Alice : Bob);
    staging->setRemoteIdKey(remoteIdKey);

    // Now the remote ratchet key
    keyLength = *data++;
    keyData = std::string(data, keyLength);
    const DhPublicKey* remoteRatchetKey = EcCurve::decodePoint((const uint8_t*)keyData.data());
    staging->setRemoteRatchetKey(remoteRatchetKey);

    sessionLock.Unlock();
}

// Also used by AxoPreKeyConnector.
void createDerivedKeys(const std::string& masterSecret, std::string* root, std::string* chain, int32_t requested)
{
    uint8_t derivedSecretBytes[256];     // we support upto 128 byte symmetric keys.

    // Use HKDF with 2 input parameters: ikm, info. The salt is SAH256 hash length 0 bytes, similar 
    // to HKDF setup for TextSecure. See https://github.com/WhisperSystems/TextSecure/wiki/ProtocolV2
    HKDF::deriveSecrets((uint8_t*)masterSecret.data(), masterSecret.size(), 
                        (uint8_t*)SILENT_MESSAGE.data(), SILENT_MESSAGE.size(), derivedSecretBytes, requested*2);
    root->assign((const char*)derivedSecretBytes, requested);
    chain->assign((const char*)derivedSecretBytes+requested, requested);
}

/*
Alice:
  KDF from master_key: RK, HKs=<none>, HKr, NHKs, NHKr, CKs=<none>, CKr
  DHIs, DHIr = A, B
  DHRs, DHRr = <none>, B1
  Ns, Nr = 0, 0
  PNs = 0
  ratchet_flag = True
Bob:
  KDF from master_key: RK, HKr=<none>, HKs, NHKr, NHKs, CKr=<none>, CKs
  DHIs, DHIr = B, A
  DHRs, DHRr = B1, <none>
  Ns, Nr = 0, 0
  PNs = 0
  ratchet_flag = False

 
 */
void setAxoExportedKey(const std::string& localUser, const std::string& user, const std::string& deviceId, const std::string& exportedKey)
{
    sessionLock.Lock();

    std::map<string, AxoZrtpConnector*>::iterator it;
    it = stagingList->find(localUser);
    AxoZrtpConnector* staging = it->second;
    if (staging == NULL) {
        sessionLock.Unlock();
        // TODO: some error message: illegal state
        return;
    }
    stagingList->erase(it);

    std::string root;
    std::string chain;
    createDerivedKeys(exportedKey, &root, &chain, SYMMETRIC_KEY_LENGTH);
    AxoConversation *conv = staging->getRemoteConversation();

//    hexdump(conv->getPartner().getName().c_str(), staging->getRemoteIdKey()->serialize());

    conv->setDHIr((Ec255PublicKey*)staging->getRemoteIdKey());
    staging->setRemoteIdKey(NULL);

    if (staging->getRole() == Alice) {
//        cerr << "Remote party '" << user << "' takes 'Alice' role" << endl;
        conv->setDHRr((Ec255PublicKey*)staging->getRemoteRatchetKey());     // Bob's B0 public part
        staging->setRemoteRatchetKey(NULL);
        conv->setRK(root);
        conv->setCKr(chain);
        conv->setRatchetFlag(true);
    }
    else {
//        cerr << "Remote party '" << user << "' takes 'Bob' role" << endl;
        conv->setDHRs(staging->getRatchetKey());           // Bob's B0 key
        staging->setRatchetKey(NULL);
        conv->setRK(root);
        conv->setCKs(chain);
        conv->setRatchetFlag(false);
    }
    conv->storeConversation();

    delete staging->getLocalConversation();
    delete staging->getRemoteConversation();
    delete staging; staging = NULL;
    sessionLock.Unlock();
}
