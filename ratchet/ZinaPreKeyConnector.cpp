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
#include <cryptcommon/ZrtpRandom.h>
#include "ZinaPreKeyConnector.h"

#include "../ratchet/crypto/EcCurve.h"

#include "../keymanagment/PreKeys.h"

// Generic function, located in AxoZrtpConnector.
void createDerivedKeys(const std::string& masterSecret, std::string* root, std::string* chain, size_t requested);

using namespace zina;

void Log(const char* format, ...);

#ifdef UNITTESTS
static char hexBuffer[2000] = {0};
static void hexdump(const char* title, const unsigned char *s, size_t l) {
    size_t n = 0;
    if (s == NULL) return;

    memset(hexBuffer, 0, 2000);
    int len = sprintf(hexBuffer, "%s",title);
    for( ; n < l ; ++n)
    {
        if((n%16) == 0)
            len += sprintf(hexBuffer+len, "\n%04x", static_cast<int>(n));
        len += sprintf(hexBuffer+len, " %02x",s[n]);
    }
    sprintf(hexBuffer+len, "\n");
}
static void hexdump(const char* title, const string& in)
{
    hexdump(title, (uint8_t*)in.data(), in.size());
}
#endif

/*
 * We are P1 (ALice) at this point:
 * 
    A  = P1_I   (private data)
    B  = P2_I   (public data)
    A0 = P1_PK1 (private data)
    B0 = P2_PK1 (public data)

    masterSecret = HASH(DH(A, B0) || DH(A0, B) || DH(A0, B0))
*/
int32_t ZinaPreKeyConnector::setupConversationAlice(const string& localUser, const string& user, const string& deviceId,
                                                   int32_t bobPreKeyId, pair<const DhPublicKey*, const DhPublicKey*> bobKeys)
{
    LOGGER(DEBUGGING, __func__, " -->");
    int32_t retVal;

    auto conv = ZinaConversation::loadConversation(localUser, user, deviceId);
    if (conv->isValid() && !conv->getRK().empty()) {       // Already a conversation available
        LOGGER(ERROR, __func__, " <-- Conversation already exists for user: ", user, ", device: ", deviceId);
        return AXO_CONV_EXISTS;
    }
    if (conv->getErrorCode() != SUCCESS) {
        retVal = conv->getErrorCode();
        return retVal;
    }

    const DhPublicKey *existingIdKey = conv->getDHIr();     // get a possible existing long term id key

    if (existingIdKey == nullptr) {
        conv->setZrtpVerifyState(0);
        conv->setIdentityKeyChanged(true);
    }
    else if (!(*existingIdKey == *bobKeys.first)) {
        conv->setIdentityKeyChanged(true);
        delete existingIdKey;
        conv->setDHIr(nullptr);
    }

    conv->reset();

    auto localConv = ZinaConversation::loadLocalConversation(localUser);
    if (!localConv->isValid()) {
        LOGGER(ERROR, __func__, " <-- No own identity exists.");
        retVal = (localConv->getErrorCode() == SUCCESS) ? NO_OWN_ID : localConv->getErrorCode();
        return retVal;
    }

    // Identify our context and count how often we ran thru this setup
    uint32_t contextId;
    ZrtpRandom::getRandomData((uint8_t*)&contextId, sizeof(uint32_t));
    contextId &= 0xffff0000;
    uint32_t sequence = conv->getContextId() & 0xffff;
    sequence++;
    contextId |= sequence;
    conv->setContextId(contextId);

    const DhKeyPair* A = new DhKeyPair(*(localConv->getDHIs()));    // Alice's Identity key pair
    const DhKeyPair* A0 = EcCurve::generateKeyPair(EcCurveTypes::Curve25519);   // generate Alice's pre-key

    const DhPublicKey* B = bobKeys.first;       // Bob's identity key, public part
    const DhPublicKey* B0 = bobKeys.second;     // Bob's pre-key, public part

    uint8_t masterSecret[EcCurveTypes::Curve25519KeyLength*3];

    // DH(Bob's public pre-key, Alice's private identity key)
    EcCurve::calculateAgreement(*B0, A->getPrivateKey(), masterSecret, EcCurveTypes::Curve25519KeyLength);

    // DH(Bob's public identity key, Alice's private pre-key)
    EcCurve::calculateAgreement(*B, A0->getPrivateKey(), masterSecret+EcCurveTypes::Curve25519KeyLength, EcCurveTypes::Curve25519KeyLength);

    // DH(Bob's public pre-key, Alice's private pre-key)
    EcCurve::calculateAgreement(*B0, A0->getPrivateKey(), masterSecret+EcCurveTypes::Curve25519KeyLength*2, EcCurveTypes::Curve25519KeyLength);
    string master((const char*)masterSecret, EcCurveTypes::Curve25519KeyLength*3);

    // derive root and chain key
    std::string root;
    std::string chain;
    createDerivedKeys(master, &root, &chain, SYMMETRIC_KEY_LENGTH);
    memset_volatile(masterSecret, 0, EcCurveTypes::Curve25519KeyLength*3);
    memset_volatile((void*)master.data(), 0, master.size());

    // Initialize conversation (ratchet context), conversation takes over the ownership of the keys.
    conv->setDHIr(B);               // Bob is receiver, set his public identity key
    conv->setDHIs(A);               // Alice is sender, set her identity key pair
    conv->setDHRr(B0);              // Bob's B0 (pre-key) public part
    conv->setA0(A0);                // Alice's generated pre-key.
    conv->setRK(root);
    conv->setCKr(chain);
    conv->setPreKeyId(bobPreKeyId);
    conv->setRatchetFlag(true);
    conv->storeConversation();
    retVal = conv->getErrorCode();

    LOGGER(DEBUGGING, __func__, " <--");
    return retVal;
}

/*
 * We are P2 (Bob) at this point:
 *  The conversation must be a new conversation state, otherwise clear old state
    A  = P2_I   (private data)
    B  = P1_I   (public data)
    A0 = P2_PK1 (private data)
    B0 = P1_PK1 (public data)

*/
int32_t ZinaPreKeyConnector::setupConversationBob(ZinaConversation* conv, int32_t bobPreKeyId, const DhPublicKey* aliceId, const DhPublicKey* alicePreKey)
{
    LOGGER(DEBUGGING, __func__, " -->");
    SQLiteStoreConv* store = SQLiteStoreConv::getStore();
//    store->dumpPreKeys();

    // Get Bob's (my) pre-key that Alice used to create her conversation (ratchet context).
    string* preKeyData = store->loadPreKey(bobPreKeyId);

    // If no such prekey then check if the conversation was already set-up (RK available)
    // if yes -> OK, Alice sent the key more then one time because Bob didn't answer her
    // yet. Otherwise Bob got an illegal pre-key.
    if (preKeyData == NULL) {
        if (conv->getRK().empty()) {
            conv->setErrorCode(NO_PRE_KEY_FOUND);
            LOGGER(ERROR, __func__, " <-- Pre-key not found.");
            return -1;
        }
        else {
            LOGGER(INFO, __func__, " <-- OK - multiple type 2 message");
            return OK;      // return this code to show that this was a multiple type 2 message
        }
    }
    const DhPublicKey *existingIdKey = conv->getDHIr();     // get a possible existing long term id key

    if (existingIdKey == nullptr) {
        conv->setZrtpVerifyState(0);
        conv->setIdentityKeyChanged(true);
    }
    else if (!(*existingIdKey == *aliceId)) {
        conv->setIdentityKeyChanged(true);
        delete existingIdKey;
        conv->setDHIr(nullptr);
    }

    // Remove the pre-key from database because Alice used the key
    store->removePreKey(bobPreKeyId);
    conv->reset();

    // A0 is Bob's (my) pre-key, this mirrors Alice's usage of her generated A0 pre-key.
    DhKeyPair* A0 = PreKeys::parsePreKeyData(*preKeyData);
    delete preKeyData;

    auto localConv = ZinaConversation::loadLocalConversation(conv->getLocalUser());
    if (!localConv->isValid()) {
        LOGGER(ERROR, __func__, " <-- Local conversation not valid, code: ", localConv->getErrorCode());
        return -1;
    }
    const DhKeyPair* A = new DhKeyPair(*(localConv->getDHIs()));

    const DhPublicKey* B = aliceId;
    const DhPublicKey* B0 = alicePreKey;

    uint8_t masterSecret[EcCurveTypes::Curve25519KeyLength*3];

    // DH(Alice's public identity key, Bob's private pre-key)
    EcCurve::calculateAgreement(*B, A0->getPrivateKey(), masterSecret, EcCurveTypes::Curve25519KeyLength);

    // DH(Alice's public pre-key, Bob's private identity key)
    EcCurve::calculateAgreement(*B0, A->getPrivateKey(), masterSecret+EcCurveTypes::Curve25519KeyLength, EcCurveTypes::Curve25519KeyLength);

    // DH(Alice's public pre-key, Bob's private pre-key)
    EcCurve::calculateAgreement(*B0, A0->getPrivateKey(), masterSecret+EcCurveTypes::Curve25519KeyLength*2, EcCurveTypes::Curve25519KeyLength);
    string master((const char*)masterSecret, EcCurveTypes::Curve25519KeyLength*3);
    delete B0;
//    hexdump("master Bob", master);  Log("%s", hexBuffer);

    // derive root and chain key
    std::string root;
    std::string chain;
    createDerivedKeys(master, &root, &chain, SYMMETRIC_KEY_LENGTH);
    memset_volatile(masterSecret, 0, EcCurveTypes::Curve25519KeyLength*3);
    memset_volatile((void*)master.data(), 0, master.size());

    conv->setDHRs(A0);              // Actually Bob's pre-key - because of the optimized pre-key handling
    conv->setDHIs(A);               // Bob's (own) identity key
    conv->setDHIr(B);               // Alice's (remote) identity key
    conv->setRK(root);
    conv->setCKs(chain);
    conv->setRatchetFlag(false);

    LOGGER(DEBUGGING, __func__, " <--");
    return SUCCESS;
}