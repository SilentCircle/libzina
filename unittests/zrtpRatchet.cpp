/*
 * Copyright 2016 Silent Circle, LLC

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
#include "gtest/gtest.h"

#include "../ratchet/state/ZinaConversation.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../ratchet/crypto/EcCurve.h"
#include "../ratchet/ratchet/ZinaRatchet.h"
#include "../logging/ZinaLogging.h"
#include "../interfaceApp/MessageEnvelope.pb.h"

using namespace zina;
using namespace std;

static const string p1Name("party1");
static const string p2Name("party2");

static const string p1dev("party1_dev");
static const string p2dev("party2_dev");

const string getAxoPublicKeyData(const string& localUser, const string& user, const string& deviceId);
void setAxoPublicKeyData(const string& localUser, const string& user, const string& deviceId, const string& pubKeyData);
void setAxoExportedKey( const string& localUser, const string& user, const string& deviceId, const string& exportedKey );

static const uint8_t keyInData[] = {0,1,2,3,4,5,6,7,8,9,19,18,17,16,15,14,13,12,11,10,20,21,22,23,24,25,26,27,28,20,31,30};

static string emptySharedString;

// Used in testing and debugging to do in-depth checks
static void hexdump(const char* title, const unsigned char *s, size_t l) {
    size_t n = 0;

    if (s == NULL) return;

    fprintf(stderr, "%s",title);
    for( ; n < l ; ++n) {
        if((n%16) == 0)
            fprintf(stderr, "\n%04x", static_cast<int>(n));
        fprintf(stderr, " %02x",s[n]);
    }
    fprintf(stderr, "\n");
}
static void hexdump(const char* title, const string& in)
{
    hexdump(title, (uint8_t*)in.data(), in.size());
}

class RatchetTestFixture: public ::testing::Test {
public:
    RatchetTestFixture( ) {
        // initialization code here
    }

    void SetUp() {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(WARNING);
        store = SQLiteStoreConv::getStore();
        if (store->isReady())
            return;
        store->setKey(std::string((const char*)keyInData, 32));
        store->openStore(std::string());
        if (SQL_FAIL(store->getSqlCode())) {
            LOGGER(ERROR, __func__, " Cannot open conversation store: ", store->getLastError());
            exit(1);
        }
        p1Conv = new ZinaConversation(p1Name, p1Name, emptyString);   // Create P1's own (local) conversation
        p1Conv->setDHIs(EcCurve::generateKeyPair(EcCurveTypes::Curve25519));
        p1Conv->storeConversation();

        p2Conv = new ZinaConversation(p2Name, p2Name, emptyString);   // Create P2's own (local) conversation
        p2Conv->setDHIs(EcCurve::generateKeyPair(EcCurveTypes::Curve25519));
        p2Conv->storeConversation();
    }

    void TearDown( ) {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
        store->closeStore();
        store = NULL;
    }

    ~RatchetTestFixture( )  {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }
    // put in any custom data members that you need
    ZinaConversation* p1Conv;
    ZinaConversation* p2Conv;
    SQLiteStoreConv* store;
};

TEST_F(RatchetTestFixture, ConversationTest)
{
    int32_t sqlCode = -1;
    shared_ptr<list<string> > p1Conversation = store->getKnownConversations(p1Name, &sqlCode);
    ASSERT_FALSE(SQL_FAIL(sqlCode));
    ASSERT_TRUE(p1Conversation.get() != NULL);
    ASSERT_EQ(1, p1Conversation->size());
    ASSERT_EQ(p1Name, p1Conversation->front());
}

TEST_F(RatchetTestFixture, RatchetTest)
{
    // Simulate the ZRTP data exchange via the confirm packets
    string p1_0_p2 = getAxoPublicKeyData(p1Name, p2Name, p2dev);
    string p2_0_p1 = getAxoPublicKeyData(p2Name, p1Name, p1dev);

    setAxoPublicKeyData(p1Name, p2Name, p2dev, p2_0_p1);
    setAxoPublicKeyData(p2Name, p1Name, p1dev, p1_0_p2);

    string exportedKey((const char*)keyInData, 32);
    setAxoExportedKey(p1Name, p2Name, p2dev, exportedKey);
    setAxoExportedKey(p2Name, p1Name, p1dev, exportedKey);

    // Load P2's conversation
    auto p1p2Conv = ZinaConversation::loadConversation(p1Name, p2Name, p2dev);
    ASSERT_TRUE(p1p2Conv->isValid());
    ASSERT_TRUE(p2Conv->getDHIs()->getPublicKey() == *p1p2Conv->getDHIr());

    auto p2p1Conv = ZinaConversation::loadConversation(p2Name, p1Name, p1dev);
    ASSERT_TRUE(p1p2Conv->isValid());
    ASSERT_TRUE(p1Conv->getDHIs()->getPublicKey() == *p2p1Conv->getDHIr());

    if (p1p2Conv->getDHRs() == NULL) {    // This conversation is Alice

    }
    else {
    }
    string p1toP2("11__22------");
    string p2toP1("22__11------");

    MessageEnvelope envelope;
    int32_t result = ZinaRatchet::encrypt(*p1p2Conv, p1toP2, envelope, emptySharedString);
    ASSERT_EQ(SUCCESS, result);

    shared_ptr<const string> p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), envelope, nullptr);
    ASSERT_TRUE(p1p2Plain != NULL);
//    hexdump("p1p2Plain", *p1p2Plain);
//    cerr << *p1p2Plain << endl;
    ASSERT_EQ(p1toP2, *p1p2Plain);

    envelope.Clear();
    result = ZinaRatchet::encrypt(*p2p1Conv, p2toP1, envelope, emptySharedString);
    ASSERT_EQ(SUCCESS, result);

    shared_ptr<const string> p2p1Plain =  ZinaRatchet::decrypt(p1p2Conv.get(), envelope, nullptr);
    ASSERT_TRUE(p2p1Plain.get() != NULL);
//    hexdump("p2p1Plain", *p2p1Plain);
//    cerr << *p2p1Plain << endl;
    ASSERT_EQ(p2toP1, *p2p1Plain);
    p1p2Conv->storeStagedMks();

    LOGGER(INFO, __func__, " 1st loop");

    const std::string baseMsg("This is round: ");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P1");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p1p2Conv, loop, envelope, emptySharedString);

        p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), envelope, nullptr);
//        std::cerr << *p1p2Plain << '\n';
        ASSERT_TRUE(p1p2Plain != NULL);
        ASSERT_EQ(loop, *p1p2Plain);
        p2p1Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 2nd loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P2");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p2p1Conv, loop, envelope, emptySharedString);

        p2p1Plain = ZinaRatchet::decrypt(p1p2Conv.get(), envelope, nullptr);
//        std::cerr << *p2p1Plain << '\n';
        ASSERT_TRUE(p2p1Plain != NULL);
        ASSERT_EQ(loop, *p2p1Plain);
        p1p2Conv->storeStagedMks();
    }

    list<pair<string, shared_ptr<MessageEnvelope> >* > outOfOrder;

    LOGGER(INFO, __func__, " 3rd loop - setup out-of-order 1st time");
    for (int32_t i = 0; i < 10; i++) {
        auto envOutOfOder = make_shared<MessageEnvelope>();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P1 - unordered");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p1p2Conv, loop, *envOutOfOder, emptySharedString);
        pair<string, shared_ptr<MessageEnvelope> >* dataPair = new pair<string, shared_ptr<MessageEnvelope> >(loop, envOutOfOder);
        if (i&1)
            outOfOrder.push_back(dataPair);
        else
            outOfOrder.push_front(dataPair);
    }

    LOGGER(INFO, __func__, " 4th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P1 - second time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p1p2Conv, loop, envelope, emptySharedString);

        p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), envelope, nullptr);
//        std::cerr << *p1p2Plain << '\n';
        ASSERT_TRUE(p1p2Plain != NULL);
        ASSERT_EQ(loop, *p1p2Plain);
        p2p1Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 5th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P2 - second time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p2p1Conv, loop, envelope, emptySharedString);

        p2p1Plain = ZinaRatchet::decrypt(p1p2Conv.get(), envelope, nullptr);
//        std::cerr << *p2p1Plain << '\n';
        ASSERT_TRUE(p2p1Plain != NULL);
        ASSERT_EQ(loop, *p2p1Plain);
        p1p2Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 6th loop");
    for(auto it = outOfOrder.begin(); it != outOfOrder.end();) {
        auto pair = *it;
//        cerr << pair->first << endl;
        p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), *(pair->second), nullptr);
//        std::cerr << *p1p2Plain << '\n';
        ASSERT_TRUE(p1p2Plain != NULL) << "Expected: " << pair->first;
        ASSERT_EQ(pair->first, *p1p2Plain);
        p2p1Conv->storeStagedMks();
        delete pair;
        outOfOrder.erase(it++);
    }

    LOGGER(INFO, __func__, " 7th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P1 - third time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p1p2Conv, loop, envelope, emptySharedString);

        p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), envelope, nullptr);
//        std::cerr << *p1p2Plain << '\n';
        ASSERT_TRUE(p1p2Plain != NULL);
        ASSERT_EQ(loop, *p1p2Plain);
        p2p1Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 8th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P2 - third time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p2p1Conv, loop, envelope, emptySharedString);

        p2p1Plain = ZinaRatchet::decrypt(p1p2Conv.get(), envelope, nullptr);
//        std::cerr << *p2p1Plain << '\n';
        ASSERT_TRUE(p2p1Plain != NULL);
        ASSERT_EQ(loop, *p2p1Plain);
        p1p2Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 9th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P1 - forth time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p1p2Conv, loop, envelope, emptySharedString);

        p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), envelope, nullptr);
//        std::cerr << *p1p2Plain << '\n';
        ASSERT_TRUE(p1p2Plain != NULL);
        ASSERT_EQ(loop, *p1p2Plain);
        p2p1Conv->storeStagedMks();
    }

    // Out-of-order Test again.
    // This time the in-between loops change. This forces the P1 to move the ratchet and to set/maintain
    // the PNp counters, also checks if P2 correctly stages the messages keys of previous ratchet
    outOfOrder.clear();

    LOGGER(INFO, __func__, " 10th loop");
    for (int32_t i = 0; i < 10; i++) {
        auto envOutOfOder = make_shared<MessageEnvelope>();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P1 - unordered");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p1p2Conv, loop, *envOutOfOder, emptySharedString);
        pair<string, shared_ptr<MessageEnvelope> >* dataPair = new pair<string, shared_ptr<MessageEnvelope> >(loop, envOutOfOder);
        if (i&1)
            outOfOrder.push_back(dataPair);
        else
            outOfOrder.push_front(dataPair);
    }

    LOGGER(INFO, __func__, " 11th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P2 - fifth time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p2p1Conv, loop, envelope, emptySharedString);

        p2p1Plain = ZinaRatchet::decrypt(p1p2Conv.get(), envelope, nullptr);
//        std::cerr << *p2p1Plain << '\n';
        ASSERT_TRUE(p2p1Plain != NULL);
        ASSERT_EQ(loop, *p2p1Plain);
        p1p2Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 12th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P1 - fifth time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p1p2Conv, loop, envelope, emptySharedString);

        p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), envelope, nullptr);
//        std::cerr << *p1p2Plain << '\n';
        ASSERT_TRUE(p1p2Plain != NULL);
        ASSERT_EQ(loop, *p1p2Plain);
        p2p1Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 13th loop");
    for(auto it = outOfOrder.begin(); it != outOfOrder.end();) {
        auto pair = *it;
//        cerr << pair->first << endl;
        p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), *(pair->second), nullptr);
//        std::cerr << *p1p2Plain << '\n';
        ASSERT_TRUE(p1p2Plain != NULL) << "Expected: " << pair->first;
        ASSERT_EQ(pair->first, *p1p2Plain);
        delete pair;
        outOfOrder.erase(it++);
        p2p1Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 14th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P2 - sixth time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p2p1Conv, loop, envelope, emptySharedString);

        p2p1Plain = ZinaRatchet::decrypt(p1p2Conv.get(), envelope, nullptr);
//        std::cerr << *p2p1Plain << '\n';
        ASSERT_TRUE(p2p1Plain != NULL);
        ASSERT_EQ(loop, *p2p1Plain);
        p1p2Conv->storeStagedMks();
    }

    LOGGER(INFO, __func__, " 15th loop");
    for (int32_t i = 0; i < 4; i++) {
        envelope.Clear();
        std::string loop = baseMsg;
        const char c = i+0x30;
        loop.append(1, c).append(" from P1 - sixth time");
//        cerr << loop << endl;
        result = ZinaRatchet::encrypt(*p1p2Conv, loop, envelope, emptySharedString);

        p1p2Plain = ZinaRatchet::decrypt(p2p1Conv.get(), envelope, nullptr);
//        std::cerr << *p1p2Plain << '\n';
        ASSERT_TRUE(p1p2Plain != NULL);
        ASSERT_EQ(loop, *p1p2Plain);
        p2p1Conv->storeStagedMks();
    }
}






























