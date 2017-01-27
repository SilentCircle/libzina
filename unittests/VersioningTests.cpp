//
// Created by werner on 26.01.17.
//

#include <string>

#include "gtest/gtest.h"
#include "../vectorclock/VectorClock.h"
#include "../logging/ZinaLogging.h"

using namespace std;
using namespace vectorclock;

// static const uint8_t keyInData[] = {0,1,2,3,4,5,6,7,8,9,19,18,17,16,15,14,13,12,11,10,20,21,22,23,24,25,26,27,28,20,31,30};
string node_1("node_1");
string node_2("node_2");
string node_3("node_3");
string node_4("node_4");
string node_5("node_5");
string node_6("node_6");


class VectorClocksTestsFixture: public ::testing::Test {
public:
    VectorClocksTestsFixture( ) {
        // initialization code here
    }

    void SetUp() {
        // code here will execute just before the test ensues
        LOGGER_INSTANCE setLogLevel(ERROR);
//        pks = SQLiteStoreConv::getStore();
//        pks->setKey(std::string((const char*)keyInData, 32));
//        pks->openStore(std::string());
    }

    void TearDown( ) {
        // code here will be called just after the test completes
        // ok to through exceptions from here if need be
//        SQLiteStoreConv::closeStore();
    }

    ~VectorClocksTestsFixture( )  {
        // cleanup any pending stuff, but no exceptions allowed
        LOGGER_INSTANCE setLogLevel(VERBOSE);
    }

    // put in any custom data members that you need
//    SQLiteStoreConv* pks;
};


TEST_F(VectorClocksTestsFixture, EmptyTests) {
    VectorClock<string> vc;

    // An empty vector clock has no nodes, thus return 0 when reading a node's clock
    ASSERT_EQ(0, vc.getNodeClock(node_1));

    // Cannot increment it either
    ASSERT_FALSE(vc.incrementNodeClock(node_1));
}

TEST_F(VectorClocksTestsFixture, InsertTests) {
    VectorClock<string> vc;

    ASSERT_TRUE(vc.insertNodeWithValue(node_1, 4711));
    ASSERT_EQ(4711, vc.getNodeClock(node_1));

    ASSERT_TRUE(vc.incrementNodeClock(node_1));
    ASSERT_EQ(4712, vc.getNodeClock(node_1));

    // Cannot insert a node a second time
    ASSERT_FALSE(vc.insertNodeWithValue(node_1, 4711));
    ASSERT_EQ(4712, vc.getNodeClock(node_1));
}

TEST_F(VectorClocksTestsFixture, MergeTests) {
    VectorClock<string> vc_1;

    ASSERT_TRUE(vc_1.insertNodeWithValue(node_1, 4711));
    ASSERT_TRUE(vc_1.insertNodeWithValue(node_2, 4712));

    // Merged is the same as vc_1, same length
    auto vc_merged = vc_1.merge(vc_1);
    ASSERT_EQ(2, vc_merged->size());
    ASSERT_EQ(4711, vc_merged->getNodeClock(node_1));
    ASSERT_EQ(4712, vc_merged->getNodeClock(node_2));

    VectorClock<string> vc_2;
    ASSERT_TRUE(vc_2.insertNodeWithValue(node_3, 815));
    ASSERT_TRUE(vc_2.insertNodeWithValue(node_4, 816));

    // Merge vc_1 and vc_2, length must be 4 now, check content
    vc_merged = vc_1.merge(vc_2);
    ASSERT_EQ(4, vc_merged->size());
    ASSERT_EQ(4711, vc_merged->getNodeClock(node_1));
    ASSERT_EQ(4712, vc_merged->getNodeClock(node_2));
    ASSERT_EQ(815, vc_merged->getNodeClock(node_3));
    ASSERT_EQ(816, vc_merged->getNodeClock(node_4));

    // Assume we somehow have now got new event from node_1, thus increment
    // merge again with vc_merged, should have new value of node_1
    ASSERT_TRUE(vc_1.incrementNodeClock(node_1));   // node_1's clock is now 4712

    vc_merged = vc_merged->merge(vc_1);
    ASSERT_EQ(4, vc_merged->size());
    ASSERT_EQ(4712, vc_merged->getNodeClock(node_1));
    ASSERT_EQ(4712, vc_merged->getNodeClock(node_2));
    ASSERT_EQ(815, vc_merged->getNodeClock(node_3));
    ASSERT_EQ(816, vc_merged->getNodeClock(node_4));

    // Merge with empty vector clock
    VectorClock<string> vc_3;
    vc_merged = vc_3.merge(*vc_merged);
    ASSERT_EQ(4, vc_merged->size());
    ASSERT_EQ(4712, vc_merged->getNodeClock(node_1));
    ASSERT_EQ(4712, vc_merged->getNodeClock(node_2));
    ASSERT_EQ(815, vc_merged->getNodeClock(node_3));
    ASSERT_EQ(816, vc_merged->getNodeClock(node_4));
}

TEST_F(VectorClocksTestsFixture, CompareTests) {
    VectorClock<string> vc_1;

    ASSERT_TRUE(vc_1.insertNodeWithValue(node_1, 4711));
    ASSERT_TRUE(vc_1.insertNodeWithValue(node_2, 4712));
    ASSERT_EQ(Equal, vc_1.compare(vc_1));

    VectorClock<string> vc_2;

    // vc_2's node_1 is greater than in vc_1, thus vc_1 is smaller: Before
    ASSERT_TRUE(vc_2.insertNodeWithValue(node_1, 4712));
    ASSERT_TRUE(vc_2.insertNodeWithValue(node_2, 4712));
    ASSERT_EQ(Before, vc_1.compare(vc_2));

    // Just reverse the test
    ASSERT_EQ(After, vc_2.compare(vc_1));

    // Test concurrency, each vector clock has a value on different nodes greater than the other
    ASSERT_TRUE(vc_1.incrementNodeClock(node_2));   // node_2's clock is now 4713
    ASSERT_EQ(Concurrent,vc_2.compare(vc_1));

    // Compare with empty vector clock
    VectorClock<string> vc_3;
    ASSERT_EQ(Before, vc_3.compare(vc_2));

    // Reverse
    ASSERT_EQ(After, vc_2.compare(vc_3));
}
