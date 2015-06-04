#include <limits.h>
#include "gtest/gtest.h"

#include "../appRepository/AppRepository.h"

using namespace axolotl;

TEST(AppRestore, Conversation)
{
    AppRepository* store = AppRepository::getStore(std::string());
    
    ASSERT_TRUE(NULL != store);
    
    std::string data("This is some test data");
    std::string name("partner");
    
    int32_t sqlCode = store->storeConversation(name, data);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    
    std::string readData;
    sqlCode = store->loadConversation(name, &readData);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    ASSERT_EQ(data, readData) << "data mistmatch";
}

TEST(AppRestore, Event)
{
    AppRepository* store = AppRepository::getStore(std::string());

    ASSERT_TRUE(NULL != store);

    std::string data("This is some test data");
    std::string name("partner");
    
    std::string msg("some message data");
    std::string msgId("first");
    int32_t sqlCode = store->insertEvent(name, msgId, msg);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();

    int32_t msgNumber;
    std::string readData;
    sqlCode = store->loadEvent(name, msgId, &readData, &msgNumber);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    ASSERT_EQ(msg, readData) << "data mistmatch";

    // Try a second time, shall fail with contraint error
    sqlCode = store->insertEvent(name, msgId, msg);
    ASSERT_EQ(SQLITE_CONSTRAINT, sqlCode);

    int32_t msgNum = store->getHighestMsgNum(name);
    ASSERT_EQ(1, msgNum);
    
    for (int32_t i = 0; i < 10; i++) {
        char c = i + 0x30;
        std::string id = msgId;
        std::string data = msg;
        data.append(1, c);
        id.append(1, c);
        sqlCode = store->insertEvent(name, id, data);
        ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    }
    msgNum = store->getHighestMsgNum(name);
    ASSERT_EQ(11, msgNum);

    std::list<std::string*> result;
    store->loadEvents(name, -1, -1, &result, &msgNumber);
    ASSERT_EQ(11, result.size());

    while (!result.empty()) {
        std::string* msg = result.front();
        result.pop_front();
//        std::cerr << *msg << std::endl;
        delete msg;
    }

    sqlCode = store->loadEvents(name, -1, 5, &result, &msgNumber);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    ASSERT_EQ(5, result.size());

    while (!result.empty()) {
        std::string* msg = result.front();
        result.pop_front();
//        std::cerr << *msg << std::endl;
        delete msg;
    }
    result.clear();

    sqlCode = store->loadEvents(name, 2, 3, &result, &msgNumber);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    ASSERT_EQ(3, result.size());

    while (!result.empty()) {
        std::string* msg = result.front();
        result.pop_front();
//        std::cerr << *msg << std::endl;
        delete msg;
    }
    // The delete should fail with a constraint problem.
    sqlCode = store->deleteConversation(name);
    ASSERT_EQ(SQLITE_CONSTRAINT, sqlCode);
    
    sqlCode = store->deleteEvent(name, msgId);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();

    readData.clear();
    sqlCode = store->loadEvent(name, msgId, &readData, &msgNumber);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    ASSERT_TRUE(readData.empty());

    // Delete all events for this conversation
    sqlCode = store->deleteEventName(name);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();

    // Now the delete of the conversation should succeed.
    sqlCode = store->deleteConversation(name);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();

    AppRepository::closeStore();
}

TEST(AppRestore, Object)
{
    AppRepository* store = AppRepository::getStore(std::string());
    ASSERT_TRUE(NULL != store);

    std::string data("This is some test data");
    std::string name("partner");
    
    // Insert a conversation
    int32_t sqlCode = store->storeConversation(name, data);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();

    // Inset a event for the conversation
    std::string msg("some message data");
    std::string msgId("first");
    sqlCode = store->insertEvent(name, msgId, msg);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();

    std::string obj("some object data");
    std::string objId("firstObj");
    sqlCode = store->insertObject(name, msgId, objId, obj);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();

    std::string readData;
    sqlCode = store->loadObject(name, msgId, objId, &readData);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    ASSERT_EQ(obj, readData) << "data mistmatch";

    for (int32_t i = 0; i < 10; i++) {
        char c = i + 0x30;
        std::string id = objId;
        std::string data = obj;
        data.append(1, c);
        id.append(1, c);
        sqlCode = store->insertObject(name, msgId, id, data);
        ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
    }

    std::list<std::string*> result;
    store->loadObjects(name, msgId, &result);
    ASSERT_EQ(11, result.size());

    // Delete the event should fail with constraint error
    sqlCode = store->deleteEvent(name, msgId);
    ASSERT_EQ(SQLITE_CONSTRAINT, sqlCode);

    // Delete all events for this event
    sqlCode = store->deleteObjectMsg(name, msgId);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();

    // Delete the event should  succeed.
    sqlCode = store->deleteEvent(name, msgId);
    ASSERT_FALSE(SQL_FAIL(sqlCode)) << store->getLastError();
}