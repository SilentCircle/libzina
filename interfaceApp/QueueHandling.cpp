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

// Functions and data to handle the Run-Q
//
// Created by werner on 29.08.16.
//

#include <condition_variable>
#include <thread>

#include "AppInterfaceImpl.h"

using namespace axolotl;

static mutex processListLock;
static list<shared_ptr<MsgQueueInfo> > processMessages;

static mutex threadLock;
static condition_variable sendCv;
static thread sendThread;
static bool sendingActive;

#ifdef UNITTESTS
static AppInterfaceImpl* testIf_;
void setTestIfObj_(AppInterfaceImpl* obj)
{
    testIf_ = obj;
}
#endif

void AppInterfaceImpl::checkStartRunThread()
{
    if (!sendingActive) {
        unique_lock<mutex> lck(threadLock);
        if (!sendingActive) {
            sendingActive = true;
            sendThread = thread(runQueue, this);
        }
        lck.unlock();
    }
}

void AppInterfaceImpl::addMsgInfoToRunQueue(shared_ptr<MsgQueueInfo> messageToProcess)
{
    checkStartRunThread();

    unique_lock<mutex> listLock(processListLock);
    processMessages.push_back(messageToProcess);
    sendCv.notify_one();

    listLock.unlock();
}

void AppInterfaceImpl::addMsgInfosToRunQueue(list<shared_ptr<MsgQueueInfo> > messagesToProcess)
{
    checkStartRunThread();

    unique_lock<mutex> listLock(processListLock);
    processMessages.splice(processMessages.end(), messagesToProcess);
    sendCv.notify_one();

    listLock.unlock();
}


// process prepared send messages, one at a time
void AppInterfaceImpl::runQueue(AppInterfaceImpl *obj)
{
    LOGGER(DEBUGGING, __func__, " -->");

    unique_lock<mutex> listLock(processListLock);
    while (sendingActive) {
        while (processMessages.empty()) sendCv.wait(listLock);

        while (!processMessages.empty()) {
            auto msgInfo = processMessages.front();
            processMessages.pop_front();
            listLock.unlock();

            int32_t result;
            switch (msgInfo->command) {
                case SendMessage: {
#ifndef UNITTESTS
                    result = msgInfo->queueInfo_newUserDevice ? obj->sendMessageNewUser(msgInfo) : obj->sendMessageExisting(msgInfo);
                    if (result != SUCCESS) {
                        if (obj->stateReportCallback_ != nullptr) {
                            obj->stateReportCallback_(msgInfo->queueInfo_transportMsgId, result, createSendErrorJson(msgInfo, result));
                        }
                        LOGGER(ERROR, __func__, " Failed to send a message, error code: ", result);
                    }
#else
                    result = msgInfo->queueInfo_newUserDevice ? testIf_->sendMessageNewUser(msgInfo)
                                                                      : testIf_->sendMessageExisting(msgInfo);
                    if (result != SUCCESS) {
                        if (testIf_->stateReportCallback_ != nullptr) {
                            testIf_->stateReportCallback_(msgInfo->queueInfo_transportMsgId, result,
                                                          createSendErrorJson(msgInfo, result));
                        }
                        LOGGER(ERROR, __func__, " Failed to send a message, error code: ", result);
                    }
#endif
                }
                break;
                case ReceivedRawData:
#ifndef UNITTESTS
                    obj->processMessageRaw(msgInfo);
#else
                    testIf_->processMessageRaw(msgInfo);
#endif
                    break;

                case ReceivedTempMsg:
                    obj->processMessagePlain(msgInfo);
                    break;

                case CheckForRetry:
                    break;
            }
            listLock.lock();
        }
    }
}

shared_ptr<vector<uint64_t> >
AppInterfaceImpl::extractTransportIds(shared_ptr<list<shared_ptr<PreparedMessageData> > > data)
{
    auto ids = make_shared<vector<uint64_t> >();

    for (auto it = data->cbegin(); it != data->cend(); ++it) {
        uint64_t id = (*it)->transportId;
        ids->push_back(id);
    }
    return ids;
}

void AppInterfaceImpl::insertRetryCommand()
{
    auto retryCommand = make_shared<MsgQueueInfo>();
    retryCommand->command = CheckForRetry;
    addMsgInfoToRunQueue(retryCommand);

}