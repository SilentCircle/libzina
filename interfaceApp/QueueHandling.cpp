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

static mutex commandQueueLock;
static list<shared_ptr<CmdQueueInfo> > commandQueue;

static mutex threadLock;
static condition_variable commandQueueCv;
static thread commandQueueThread;
static bool commandThreadActive;

#ifdef UNITTESTS
static AppInterfaceImpl* testIf_;
void setTestIfObj_(AppInterfaceImpl* obj)
{
    testIf_ = obj;
}
#endif

void AppInterfaceImpl::checkStartRunThread()
{
    if (!commandThreadActive) {
        unique_lock<mutex> lck(threadLock);
        if (!commandThreadActive) {
            commandThreadActive = true;
            commandQueueThread = thread(commandQueueHandler, this);
        }
        lck.unlock();
    }
}

void AppInterfaceImpl::addMsgInfoToRunQueue(shared_ptr<CmdQueueInfo> messageToProcess)
{
    checkStartRunThread();

    unique_lock<mutex> listLock(commandQueueLock);
    commandQueue.push_back(messageToProcess);
    commandQueueCv.notify_one();

    listLock.unlock();
}

void AppInterfaceImpl::addMsgInfosToRunQueue(list<shared_ptr<CmdQueueInfo> > messagesToProcess)
{
    checkStartRunThread();

    unique_lock<mutex> listLock(commandQueueLock);
    commandQueue.splice(commandQueue.end(), messagesToProcess);
    commandQueueCv.notify_one();

    listLock.unlock();
}


// process prepared send messages, one at a time
void AppInterfaceImpl::commandQueueHandler(AppInterfaceImpl *obj)
{
    LOGGER(INFO, __func__, " -->");

    unique_lock<mutex> listLock(commandQueueLock);
    while (commandThreadActive) {
        while (commandQueue.empty()) commandQueueCv.wait(listLock);

        while (!commandQueue.empty()) {
            auto cmdInfo = commandQueue.front();
            commandQueue.pop_front();
            listLock.unlock();

            int32_t result;
            switch (cmdInfo->command) {
                case SendMessage: {
#ifndef UNITTESTS
                    result = cmdInfo->queueInfo_newUserDevice ? obj->sendMessageNewUser(cmdInfo) : obj->sendMessageExisting(cmdInfo);
                    if (result != SUCCESS) {
                        if (obj->stateReportCallback_ != nullptr) {
                            obj->stateReportCallback_(cmdInfo->queueInfo_transportMsgId, result, createSendErrorJson(cmdInfo, result));
                        }
                        LOGGER(ERROR, __func__, " Failed to send a message, error code: ", result);
                    }
#else
                    result = cmdInfo->queueInfo_newUserDevice ? testIf_->sendMessageNewUser(cmdInfo)
                                                              : testIf_->sendMessageExisting(cmdInfo);
                    if (result != SUCCESS) {
                        if (testIf_->stateReportCallback_ != nullptr) {
                            testIf_->stateReportCallback_(cmdInfo->queueInfo_transportMsgId, result,
                                                          createSendErrorJson(cmdInfo, result));
                        }
                        LOGGER(ERROR, __func__, " Failed to send a message, error code: ", result);
                    }
#endif
                }
                break;
                case ReceivedRawData:
#ifndef UNITTESTS
                    obj->processMessageRaw(cmdInfo);
#else
                    testIf_->processMessageRaw(cmdInfo);
#endif
                    break;

                case ReceivedTempMsg:
                    obj->processMessagePlain(cmdInfo);
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
    auto retryCommand = make_shared<CmdQueueInfo>();
    retryCommand->command = CheckForRetry;
    addMsgInfoToRunQueue(retryCommand);
}

void AppInterfaceImpl::retryReceivedMessages()
{
    LOGGER(INFO, __func__, " -->");
    list<shared_ptr<CmdQueueInfo> > messagesToProcess;
    int32_t plainCounter = 0;
    int32_t rawCounter = 0;

    shared_ptr<list<shared_ptr<StoredMsgInfo> > > storedMsgInfos = make_shared<list<shared_ptr<StoredMsgInfo> > > ();
    int32_t result = store_->loadTempMsg(storedMsgInfos);

    if (!SQL_FAIL(result)) {
        while (!storedMsgInfos->empty()) {
            auto storedInfo = storedMsgInfos->front();
            auto plainMsgInfo = make_shared<CmdQueueInfo>();

            plainMsgInfo->command = ReceivedTempMsg;
            plainMsgInfo->queueInfo_sequence = storedInfo->sequence;
            plainMsgInfo->queueInfo_message = storedInfo->info_msgDescriptor;
            plainMsgInfo->queueInfo_supplement = storedInfo->info_supplementary;
            plainMsgInfo->queueInfo_msgType = storedInfo->info_msgType;

            messagesToProcess.push_back(plainMsgInfo);
            storedMsgInfos->pop_front();
            plainCounter++;
        }
    }
    result = store_->loadReceivedRawData(storedMsgInfos);
    if (!SQL_FAIL(result)) {
        while (!storedMsgInfos->empty()) {
            auto storedInfo = storedMsgInfos->front();
            auto rawMsgInfo = make_shared<CmdQueueInfo>();

            rawMsgInfo->command = ReceivedRawData;
            rawMsgInfo->queueInfo_sequence = storedInfo->sequence;
            rawMsgInfo->queueInfo_envelope = storedInfo->info_rawMsgData;
            rawMsgInfo->queueInfo_uid = storedInfo->info_uid;
            rawMsgInfo->queueInfo_displayName = storedInfo->info_displayName;

            messagesToProcess.push_back(rawMsgInfo);
            storedMsgInfos->pop_front();
            rawCounter++;
        }
    }
    if (!messagesToProcess.empty()) {
        addMsgInfosToRunQueue(messagesToProcess);
        LOGGER(WARNING, __func__, " Queued messages for retry, plain: ", plainCounter, ", raw: ", rawCounter);
    }
    LOGGER(INFO, __func__, " <--");
}