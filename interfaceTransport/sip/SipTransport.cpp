#include "SipTransport.h"
#include <iostream>

using namespace axolotl;

void Log(const char* format, ...);

std::vector< int64_t >* SipTransport::sendAxoMessage( const std::string& recipient, std::vector< std::pair< std::string, std::string > >* msgPairs )
{
    int32_t numPairs = msgPairs->size();

    uint8_t** names = new uint8_t*[numPairs+1];
    uint8_t** devIds = new uint8_t*[numPairs+1];
    uint8_t** envelopes = new uint8_t*[numPairs+1];
    size_t*   sizes = new size_t[numPairs+1];
    uint64_t* msgIds = new uint64_t[numPairs+1];

    int32_t index = 0;
    for(; index < numPairs; index++) {
        std::pair<std::string, std::string>& msgPair = msgPairs->at(index);
        names[index] = (uint8_t*)recipient.c_str();
        devIds[index] = (uint8_t*)msgPair.first.c_str();
        envelopes[index] = (uint8_t*)msgPair.second.data();
        sizes[index] = msgPair.second.size();
    }
    names[index] = NULL; devIds[index] = NULL; envelopes[index] = NULL; 

    sendAxoData_(names, devIds, envelopes, sizes, msgIds);

    // This should clear everything because no pointers involved
    msgPairs->clear();
    delete names; delete devIds; delete envelopes; delete sizes;

    std::vector<int64_t>* msgIdsReturn = new std::vector<int64_t>;
    for (int32_t i = 0; i < numPairs; i++) {
        if (msgIds[i] != 0)
            msgIdsReturn->push_back(msgIds[i]);
    }
    delete msgIds;
    return msgIdsReturn;
}

int32_t SipTransport::receiveAxoMessage(uint8_t* data, size_t length)
{
    std::string envelope((const char*)data, length);
    int32_t result = appInterface_->receiveMessage(envelope);

    return result;
}

void SipTransport::stateReportAxo(int64_t messageIdentifier, int32_t stateCode, uint8_t* data, size_t length)
{
    std::string info;
    if (data != NULL) {
        Log("state report data: %p, length: %d", data, length);
        // info.assign((const char*)data, 200);
    }
    appInterface_->stateReportCallback_(messageIdentifier, stateCode, info);
}