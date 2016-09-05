//
// Created by werner on 05.05.16.
//

#ifndef LIBAXOLOTL_MESSAGECAPTURE_H
#define LIBAXOLOTL_MESSAGECAPTURE_H

/**
 * @file MessageCapture.h
 * @brief Capture message flow
 * @ingroup Zina
 * @{
 *
 * This class contains functions to store and retrieve message trace data.
 * The functions store a subset of message data to provide information about
 * the state of a message, for example if a receiver of a message sent a
 * delivery report or if the client sent a read-receipt for a message.
 *
 * The functions do not store any message content or sensitive data such as
 * location information.
 */

#include <string>
#include <list>
#include <memory>

using namespace std;

class MessageCapture {

public:
    /**
     * @brief Capture received message trace data.
     *
     * @param sender The message sender's name (SC uid)
     * @param messageId The UUID of the message
     * @param deviceId The sender's device id
     * @param convState the relevant data of the ratchet state
     * @param attribute The message attribute string which contains status information
     * @param attachments If set the message contained an attachment descriptor
     */
    static int32_t captureReceivedMessage(const string& sender, const string& messageId, const string& deviceId,
                                          const string &convState, const string& attributes, bool attachments);

    /**
     * @brief Capture send message trace data.
     *
     * @param receiver The message receiver's name (SC uid)
     * @param deviceId The sender's device id
     * @param deviceId The receiver's device id
     * @param convState the relevant data of the ratchet state
     * @param attribute The message attribute string which contains status information
     * @param attachments If set the message contained an attachment descriptor
     */
    static int32_t captureSendMessage(const string& receiver, const string& messageId, const string& deviceId,
                                      const string &convState, const string& attributes, bool attachments);

    /**
     * @brief Return a list of message trace records.
     *
     * The function selects and returns a list of JSON formatted message trace records, ordered by the
     * sequence of record insertion. The function supports the following selections:
     * <ul>
     * <li>@c name contains data, @c messageId and @c deviceId are empty: return all message trace records
     *     for this name</li>
     * <li>@c messageId contains data, @c name and @c deviceId are empty: return all message trace records
     *     for this messageId</li>
     * <li>@c deviceId contains data, @c name and @c messageId are empty: return all message trace records
     *     for this deviceId</li>
     * <li>@c messageId and @c deviceId contain data, @c name is empty: return all message trace records
     *     that match the messageId AND deviceId</li>
     * </ul>
     * @param name The message sender's/receiver's name (SC uid)
     * @param messageId The UUID of the message
     * @param deviceId The sender's device id
     * @param sqlCode If not @c NULL returns the SQLite return/error code
     * @return list of trace records, maybe empty, never @c NULL
     */
    static shared_ptr<list<string> > loadCapturedMsgs(const string& name, const string& messageId, const string& deviceId, int32_t* sqlCode = NULL);
};


/**
 * @}
 */
#endif //LIBAXOLOTL_MESSAGECAPTURE_H
