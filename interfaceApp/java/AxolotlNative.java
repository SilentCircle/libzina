package axolotl;

/**
 * Native functions and callbacks for Axolotl library.
 *
 * The functions in this class use JSON formatted strings to exchange data with the
 * native Axolotl library functions.
 * 
 * The native functions expect UTF-8 encoded strings and return UTF-8 encoded strings.
 * 
 * Java uses a modified UTF-8 encoding in its String class and this encoding could 
 * give problems if a Java program hands over a pure Java String to the native functions.
 * Fortunately Java can convert its internal encoding into the correct standard encoding. 
 * The following Java code snippet shows how to to it:
 * <code>
 * String str = "contains some other characters öäüß á â ã";
 * byte[] utf8Encoded = str.getBytes("UTF-8");   // Encode to standard UTF-8 and store as bytes
 * <code>
 * A Java function then uses the byte array as a parameter to the native function. On callback
 * it just works the other way around. This is the reason why the interface uses {@code byte[]}
 * and not {@code String}.
 */

public abstract class AxolotlNative { //  extends Service {  -- depends on the implementation of the real Java class 

    /**
     * Initialize the Axolotl library.
     * 
     * The following native functions MUST NOT be static because their native implementation 
     * use the "this" object.
     * 
     * An application must call this functions before it can use any other Axolotl library
     * functions.
     * 
     * @param flags Lower 4 bits define debugging level, upper bits some flags
     * @param dbName the full path of the database filename
     * @param dbPassphrase the passphrase to encrypt database content
     * @param userName the local username, for SC it's the name of the user's account
     * @param authorization some authorization code, for SC it's the API key of this device
     * @param scClientDevId the sender's device id, same as used to register the device (v1/me/device/{device_id}/)
     * @return 1 if call was OK, a negative value in case of errors
     */
    public native int doInit(int flags, String dbName, byte[] dbPassphrase, byte[] userName, byte[] authorization, byte[] scClientDevId);

    /**
     * Send a message with an optional attachment.
     *
     * Takes JSON formatted message descriptor and sends the message. The function accepts
     * an optional JSON formatted attachment descriptor and sends the attachment data to the
     * recipient together with the message.
     *
     * This is a blocking call and the function returns after the transport layer accepted the
     * message and returns. This function may take some time if the recipient is not yet known
     * and has no Axolotl session. In this case the function interrogates the provisioning server
     * to get the necessary Axolotl data of the recipient, creates a session and then sends the 
     * message.
     *
     * After encrypting the message the function forwards the message data to the message handler.
     * The message handler takes the message, processes it and returns a unique message id (see 
     * description of message handler API). The UI should use the unique id to monitor message
     * state, for example if the message was actually sent, etc. Refer to message state report
     * callback below. The message id is an opaque datum.
     *
     * The @c sendMessage function does not interpret or re-format the attachment descriptor. It takes
     * the string, encrypts it with the same key as the message data and puts it into the message
     * bundle.
     *
     * @param messageDescriptor      The JSON formatted message descriptor, string, required.
     * 
     * @param attachementDescriptor  Optional, a string that contains an attachment descriptor. An empty
     *                               string ot {@code null} shows that not attachment descriptor is available.
     * 
     * @param messageAttributes      Optional, a JSON formatted string that contains message attributes.
     *                               An empty string ot {@code null} shows that not attributes are available.
     * 
     * @return A list of unique 64-bit transport message identifiers, one for each message set to the user's 
     *         devices. In case of error the functions return {@code null} and the {@code getErrorCode} and
     *         {@code getErrorInfo} have the details.
     */
    public static native long[] sendMessage(byte[] messageDescriptor, byte[] attachementDescriptor, byte[] messageAttributes);

    /**
     * Send message to siblinge devices.
     * 
     * Similar to @c sendMessage, however send this data to sibling devices, i.e. to other devices that
     * belong to a user. The client uses function for send synchronization message to the siblings to
     * keep them in sync.
     * 
     * @param messageDescriptor      The JSON formatted message descriptor, required
     * @param attachementDescriptor  A string that contains an attachment descriptor. An empty string
     *                               shows that not attachment descriptor is available.
     * @param messageAttributes      Optional, a JSON formatted string that contains message attributes.
     *                               An empty string shows that not attributes are available.
     * @return unique message identifiers if the messages were processed for sending, 0 if processing
     *         failed.
     */
    public static native long[] sendMessageToSiblings(byte[] messageDescriptor, byte[] attachementDescriptor, byte[] messageAttributes);

    /**
     * Request names of known trusted Axolotl user identities.
     *
     * The Axolotl library stores an identity (name) for each remote user.
     *
     * @return JSON formatted information about the known users. It returns an empty 
     *         string if no users known. It returns NULL in case the request failed.
     *         Language bindings use appropriate return types.
     */
    public static native byte[] getKnownUsers();

    /**
     * Get public part of own identity key.
     * 
     * The returned array contains the B64 encoded data of the own public identity key, optinally
     * followed by a colon and the device name.
     *
     * @return public part of own identity key, {@code null} if no own identity key available
     */
     public static native byte[] getOwnIdentityKey();

    /**
     * Get a list of all identity keys a remote parts.
     * 
     * The remote partner may have more than one device. This function returns the identity 
     * keys of remote user's devices that this client knows of. The client sends messages only
     * to these known device of the remote user.
     * 
     * The returned strings in the list contain the B64 encoded data of the public identity keys
     * of the known devices, followed by a colon and the device name, followed by a colon and the
     * the device id, followed by a colon and the ZRTP verify state.
     * 
     * identityKey:device name:device id:verify state
     * 
     * @param user the name of the user
     * @return array of identity keys, {@code null} if no identity keys are available for that user.
     */
    public static native byte[][] getIdentityKeys(byte[] user);

    /**
     * Request a user's Axolotl device names.
     *
     * Ask the server for known Axolotl devices of a user.
     *
     * @return JSON formatted information about user's Axolotl devices. It returns {@code null} 
     *         if no devices known for this user.
     */
    public static native byte[] getAxoDevicesUser(byte[] userName);

    /**
     * Register Axolotl device.
     *
     * Register this device with the server. The registration requires a device id that's unique
     * for the user's account on the server. The user should have a valid account on the server.
     * 
     * In the Silent Circle use case the user name was provided during account creation, the client computes a
     * unique device id and registers this with the server during the first generic device registration.
     * 
     * @param resultCode a inte array with at least a length of one. The functions returns the
     *        request result code at index 0 
     * @return a JSON string as UTF-8 encoded bytes, contains information in case of failures.
     */
    public static native byte[] registerAxolotlDevice(int[] resultCode);

    /**
     * Remove Axolotl device.
     *
     * Remove an Axolotl device from a user's account.
     * 
     * @param resultCode a inte array with at least a length of one. The functions returns the
     *        request result code at index 0
     * @param deviceId the SC device id of the device to remove.
     * @return a JSON string as UTF-8 encoded bytes, contains information in case of failures.
     */
    public static native byte[] removeAxolotlDevice(byte[] deviceId, int[] resultCode);

    /**
     * Generate and register a set of new pre-keys.
     * 
     * @return Result of the register new pre-key request, usually a HTTP code (200, 404, etc)
     */
    public static native int newPreKeys(int number);

    /**
     * Get number of pre-keys available on the server.
     * 
     * Checks if the server has pre-keys for this account/device id and return how many keys are
     * available.
     * 
     * @return number of available pre-keys or -1 if request to server failed.
     */
    public static native int getNumPreKeys();

    /**
     * Return the stored error code.
     * 
     * Functions of this implementation store error code in case they detect
     * a problem and return {@code null}, for example. In this case the caller should
     * get the error code and the additional error information for detailled error
     * data.
     * 
     * Functions overwrite the stored error code only if they return {@code null} or some
     * other error indicator.
     * 
     * @return The stored error code.
     */
    public static native int getErrorCode();

    /**
     * Return the stored error information.
     * 
     * Functions of this implementation store error information in case they detect
     * a problem and return {@code null}, for example. In this case the caller should
     * get the error code and the additional error information for detailed error
     * data.
     * 
     * Functions overwrite the stored error information only if they return {@code null} 
     * or some other error indicator.
     * 
     * @return The stored error information string.
     */
    public static native String getErrorInfo();

    /**
     * For testing only, not available in production code.
     * 
     * Returns -1 in production code.
     */
    public static native int testCommand(String command, byte[] data);

    /**
     * Command interface to send managment command and to request managment information.
     * 
     * @param command the managment command string.
     * @param optinal data required for the command.
     * @return a string depending on command.
     */
    public static native String axoCommand(String command, byte[] data);

    /**
     * Receive a Message.
     *
     * Takes JSON formatted message descriptor of the received message and forwards it to the UI
     * code via a callback functions. The function accepts an optional JSON formatted attachment
     * descriptor and forwards it to the UI code if a descriptor is available.
     *
     * The implementation classes for the different language bindings need to perform the necessary
     * setup to be able to call into the UI code. The function and thus also the called function in
     * the UI runs in an own thread. UI frameworks may not directly call UI related functions inside
     * their callback function. Some frameworks provide special functions to run code on the UI 
     * thread even if the current functions runs on another thread.
     *
     * In any case the UI code shall not block processing of this callback function and shall return
     * from the callback function as soon as possible.
     *
     * The @c receiveMessage function does not interpret or re-format the attachment descriptor. It takes
     * the the data from the received message bundle, decrypts it with the same key as the message data
     * and forwards the resulting string to the UI code. The UI code can then use this data as input to
     * the attachment handling.
     *
     * @param messageDescriptor      The JSON formatted message descriptor, string, required.
     * 
     * @param attachmentDescriptor   Optional, a string that contains an attachment descriptor. An empty
     *                               string ot {@code null} shows that not attachment descriptor is available.
     * 
     * @param messageAttributes      Optional, a JSON formatted string that contains message attributes.
     *                               An empty string ot {@code null} shows that not attributes are available.
     * @return Either success of an error code (to be defined)
     */
    public abstract int receiveMessage(byte[] messageDescriptor, byte[] attachmentDescriptor, byte[] messageAttributes);

    /**
     * Message state change.
     *
     * The Axolotl library uses this callback function to report message state changes to the UI.
     * The library reports state changes of message it got for sending and it also reports if it
     * received a message but could not process it, for example decryption failed.
     *
     * @param messageIdentifier  the unique 64-bit transport message identifier. If this identifier 
     *                           is 0 then this report belongs to a received message and the library 
     *                           failed to process it.
     * 
     * @param statusCode         The status code as reported from the network transport, usually like
     *                           HTTP or SIP codes. If less 0 then the messageIdentfier may be 0 and
     *                           this would indicate a problem with a received message.
     * 
     * @param stateInformation   JSON formatted state information block (string) that contains the
     *                           details about the new state of some error information.
     */
    public abstract void messageStateReport(long messageIdentifier, int statusCode, byte[] stateInformation);

    /**
     * Helper function to perform HTTP(S) requests.
     * 
     * The Axolotl library uses this callback to perform HTTP(S) requests. The application should
     * implement this function to contact a provisioning server or other server that can return
     * required Axolotl data. If the application really implements this as HTTP(S) or not is an
     * implementation detail of the application.
     * 
     * The Axolotl library creates a request URI, provides request data if required, specifies the
     * method (GET, PUT) to use. On return the function sets the request return code in the code
     * array at index 0 and returns response data as byte array.
     * 
     * The functions returns after the HTTP(S) or other network requests return.
     * 
     * @param requestUri the request URI without the protocol and domain part.
     * @param requestData data for the request if required
     * @param method to use, GET, PUT
     * @param code to return the request result code at index 0 (200, 404 etc)
     * @return the received data
     */
    public abstract byte[] httpHelper(byte[] requestUri, String method, byte[] requestData, int[] code);

    /**
     * Notify callback.
     *
     * The Axolotl library uses this callback function to report data of a SIP NOTIFY to the app.
     *
     * @param messageIdentifier  the unique 64-bit transport message identifier. 
     * 
     * @param notifyActionCode   This code defines which action to perform, for example re-scan a
     *                           user's Axolotl devices
     * 
     * @param actionInformation  JSON formatted state information block (string) that contains the
     *                           details required for the action.
     */
    public abstract void notifyCallback(int notifyActionCode, byte[] actionInformation, byte[] deviceId);

    /*
     ***************************************************************
     * Below the native interfaces for the repository database
     * *************************************************************
     */

    /**
     * Open the repository database.
     *
     * @param databaseName The path and filename of the database file.
     * @return {@code true} if open was OK, {@code false} if not.
     */
    public static native int repoOpenDatabase(String databaseName, byte[] keyData);

    /**
     * Close the repository database.
     */
    public static native void repoCloseDatabase();

    /**
     * Check if repository database is open.
     * @return {@code true} if repository is open, {@code false} if not.
     */
    public static native boolean repoIsOpen();

    /**
     * Checks if a conversation for the name pattern exists.
     *
     * A unique conversation consists of a local username, a special separator and the
     * partner name, concatenated to one string. See comment for
     * {@link com.silentcircle.messaging.repository.DbRepository.DbConversationRepository}.
     *
     *
     * @param namePattern This name is the parameter with the unique conversation name.
     * @return {@code true} if the pattern exists, {@code false} if not.
     */
    public static native boolean existConversation(byte[] name);

    /**
     * @brief Store serialized conversation data.
     *
     * @param name the unique conversation name
     * @param conversation The serialized data of the conversation data structure
     * @return An SQLITE code.
     */
    public static native int storeConversation(byte[]name, byte[] conversation);

    /**
     * Load and return serialized conversation data.
     *
     * @param name the unique conversation name
     * @param code array of length 1 to return the request result code at index 0, usually a SQLITE code
     * @return The serialized data of the conversation data structure, {@code null} if no
     *         such conversation
     */
    public synchronized static native byte[] loadConversation(byte[]name, int[] code);

    /**
     * Delete a conversation.
     *
     * Deletes a conversation and all its related data, including messages, events, objects.
     *
     * @param name Name of conversation
     * @return A SQLITE code.
     */
    public static native int deleteConversation(byte[] name);

    /**
     * Return a list of names for all known conversations.
     * 
     * @return A list of names for conversations, {@code null} in case of an error.
     */
    public static native byte[][] listConversations();

    /**
     * Insert serialized event/message data.
     *
     * The functions inserts the event/message data and assigns a sequence number to this
     * record. The sequence number is unique inside the set of messages of a conversation.
     *
     * The functions returns and error in case a record with the same event id for this
     * conversation already exists.
     *
     * @param name The conversation partner's name
     * @param eventId The event id, unique inside partner's conversation
     * @param event The serialized data of the event data structure
     * @return A SQLITE code.
     */
    public static native int insertEvent(byte[] name, byte[] eventId, byte[] event);

    /**
     * Load and returns one serialized event/message data.
     *
     * The functions returns the sequence number of the loaded event record at index 1 of
     * the return {@code code} array
     * 
     * @param name The conversation partner's name
     * @param eventId The event id, unique inside partner's conversation
     * @param code array of length 2 to return the request result code at index 0 (usually 
     *             a SQLITE code) and the message sequence number at index 1. 
     * @return The serialized data of the event/message data structure, {@code null} if no
     *         such event/message
     */
    public static native byte[] loadEvent(byte[] name, byte[]eventId, int[] code);

    /**
     * Load a message with a defined message id.
     *
     * Lookup and load a message based on the unique message id (UUID). The function does
     * not restrict the lookup to a particular conversation.
     *
     * @param msgId The message id
     * @param code An int array with a minimum length of 1. Index 0 has the SQL code
     *        on return
     * @return the message or {@code null} if no message found
     */
    public static native byte[] loadEventWithMsgId(byte[] eventId, int[] code);

    /**
     * Checks if an event exists.
     *
     * @param name Name of conversation
     * @param eventId Id of the event
     * @return {@code true} if the event exists, {@code false} if not.
     */
    public static native boolean existEvent(byte[] name, byte[] eventId);

    /**
     * Load and returns a set of serialized event/message data.
     *
     * Each event/message record has a increasing serial number and the highest serial number
     * is the newest message this functions provides several ways to select the set of message
     * records to return:
     *
     * If @c offset is -1 then the functions takes the highest available message number and
     * subtracts the @c number to select and starts with this message. It sorts the message
     * records is descending order, thus the newest message is the first in the returned vector.
     * If the computation results in a negative record number then the functions starts with
     * record number 1.
     *
     * If @c offset is not -1 then the function takes this number as a sequence number of a
     * record and starts to select @c number of records or until the end of the record table,
     * sorted in descending order.
     *
     * If @c offset and @c number are both -1 the the functions return all message records,
     * sorted in descending order.
     *
     * The functions may return less event than request if the application deleted event
     * records in the selected range. The functions returns the sequence number of the last
     * (oldest) event record, i.e. the smallest found sequence number.
     *
     * @param name The conversation partner's name
     * @param offset Where to start to retrieve the events/message
     * @param number how many enevt/message to load
     * @param code array of length 2 to return the request result code at index 0 (usually 
     *             a SQLITE code) and the message sequence number at index 1. 
     * @return Array of byte arrays that contain the serialied event data
     */
    public static native byte[][] loadEvents(byte[]name, int offset, int number, int[] code);

    /**
     * Delete an event from a conversation.
     *
     * Deletes an event/message and all its related data.
     *
     * @param name Name of conversation
     * @param eventId Id of the event
     * @return A SQLITE code.
     */
    public static native int deleteEvent(byte[] name, byte[] eventId);

    /**
     * Insert serialized Object (attachment) data.
     *
     * @param name The conversation partner's name
     * @param eventId The event id, unique inside partner's conversation
     * @param objectId The object id, unique inside the event it belongs to
     * @param object The serialized data of the object data structure
     * @return A SQLITE code.
     */
    public static native int insertObject(byte[] name, byte[] eventId, byte[] objectId, byte[] object);

    /**
     * @brief Load and returns one serialized object descriptor data.
     *
     * @param name The conversation partner's name
     * @param eventId The event id
     * @param objectId The object id, unique inside the event it belongs to
     * @param code array of length 1 to return the request result code at index 0, usually a SQLITE code
     * @return The serialized data of the object description data structure, {@code null} if no
     *         such object
     */
    public static native byte[] loadObject(byte[] name, byte[] eventId, byte[] objectId,int[] code);

    /**
     * Checks if an object descriptor exists.
     *
     * @param name Name of conversation
     * @param eventId Id of the event
     * @param objectId Id of the object
     * @return {@code true} if the object exists, {@code false} if not.
     */
    public static native boolean existObject(byte[] name, byte[] eventId, byte[] objectId);

    /**
     * Load and returns the serialized data of all object descriptors for this event/message.
     *
     * @param name Name of conversation
     * @param eventId Id of the event
     * @return The list of serialized data of the object data structures, {@code null} if none
     *         exist.
     */
    public static native byte[][] loadObjects(byte[]name, byte[] eventId, int[] code);

    /**
     * Delete an object descriptor from the event/message.
     *
     * @param name Name of conversation
     * @param eventId Id of the event
     * @param objectId Id of the object
     * @return A SQLITE code.
     */
    public static native int deleteObject(byte[] name, byte[] eventId, byte[] objectId);

    /**
     * Insert or update the attachment status.
     *
     * If no entry exists for the msgId then insert a new entry and set its
     * status to 'status'. If an entry already exists then update the status
     * only.
     * 
     * If the caller provides a {@code partnerName} then the function stores it together
     * with the message id.
     * 
     * @param mesgId the message identifier of the attachment status entry.
     * @param partnerName Name of the conversation partner, maybe {@code null}
     * @param status the new attchment status
     * @return the SQL code
     */
    public static native int storeAttachmentStatus(byte[] mesgId, byte[] partnerName, int status);

    /**
     * Delete the attachment status entry.
     *
     * If the partner name is {@code null} then the function uses only the message id to
     * perform the delete request. Otherwise it requires full match, message id and
     * partner name to delete the status entry.
     * 
     * @param mesgId the message identifier of the attachment status entry.
     * @param partnerName Name of the conversation partner, maybe {@code null}
     * @return the SQL code
     */
    public static native int deleteAttachmentStatus(byte[] mesgId, byte[] partnerName);

    /**
     * Delete all attachment status entries with a given status.
     *
     * @param the status code
     * @return the SQL code
     */
    public static native int deleteWithAttachmentStatus(int status);

    /**
     * Return attachment status for msgId.
     *
     * If the partner name is {@code null} then the function uses only the message id to
     * perform the load request. Otherwise it requires full match, message id and
     * partner name to load the status entry.
     * 
     * @param mesgId the message identifier of the attachment status entry.
     * @param partnerName Name of the conversation partner, maybe {@code null}
     * @param code is an array with a minimum  length of 1, index 0 contains 
     *        the SQL code on return
     * @return the attachment status or -1 in case of error
     */
    public static native int loadAttachmentStatus(byte[] mesgId, byte[] partnerName, int[] code);

    /**
     * Return all message ids with a give status.
     * 
     * Returns a string array that contains the message identifier as UUID string.
     * If a partner name was set then the functions appends a colon (:) and the
     * partner name to the UUID string.
     *
     * @param status finds all attachment message ids with this status.
     * @param code is an array with a minimum  length of 1, index 0 contains 
     *        the SQL code on return
     * @return a String array with the found message ids (UUID) or {@code null}
     *         in case of error
     */
    public static native String[] loadMsgsIdsWithAttachmentStatus(int status, int[] code);


    /*
     ***************************************************************
     * Below the native interface for the SClound crypto primitves
     * -- these do not really belong to Axolotl, however it's simpler
     *    to leave it in one library --
     * *************************************************************
     */

    /**
     * Prepare and setup a new file encryption.
     *
     * This function takes the data and the meta-data of a file, creates an internal context
     * and populates it with the data.
     *
     * @param context  Some random bytes which the functions uses to salt the locator (the file
     *                 name of the encrypted file). This is optional and may be {@code null}.
     *
     * @param data     The data to encrypt
     *
     * @param metadata The meta data that describes the data
     *
     * @param errorCode A 1 element integer array that returns the result code/error code.
     *
     * @return a long integer that identifies the interally created context. The call shall not
     *         modify this long integer.
     */
    public static native long cloudEncryptNew (byte[] context, byte[] data, byte[] metaData, int[] errorCode);

    /**
     * Compute the encryption key, IV, and the locator for the encrypted file.
     *
     * @param scloudRef the long integer context identifier
     *
     * @return the result or error code
     */
    public static native int cloudCalculateKey (long scloudRef);  // blocksize not required

    /**
     * Get the JSON structured key information.
     *
     * The caller can request the computed key data. The function returns a JSON string which
     * contains the data:
     *
     * {"version":2,"keySuite":0,"symkey":"0E685AC318D9D465B40416ABA4C7ACA57A2D50E0695320224DDB08B38FAD68BA"}
     *
     * @param scloudRef the long integer context identifier
     *
     * @param errorCode A 1 element integer array that returns the result code/error code.
     *
     * @return a byte array (UTF-8 data) that contains the JSON string.
     */
    public static native byte[] cloudEncryptGetKeyBLOB(long scloudRef, int[] errorCode);

    /**
     * Get the JSON structured segment information.
     *
     * The caller can request the segment data. The function returns a JSON string which
     * contains the data:
     *
     * [1,"QGn3vsKDOaCels0gQGuEPlBDkPIA",{"version":2,"keySuite":0,"symkey":"0E685AC318D9D465B40416ABA4C7ACA57A2D50E0695320224DDB08B38FAD68BA"}]
     *
     * @param scloudRef the long integer context identifier
     *
     * @param segNum  The number of the segment
     * @param errorCode A 1 element integer array that returns the result code/error code.
     *
     * @return a byte array (UTF-8 data) that contains the JSON string.
     */
    public static native byte[] cloudEncryptGetSegmentBLOB(long scloudRef, int segNum, int[] errorCode);

    /**
     * Get the binary locator information.
     *
     * The caller can request the computed binary locator data.
     *
     * @param scloudRef the long integer context identifier
     *
     * @param errorCode A 1 element integer array that returns the result code/error code.
     *
     * @return a byte array that contains the data.
     */
    public static native byte[] cloudEncryptGetLocator(long scloudRef, int[] errorCode);

    /**
     * Get the URL Base64 encoded locator information.
     *
     * The caller can request a URL Base64 encode locator string.
     *
     * @param scloudRef the long integer context identifier
     *
     * @param errorCode A 1 element integer array that returns the result code/error code.
     *
     * @return a byte array (UTF-8 data) that contains the string.
     */
    public static native byte[] cloudEncryptGetLocatorREST(long scloudRef, int[] errorCode);

    /**
     * Encrypt and return the data.
     *
     * The function adds a header, the meta data to the file (raw) data and encrypts this
     * bundle. The {@code buffer} must be large enough to hold all data. Refer to
     * {@code cloudEncryptBufferSize} to get the required buffer size.
     *
     * @param scloudRef the long integer context identifier
     *
     * @param errorCode A 1 element integer array that returns the result code/error code.
     *
     * @return a byte array with the formatted and encrypted data
     */
    public static native byte[] cloudEncryptNext(long scloudRef, int[] errorCode);

    /**
     * Prepare and setup file decryption.
     *
     * @param key   the key information  to decrypt the file. Must be in JSON format
     *              as returned by {@code cloudEncryptGetKeyBLOB}.
     *
     * @param errorCode A 1 element integer array that returns the result code/error code.
     *
     * @return a long integer that identifies the interally created context. The call shall not
     *         modify this long integer.
     */
    public static native long cloudDecryptNew (byte[] key, int[] errorCode);

    /**
     * Decrypt a formatted file.
     *
     * Call this function to either decrypt a whole file at once or read the file in smaller
     * parts and call this function with the data until no more data available.
     *
     * @param scloudRef the long integer context identifier
     *
     * @param in  a byte buffer that contains the file to or a part of the file to encrypt. The
     *            file must be encrypted with {@code cloudEncryptNext}.
     *
     * @return result code
     */
    public static native int cloudDecryptNext(long scloudRef, byte[] in);

    /**
     * Get the decrypted data.
     *
     * After the caller has no more data to decrypt it needs to call this function which returns
     * the decrypted data.
     *
     * @param scloudRef the long integer context identifier
     *
     * @return  a byte buffer that contains all the decrypted data of the file or {@code null}
     */
    public static native byte[] cloudGetDecryptedData(long scloudRef);

    /**
     * Get the decrypted meta data.
     *
     * After the caller has no more data to decrypt it needs to call this function which returns
     * the decrypted meta data.
     *
     * @param scloudRef the long integer context identifier
     *
     * @return  a byte buffer that contains all the decrypted meta data of the file or {@code null}
     */
    public static native byte[] cloudGetDecryptedMetaData(long scloudRef);

    /**
     * Free the context data.
     *
     * The caller must call this function after all the encrypt or decrypt operations are complete.
     * The context is invalid after this call.
     *
     * @param scloudRef the long integer context identifier
     */
    public static native void cloudFree(long scloudRef);
}