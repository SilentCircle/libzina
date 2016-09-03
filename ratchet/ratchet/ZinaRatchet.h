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
#ifndef AXORATCHET_H
#define AXORATCHET_H

/**
 * @file AxoRatchet.h
 * @brief Axolotl ratchet functions
 * @ingroup Axolotl++
 * @{
 */

#include <memory>
#include "../crypto/DhKeyPair.h"
#include "../crypto/DhPublicKey.h"
#include "../state/ZinaConversation.h"

using namespace std;

namespace axolotl {
class ZinaRatchet
{
public:
    /**
     * @brief Encrypt a message and message supplements, assemble a wire message.
     *
     * @param conv The Axolotl conversation
     * @param message The plaintext message bytes.
     * @param supplements Additional data for the message, will be encrypted with the message key
     * @param idHashes The sender's and receiver's id hashes to send with the message, can be @c NULL if
     *                 not required
     * @return An encrypted wire message, ready to send to the recipient+device tuple.
     */
    static shared_ptr<const string> encrypt(ZinaConversation& conv, const string& message, const string& supplements,
                                            shared_ptr<string> supplementsEncrypted, pair<string, string>* idHashes = NULL);

    /**
     * @brief Parse a wire message and decrypt the payload.
     * 
     * @param conv The Axolotl conversation
     * @param wire The wire message.
     * @param supplements Encrypted additional data for the message
     * @param supplementsPlain Additional data for the message if available and decryption was successful.
     * @param idHashes The sender's and receiver's id hashes contained in the message, can be @c NULL if
     *                 not available
     * @return Plaintext or @c NULL if decryption failed
     */
    static shared_ptr<const string> decrypt(axolotl::ZinaConversation* conv, const string& wire, const string& supplements,
                                            shared_ptr<string> supplementsPlain, pair<string, string>* idHashes = NULL);
private:
    ZinaRatchet() {};

    ~ZinaRatchet() {};

};
}
/**
 * @}
 */

#endif // AXORATCHET_H
