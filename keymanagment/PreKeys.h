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
#ifndef PREKEYS_H
#define PREKEYS_H

/**
 * @file PreKeys.h
 * @brief Generate and store pre-keys
 * @ingroup Axolotl++
 * @{
 */

#include <string>
#include <stdint.h>
#include <list>

#include "../axolotl/crypto/DhKeyPair.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../axolotl/Constants.h"

using namespace std;
namespace axolotl {

class PreKeys
{
public:
    /**
     * @brief Generate one pre-key.
     * 
     * This functions generates one pre-key and stores it in the persistent
     * store. The store instance must be open and ready.
     * 
     * @param store The persitent Axolotl store to store and retrieve state information.
     * @return a new pre-key and its id
     */
    static pair< int32_t, const DhKeyPair* > generatePreKey(SQLiteStoreConv* store );

    /**
     * @brief Generate a batch of pre-keys.
     * 
     * This functions generates a batch pre-keys and stores them in the persistent
     * store. The store instance must be open and ready.
     * 
     * The caller should check the size of the list if it contains generated pre-keys.
     * The list does not contain @c NULL pointers.
     * 
     * @param store The persitent Axolotl store to store and retrieve state information.
     * @return a list of the generated new pre-key.
     */
    static list< pair< int32_t, const DhKeyPair* > >* generatePreKeys(SQLiteStoreConv* store, int32_t num = NUM_PRE_KEYS);

    /**
     * @brief Parse pre-key JSON data and return the keys
     * 
     * @param data The JSON string as produced during pre-key generation
     * @return a DH key pair
     */
    static DhKeyPair* parsePreKeyData(const string& data);
};
} // namespace axolotl

/**
 * @}
 */

#endif // PREKEYS_H
