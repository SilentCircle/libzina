/*
Copyright 2017 Silent Circle, LLC

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
//
// Created by werner on 29.01.17.
//

#ifndef LIBZINA_VECTORHELPER_H
#define LIBZINA_VECTORHELPER_H

/**
 * @file
 * @brief Functions to create, manage and compare Vector Clocks
 * @ingroup Zina
 * @{
 */

#include "VectorClock.h"
#include "../storage/sqlite/SQLiteStoreConv.h"
#include "../interfaceApp/GroupProtocol.pb.h"
#include "../interfaceApp/AppInterfaceImpl.h"

namespace zina {
    /**
     * @brief Read the current local vector clock for a group/type pair
     *
     * ZINA stores the local vector clocks for each group/type pair in a database. This
     * Function is a helper that reads an de-serializes the vector clock data and returns
     * it.
     *
     * In case of error the content of `vectorClock' is undefined.
     *
     * @param store Persistent storage
     * @param groupId the group identifier
     * @param type event type of the vector clock, for example GROUP_SET_NAME
     * @param vectorClock address of the LocalVClock class to add the de-serialized data
     * @return @c SUCCESS if de-serializing was OK, an error code if the operation failed
     */
    int32_t readLocalVectorClock(SQLiteStoreConv &store, const string& groupId, GroupUpdateType type, LocalVClock *vectorClock);

    /**
     * @brief Store a vector clock for a group/type pair.
     *
     * The function serializes the vector clock data and stores it in persistent storage.
     *
     * @param store Persistent storage
     * @param groupId the group identifier
     * @param type event type of the vector clock, for example GROUP_SET_NAME
     * @param vectorClock the LocalVClock class to store
     * @return @c SUCCESS if the function could store the data
     */
    int32_t storeLocalVectorClock(SQLiteStoreConv &store, const string& groupId, GroupUpdateType type, const LocalVClock &vectorClock);
}

/**
 * @}
 */
#endif //LIBZINA_VECTORHELPER_H
