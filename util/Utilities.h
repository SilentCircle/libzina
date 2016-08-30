//
// Created by werner on 07.06.16.
//

#ifndef LIBAXOLOTL_UTILITIES_H
#define LIBAXOLOTL_UTILITIES_H

/**
 * @file Utilities.h
 * @brief Some utility and helper functions
 * @ingroup Axolotl++
 * @{
 */


#include <sys/types.h>
#include <string>
#include <vector>
#include <memory>
#include "cJSON.h"

using namespace std;

namespace axolotl {
    class Utilities {
    public:
        /**
         * @brief Return an integer value from a JSON structure.
         *
         * @param root the pointer to the cJSON structure
         * @name Name of the value
         * @error Error value, the function returns this value if the JSON structure contains no @c name
         */
        static int32_t getJsonInt(const cJSON* const root, const char* const name, int32_t error);

        /**
         * @brief Return a c-string value from a JSON structure.
         *
         * The functions returns a pointer to the c-string inside the cJSON data structure.
         * The caller must not free or modify this pointer.
         *
         * @param root the pointer to the cJSON structure
         * @name Name of the value
         * @error Error value, the function returns this value if the JSON structure contains no @c name
         */
        static const char* const getJsonString(const cJSON* const root, const char* const name, const char* const error);

        /**
         * @brief Return a boolean value from a JSON structure.
         *
         * The functions returns the boolean value of a JSON name.
         *
         * @param root the pointer to the cJSON structure
         * @name Name of the value
         * @error Error value, the function returns this value if the JSON structure contains no @c name
         */
        static bool getJsonBool(const cJSON* const root, const char* const name, bool error);

        /**
         * @brief Splits a string around matches of the given delimiter character.
         *
         * Trailing empty strings are not included in the resulting array.
         * This function works similar to the Java string split function, however it does
         * not support regular expressions, only a simple delimiter character.
         *
         * @param data The std::string to split
         * @param delimiter The delimiter character
         * @return A vector of strings
         */
        static shared_ptr<vector<string> > splitString(const string& data, const string delimiter);

        /**
         * @brief Returns a string with date and Time with milliseconds, formatted according to ISO8601.
         *
         * The function uses Zulu (GMT) time, not the local time as input to generate the string.
         * Example of a formatted string: 2016-08-30T13:09:17.122Z
         *
         * @return A formatted string with current Zulu time.
         */
        static string currentTimeMsISO8601();

        /**
         * @brief Returns a string with date and Time without milliseconds, formatted according to ISO8601.
         *
         * The function uses Zulu (GMT) time, not the local time as input to generate the string.
         * Example of a formatted string: 2016-08-30T13:09:17Z
         *
         * @return A formatted string with current Zulu time.
         */
        static string currentTimeISO8601();
    };
}

/**
 * @}
 */
#endif //LIBAXOLOTL_UTILITIES_H
