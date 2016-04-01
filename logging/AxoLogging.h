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
//
// Created by werner on 30.11.15.
//

#ifndef LIBAXOLOTL_AXOLOGGING_H
#define LIBAXOLOTL_AXOLOGGING_H

// Set the project's maximum compiler log level if not otherwise specified during
// compilation. See main CMakeLists.txt file, setting CMAKE_CXX_FLAGS_DEBUG for
// DEBUG builds.
// The standard compile setting is logging level 'WARNING'

#ifndef LOG_MAX_LEVEL
#define LOG_MAX_LEVEL WARNING
#endif

#define LOGGER_INSTANCE _globalLogger->
#include "Logger.h"

#ifdef ANDROID_LOGGER
extern std::shared_ptr<logging::Logger<logging::AndroidLogPolicy> > _globalLogger;

#elif defined(LINUX_LOGGER) || defined(APPLE_LOGGER)
extern std::shared_ptr<logging::Logger<logging::CerrLogPolicy> > _globalLogger;
#else
#error "Define Logger instance according to the system in use."
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

__EXPORT extern void setAxoLogLevel(int32_t level);

#if defined(__cplusplus)
}
#endif

#endif //LIBAXOLOTL_AXOLOGGING_CPP_H
