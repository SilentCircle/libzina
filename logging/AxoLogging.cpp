//
// Created by werner on 30.11.15.
//

#include "AxoLogging.h"

#ifdef ANDROID_LOGGER
std::shared_ptr<logging::Logger<logging::AndroidLogPolicy> >
        _globalLogger = std::make_shared<logging::Logger<logging::AndroidLogPolicy> >(std::string(""));

#elif defined(LINUX_LOGGER)
std::shared_ptr<logging::Logger<logging::CerrLogPolicy> >
        _globalLogger = std::make_shared<logging::Logger<logging::CerrLogPolicy> >(std::string(""));
#else
#error "Define Logger instance according to the system in use."
#endif

void setAxoLogLevel(int32_t level)
{
    _globalLogger->setLogLevel(static_cast<LoggingLogLevel>(level));
}