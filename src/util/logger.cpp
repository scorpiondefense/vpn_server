#include "vpn/util/logger.hpp"

namespace vpn::util {

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

} // namespace vpn::util
