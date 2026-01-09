#ifndef GRAVASTAR_CONTROLLER_LOGGER_H
#define GRAVASTAR_CONTROLLER_LOGGER_H

#include "util.h"

#include <cstdio>
#include <pthread.h>
#include <string>

namespace gravastar {

class ControllerLogger {
public:
    ControllerLogger(const std::string &dir, size_t max_bytes);
    ~ControllerLogger();

    bool Log(LogLevel level, const std::string &msg);

private:
    struct LogFile {
        std::string name;
        std::string path;
        FILE *file;
    };

    bool EnsureDirectory();
    bool EnsureOpen();
    bool RotateIfNeeded();
    bool WriteLine(const std::string &line);
    std::string NowString() const;
    std::string LevelString(LogLevel level) const;
    bool CompressFile(const std::string &path);
    void CleanupOld(const std::string &suffix);
    std::string UniqueRotatedName() const;

    std::string dir_;
    size_t max_bytes_;
    bool enabled_;
    pthread_mutex_t mutex_;
    LogFile log_;
};

} // namespace gravastar

#endif // GRAVASTAR_CONTROLLER_LOGGER_H
