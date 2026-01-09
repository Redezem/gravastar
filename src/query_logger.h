#ifndef GRAVASTAR_QUERY_LOGGER_H
#define GRAVASTAR_QUERY_LOGGER_H

#include <cstdio>
#include <pthread.h>
#include <string>

namespace gravastar {

class QueryLogger {
public:
    QueryLogger(const std::string &dir, size_t max_bytes);
    ~QueryLogger();

    bool LogPass(const std::string &client_ip,
                 const std::string &client_name,
                 const std::string &qname,
                 const std::string &qtype,
                 const std::string &resolved_by,
                 const std::string &upstream);
    bool LogBlock(const std::string &client_ip,
                  const std::string &client_name,
                  const std::string &qname,
                  const std::string &qtype);

private:
    struct LogFile {
        std::string name;
        std::string path;
        FILE *file;
    };

    bool EnsureDirectory();
    bool EnsureOpen(LogFile *log);
    bool RotateIfNeeded(LogFile *log);
    bool WriteLine(LogFile *log, const std::string &line);
    std::string NowString() const;
    std::string BuildLine(const std::string &client_ip,
                          const std::string &client_name,
                          const std::string &qname,
                          const std::string &qtype,
                          const std::string &resolved_by,
                          const std::string &upstream) const;
    std::string BuildBlockLine(const std::string &client_ip,
                               const std::string &client_name,
                               const std::string &qname,
                               const std::string &qtype) const;
    bool CompressFile(const std::string &path);
    void CleanupOld(const std::string &suffix);
    std::string UniqueRotatedName(const std::string &base_name) const;

    std::string dir_;
    size_t max_bytes_;
    bool enabled_;
    pthread_mutex_t mutex_;
    LogFile pass_;
    LogFile block_;
};

} // namespace gravastar

#endif // GRAVASTAR_QUERY_LOGGER_H
