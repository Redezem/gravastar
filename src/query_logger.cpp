#include "query_logger.h"
#include "util.h"

#include <cerrno>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace gravastar {

namespace {

bool EndsWith(const std::string &value, const std::string &suffix) {
    if (suffix.size() > value.size()) {
        return false;
    }
    return value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool IsDir(const std::string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

} // namespace

QueryLogger::QueryLogger(const std::string &dir, size_t max_bytes)
    : dir_(dir),
      max_bytes_(max_bytes),
      enabled_(false),
      pass_(),
      block_() {
    pthread_mutex_init(&mutex_, NULL);
    pass_.name = "pass.log";
    block_.name = "block.log";
    pass_.file = NULL;
    block_.file = NULL;
    pass_.path = dir_ + "/" + pass_.name;
    block_.path = dir_ + "/" + block_.name;
    enabled_ = EnsureDirectory();
}

QueryLogger::~QueryLogger() {
    pthread_mutex_lock(&mutex_);
    if (pass_.file) {
        fclose(pass_.file);
        pass_.file = NULL;
    }
    if (block_.file) {
        fclose(block_.file);
        block_.file = NULL;
    }
    pthread_mutex_unlock(&mutex_);
    pthread_mutex_destroy(&mutex_);
}

bool QueryLogger::EnsureDirectory() {
    if (IsDir(dir_)) {
        return true;
    }
    if (mkdir(dir_.c_str(), 0755) == 0) {
        return true;
    }
    if (IsDir(dir_)) {
        return true;
    }
    LogError("Failed to create log dir " + dir_ + ": " + std::strerror(errno));
    return false;
}

bool QueryLogger::EnsureOpen(LogFile *log) {
    if (!enabled_ || !log) {
        return false;
    }
    if (log->file) {
        return true;
    }
    log->file = std::fopen(log->path.c_str(), "a");
    if (!log->file) {
        LogError("Failed to open log file " + log->path + ": " + std::strerror(errno));
        return false;
    }
    return true;
}

bool QueryLogger::RotateIfNeeded(LogFile *log) {
    if (!enabled_ || !log) {
        return false;
    }
    struct stat st;
    if (stat(log->path.c_str(), &st) != 0) {
        return false;
    }
    if (static_cast<size_t>(st.st_size) < max_bytes_) {
        return false;
    }
    if (log->file) {
        fclose(log->file);
        log->file = NULL;
    }
    std::string rotated = UniqueRotatedName(log->name);
    if (rename(log->path.c_str(), rotated.c_str()) != 0) {
        LogError("Failed to rotate log file " + log->path + ": " + std::strerror(errno));
        return false;
    }
    if (!CompressFile(rotated)) {
        LogError("Failed to compress log file " + rotated);
    }
    CleanupOld("_" + log->name + ".gz");
    return true;
}

bool QueryLogger::WriteLine(LogFile *log, const std::string &line) {
    if (!EnsureOpen(log)) {
        return false;
    }
    RotateIfNeeded(log);
    if (!EnsureOpen(log)) {
        return false;
    }
    if (std::fwrite(line.data(), 1, line.size(), log->file) != line.size()) {
        return false;
    }
    if (std::fwrite("\n", 1, 1, log->file) != 1) {
        return false;
    }
    std::fflush(log->file);
    return true;
}

std::string QueryLogger::NowString() const {
    char buf[32];
    std::time_t now = std::time(NULL);
    struct tm tm_buf;
    struct tm *tm_ptr = localtime_r(&now, &tm_buf);
    if (!tm_ptr) {
        return "1970-01-01T00:00:00";
    }
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm_ptr);
    return std::string(buf);
}

std::string QueryLogger::BuildLine(const std::string &client_ip,
                                   const std::string &client_name,
                                   const std::string &qname,
                                   const std::string &qtype,
                                   const std::string &resolved_by,
                                   const std::string &upstream) const {
    std::ostringstream out;
    out << "ts=" << NowString()
        << " client_ip=" << client_ip
        << " client_name=" << client_name
        << " qname=" << qname
        << " qtype=" << qtype
        << " resolved_by=" << resolved_by;
    if (!upstream.empty()) {
        out << " upstream=" << upstream;
    }
    return out.str();
}

std::string QueryLogger::BuildBlockLine(const std::string &client_ip,
                                        const std::string &client_name,
                                        const std::string &qname,
                                        const std::string &qtype) const {
    std::ostringstream out;
    out << "ts=" << NowString()
        << " client_ip=" << client_ip
        << " client_name=" << client_name
        << " qname=" << qname
        << " qtype=" << qtype;
    return out.str();
}

bool QueryLogger::CompressFile(const std::string &path) {
    pid_t pid = fork();
    if (pid < 0) {
        return false;
    }
    if (pid == 0) {
        execlp("gzip", "gzip", "-f", path.c_str(), static_cast<char *>(NULL));
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

void QueryLogger::CleanupOld(const std::string &suffix) {
    DIR *dir = opendir(dir_.c_str());
    if (!dir) {
        return;
    }
    std::vector<std::pair<long long, std::string> > entries;
    struct dirent *ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
        std::string name = ent->d_name;
        if (!EndsWith(name, suffix)) {
            continue;
        }
        size_t underscore = name.find('_');
        if (underscore == std::string::npos) {
            continue;
        }
        long long ts = 0;
        std::istringstream iss(name.substr(0, underscore));
        iss >> ts;
        if (ts <= 0) {
            continue;
        }
        entries.push_back(std::make_pair(ts, name));
    }
    closedir(dir);
    if (entries.size() <= 10) {
        return;
    }
    std::sort(entries.begin(), entries.end());
    size_t remove_count = entries.size() - 10;
    for (size_t i = 0; i < remove_count; ++i) {
        std::string path = dir_ + "/" + entries[i].second;
        unlink(path.c_str());
    }
}

std::string QueryLogger::UniqueRotatedName(const std::string &base_name) const {
    std::time_t now = std::time(NULL);
    std::ostringstream base;
    base << dir_ << "/" << static_cast<long long>(now) << "_" << base_name;
    std::string candidate = base.str();
    struct stat st;
    if (stat(candidate.c_str(), &st) != 0) {
        return candidate;
    }
    for (int i = 1; i < 1000; ++i) {
        std::ostringstream alt;
        alt << dir_ << "/" << static_cast<long long>(now) << "_" << i << "_" << base_name;
        candidate = alt.str();
        if (stat(candidate.c_str(), &st) != 0) {
            return candidate;
        }
    }
    return candidate;
}

bool QueryLogger::LogPass(const std::string &client_ip,
                          const std::string &client_name,
                          const std::string &qname,
                          const std::string &qtype,
                          const std::string &resolved_by,
                          const std::string &upstream) {
    pthread_mutex_lock(&mutex_);
    bool ok = WriteLine(&pass_, BuildLine(client_ip, client_name, qname, qtype,
                                          resolved_by, upstream));
    pthread_mutex_unlock(&mutex_);
    return ok;
}

bool QueryLogger::LogBlock(const std::string &client_ip,
                           const std::string &client_name,
                           const std::string &qname,
                           const std::string &qtype) {
    pthread_mutex_lock(&mutex_);
    bool ok = WriteLine(&block_, BuildBlockLine(client_ip, client_name, qname, qtype));
    pthread_mutex_unlock(&mutex_);
    return ok;
}

} // namespace gravastar
