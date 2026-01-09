#include "query_logger.h"
#include "controller_logger.h"
#include "util.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

bool EndsWith(const std::string &value, const std::string &suffix) {
    if (suffix.size() > value.size()) {
        return false;
    }
    return value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool RemoveTree(const std::string &path) {
    DIR *dir = opendir(path.c_str());
    if (!dir) {
        return false;
    }
    struct dirent *ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
        std::string name = ent->d_name;
        if (name == "." || name == "..") {
            continue;
        }
        std::string full = path + "/" + name;
        struct stat st;
        if (stat(full.c_str(), &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            RemoveTree(full);
            rmdir(full.c_str());
        } else {
            unlink(full.c_str());
        }
    }
    closedir(dir);
    rmdir(path.c_str());
    return true;
}

size_t CountFilesWithSuffix(const std::string &dir, const std::string &suffix) {
    DIR *d = opendir(dir.c_str());
    if (!d) {
        return 0;
    }
    size_t count = 0;
    struct dirent *ent = NULL;
    while ((ent = readdir(d)) != NULL) {
        std::string name = ent->d_name;
        if (EndsWith(name, suffix)) {
            count++;
        }
    }
    closedir(d);
    return count;
}

std::string MakeTempDir() {
    char tmpl[] = "/tmp/gravastar_logs_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        return "";
    }
    return std::string(dir);
}

} // namespace

bool TestLoggingRotation() {
    std::string dir = MakeTempDir();
    if (dir.empty()) {
        return false;
    }
    {
        gravastar::QueryLogger logger(dir, 100);
        std::string long_name(120, 'a');
        for (int i = 0; i < 25; ++i) {
            if (!logger.LogPass("1.2.3.4", "client.example", long_name, "A",
                                "external", "9.9.9.9")) {
                RemoveTree(dir);
                return false;
            }
        }
    }
    size_t pass_count = CountFilesWithSuffix(dir, "_pass.log.gz");
    if (pass_count > 10) {
        RemoveTree(dir);
        return false;
    }
    struct stat st;
    std::string pass_path = dir + "/pass.log";
    if (stat(pass_path.c_str(), &st) != 0) {
        RemoveTree(dir);
        return false;
    }
    RemoveTree(dir);
    return true;
}

bool TestLoggingFailurePath() {
    std::string dir = MakeTempDir();
    if (dir.empty()) {
        return false;
    }
    std::string file_path = dir + "/not_a_dir";
    FILE *fp = std::fopen(file_path.c_str(), "w");
    if (!fp) {
        RemoveTree(dir);
        return false;
    }
    std::fputs("x", fp);
    std::fclose(fp);
    gravastar::QueryLogger logger(file_path, 100);
    bool ok = logger.LogPass("1.2.3.4", "client.example", "example.com", "A",
                             "external", "9.9.9.9");
    RemoveTree(dir);
    return !ok;
}

bool TestControllerLoggerRotation() {
    std::string dir = MakeTempDir();
    if (dir.empty()) {
        return false;
    }
    {
        gravastar::ControllerLogger logger(dir, 100);
        for (int i = 0; i < 25; ++i) {
            if (!logger.Log(gravastar::LOG_INFO, "controller message")) {
                RemoveTree(dir);
                return false;
            }
        }
    }
    size_t count = CountFilesWithSuffix(dir, "_controller.log.gz");
    if (count > 10) {
        RemoveTree(dir);
        return false;
    }
    struct stat st;
    std::string path = dir + "/controller.log";
    if (stat(path.c_str(), &st) != 0) {
        RemoveTree(dir);
        return false;
    }
    RemoveTree(dir);
    return true;
}

bool TestControllerLogLevelFilter() {
    std::string dir = MakeTempDir();
    if (dir.empty()) {
        return false;
    }
    gravastar::ControllerLogger logger(dir, 1024);
    gravastar::SetControllerLogger(&logger);
    gravastar::SetLogLevel(gravastar::LOG_WARN);
    gravastar::LogInfo("info message");
    gravastar::LogError("error message");
    std::string path = dir + "/controller.log";
    std::ifstream in(path.c_str());
    if (!in.is_open()) {
        RemoveTree(dir);
        return false;
    }
    std::string contents;
    std::getline(in, contents);
    bool has_error = contents.find("error message") != std::string::npos;
    bool has_info = contents.find("info message") != std::string::npos;
    gravastar::SetControllerLogger(NULL);
    gravastar::SetLogLevel(gravastar::LOG_DEBUG);
    RemoveTree(dir);
    return has_error && !has_info;
}
