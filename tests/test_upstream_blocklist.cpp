#include "upstream_blocklist.h"

#include <dirent.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

bool WriteFile(const std::string &path, const std::string &contents) {
    std::ofstream out(path.c_str());
    if (!out.is_open()) {
        return false;
    }
    out << contents;
    return true;
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

std::string MakeTempDir() {
    char tmpl[] = "/tmp/gravastar_upstream_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        return "";
    }
    return std::string(dir);
}

} // namespace

bool TestUpstreamBlocklistParse() {
    std::string content =
        "# comment\n"
        "0.0.0.0 ads.example.com tracker.example.com\n"
        "example.net\n"
        "||abp.example.org^\n"
        "||bad.example.org/path^\n"
        "! ABP comment\n"
        "[Adblock Plus 2.0]\n"
        "127.0.0.1 localhost\n";
    std::set<std::string> domains;
    if (!gravastar::ParseUpstreamBlocklistContent(content, &domains)) {
        return false;
    }
    if (domains.find("ads.example.com") == domains.end()) {
        return false;
    }
    if (domains.find("tracker.example.com") == domains.end()) {
        return false;
    }
    if (domains.find("example.net") == domains.end()) {
        return false;
    }
    if (domains.find("abp.example.org") == domains.end()) {
        return false;
    }
    if (domains.find("bad.example.org") != domains.end()) {
        return false;
    }
    if (domains.find("localhost") != domains.end()) {
        return false;
    }
    return true;
}

bool TestUpstreamBlocklistCacheFallback() {
    std::string dir = MakeTempDir();
    if (dir.empty()) {
        return false;
    }
    std::string url = "file:///nonexistent/list.txt";
    std::string cache_path = gravastar::CachePathForUrl(dir, url);
    if (!WriteFile(cache_path, "cached.example.com\n")) {
        RemoveTree(dir);
        return false;
    }
    std::set<std::string> domains;
    std::vector<std::string> urls;
    urls.push_back(url);
    std::string err;
    if (!gravastar::BuildBlocklistFromSources(urls, dir, &domains, &err)) {
        RemoveTree(dir);
        return false;
    }
    if (domains.find("cached.example.com") == domains.end()) {
        RemoveTree(dir);
        return false;
    }
    std::vector<std::string> urls_fail;
    urls_fail.push_back("file:///nonexistent/missing.txt");
    std::set<std::string> domains_fail;
    std::string err_fail;
    if (gravastar::BuildBlocklistFromSources(urls_fail, dir, &domains_fail, &err_fail)) {
        RemoveTree(dir);
        return false;
    }
    RemoveTree(dir);
    return true;
}
