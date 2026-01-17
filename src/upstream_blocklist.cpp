#include "upstream_blocklist.h"

#include "util.h"
#include "config.h"

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <curl/curl.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

namespace gravastar {

namespace {

bool FileExists(const std::string &path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

bool ParseQuotedString(const std::string &raw, std::string *out) {
    if (!out) {
        return false;
    }
    std::string s = Trim(raw);
    if (s.size() < 2 || s[0] != '"' || s[s.size() - 1] != '"') {
        return false;
    }
    *out = s.substr(1, s.size() - 2);
    return true;
}

bool ParseInteger(const std::string &raw, unsigned long *out) {
    if (!out) {
        return false;
    }
    std::string s = Trim(raw);
    if (s.empty()) {
        return false;
    }
    char *endptr = 0;
    unsigned long val = std::strtoul(s.c_str(), &endptr, 10);
    if (endptr == s.c_str() || *endptr != '\0') {
        return false;
    }
    *out = val;
    return true;
}

bool ParseStringArray(const std::string &raw, std::vector<std::string> *out) {
    if (!out) {
        return false;
    }
    std::string s = Trim(raw);
    if (s.size() < 2 || s[0] != '[' || s[s.size() - 1] != ']') {
        return false;
    }
    std::string inner = Trim(s.substr(1, s.size() - 2));
    if (inner.empty()) {
        return true;
    }
    std::vector<std::string> parts = Split(inner, ',');
    for (size_t i = 0; i < parts.size(); ++i) {
        std::string item;
        if (!ParseQuotedString(parts[i], &item)) {
            return false;
        }
        out->push_back(item);
    }
    return true;
}

std::string StripComment(const std::string &line) {
    size_t pos = line.find('#');
    if (pos == std::string::npos) {
        return line;
    }
    return line.substr(0, pos);
}

bool ReadLines(const std::string &path, std::vector<std::string> *lines, std::string *err) {
    if (!lines) {
        return false;
    }
    std::ifstream in(path.c_str());
    if (!in.is_open()) {
        if (err) {
            *err = "unable to open file: " + path;
        }
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        lines->push_back(line);
    }
    return true;
}

bool IsDir(const std::string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

bool EnsureDir(const std::string &path) {
    if (IsDir(path)) {
        return true;
    }
    if (mkdir(path.c_str(), 0755) == 0) {
        return true;
    }
    return IsDir(path);
}

std::string ReadFile(const std::string &path) {
    std::ifstream in(path.c_str());
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

bool WriteFile(const std::string &path, const std::string &contents, std::string *err) {
    std::ofstream out(path.c_str());
    if (!out.is_open()) {
        if (err) {
            *err = "unable to write file: " + path;
        }
        return false;
    }
    out << contents;
    return true;
}

unsigned long HashUrl(const std::string &url) {
    unsigned long hash = 5381;
    for (size_t i = 0; i < url.size(); ++i) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(url[i]);
    }
    return hash;
}

std::vector<std::string> SplitWhitespace(const std::string &line) {
    std::vector<std::string> parts;
    std::string current;
    for (size_t i = 0; i < line.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(line[i]);
        if (std::isspace(c)) {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(line[i]);
        }
    }
    if (!current.empty()) {
        parts.push_back(current);
    }
    return parts;
}

bool LooksLikeIp(const std::string &token) {
    if (token.find(':') != std::string::npos) {
        return true;
    }
    bool has_dot = false;
    for (size_t i = 0; i < token.size(); ++i) {
        char c = token[i];
        if (c == '.') {
            has_dot = true;
        } else if (c < '0' || c > '9') {
            return false;
        }
    }
    return has_dot;
}

bool IsValidLabel(const std::string &label) {
    if (label.empty()) {
        return false;
    }
    if (label[0] == '-' || label[label.size() - 1] == '-') {
        return false;
    }
    for (size_t i = 0; i < label.size(); ++i) {
        char c = label[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-') {
            continue;
        }
        return false;
    }
    return true;
}

bool NormalizeDomain(const std::string &raw, std::string *out) {
    if (!out) {
        return false;
    }
    std::string name = ToLower(raw);
    if (!name.empty() && name[name.size() - 1] == '.') {
        name.resize(name.size() - 1);
    }
    if (name.empty()) {
        return false;
    }
    if (name.find('/') != std::string::npos || name.find('*') != std::string::npos) {
        return false;
    }
    std::vector<std::string> labels = Split(name, '.');
    if (labels.size() < 2) {
        return false;
    }
    for (size_t i = 0; i < labels.size(); ++i) {
        if (!IsValidLabel(labels[i])) {
            return false;
        }
    }
    *out = name;
    return true;
}

bool IsSkippableLine(const std::string &line) {
    if (line.empty()) {
        return true;
    }
    if (line[0] == '!' || line[0] == '[' || line[0] == '#') {
        return true;
    }
    if (line.find("##") != std::string::npos ||
        line.find("#@#") != std::string::npos ||
        line.find("#?#") != std::string::npos ||
        line.find("#$#") != std::string::npos) {
        return true;
    }
    return false;
}

size_t CurlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    std::string *out = static_cast<std::string *>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

bool FetchUrl(const std::string &url, std::string *out, std::string *err) {
    if (!out) {
        return false;
    }
    static bool curl_inited = false;
    if (!curl_inited) {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
            if (err) {
                *err = "curl_global_init failed";
            }
            return false;
        }
        curl_inited = true;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        if (err) {
            *err = "curl_easy_init failed";
        }
        return false;
    }
    out->clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK) {
        if (err) {
            *err = std::string("curl error: ") + curl_easy_strerror(res);
        }
        return false;
    }
    return true;
}

} // namespace

bool LoadUpstreamBlocklistConfig(const std::string &path,
                                 UpstreamBlocklistConfig *out,
                                 std::string *err) {
    if (!out) {
        return false;
    }
    out->urls.clear();
    out->update_interval_sec = 3600;
    out->cache_dir = "/var/gravastar";

    std::vector<std::string> lines;
    if (!ReadLines(path, &lines, err)) {
        return false;
    }
    for (size_t i = 0; i < lines.size(); ++i) {
        std::string line = Trim(StripComment(lines[i]));
        if (line.empty()) {
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = Trim(line.substr(0, eq));
        std::string value = Trim(line.substr(eq + 1));
        if (key == "update_interval_sec") {
            unsigned long v = 0;
            if (!ParseInteger(value, &v)) {
                if (err) *err = "invalid update_interval_sec";
                return false;
            }
            out->update_interval_sec = static_cast<unsigned int>(v);
        } else if (key == "urls") {
            while (value.find(']') == std::string::npos && i + 1 < lines.size()) {
                ++i;
                std::string next = Trim(StripComment(lines[i]));
                if (!next.empty()) {
                    value.append(next);
                }
            }
            if (!ParseStringArray(value, &out->urls)) {
                if (err) *err = "invalid urls";
                return false;
            }
        } else if (key == "cache_dir") {
            std::string v;
            if (!ParseQuotedString(value, &v)) {
                if (err) *err = "invalid cache_dir";
                return false;
            }
            out->cache_dir = v;
        }
    }
    if (out->update_interval_sec == 0) {
        out->update_interval_sec = 3600;
    }
    return true;
}

bool ParseUpstreamBlocklistContent(const std::string &content,
                                   std::set<std::string> *domains) {
    if (!domains) {
        return false;
    }
    std::istringstream in(content);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line[line.size() - 1] == '\r') {
            line.resize(line.size() - 1);
        }
        std::string trimmed = Trim(line);
        if (IsSkippableLine(trimmed)) {
            continue;
        }
        if (StartsWith(trimmed, "||")) {
            size_t caret = trimmed.find('^', 2);
            if (caret == std::string::npos) {
                continue;
            }
            std::string domain = trimmed.substr(2, caret - 2);
            std::string normalized;
            if (NormalizeDomain(domain, &normalized)) {
                domains->insert(normalized);
            }
            continue;
        }
        std::vector<std::string> tokens = SplitWhitespace(trimmed);
        if (tokens.empty()) {
            continue;
        }
        size_t start = 0;
        if (LooksLikeIp(tokens[0])) {
            start = 1;
        }
        for (size_t i = start; i < tokens.size(); ++i) {
            if (!tokens[i].empty() && tokens[i][0] == '#') {
                break;
            }
            std::string normalized;
            if (NormalizeDomain(tokens[i], &normalized)) {
                domains->insert(normalized);
            }
        }
    }
    return true;
}

bool BuildBlocklistFromSources(const std::vector<std::string> &urls,
                               const std::string &cache_dir,
                               std::set<std::string> *domains,
                               std::string *err) {
    if (!domains) {
        return false;
    }
    domains->clear();
    if (urls.empty()) {
        if (err) {
            *err = "no upstream urls configured";
        }
        return false;
    }
    if (!EnsureDir(cache_dir)) {
        if (err) {
            *err = "unable to create cache dir: " + cache_dir;
        }
        return false;
    }
    for (size_t i = 0; i < urls.size(); ++i) {
        std::string content;
        std::string fetch_err;
        LogInfo("Upstream blocklist fetch: " + urls[i]);
        bool fetched = FetchUrl(urls[i], &content, &fetch_err);
        std::string cache_path = CachePathForUrl(cache_dir, urls[i]);
        if (fetched) {
            WriteFile(cache_path, content, NULL);
            LogInfo("Upstream blocklist fetched: " + urls[i]);
        } else if (FileExists(cache_path)) {
            content = ReadFile(cache_path);
            LogWarn("Upstream fetch failed, using cached copy: " + urls[i] + " (" + fetch_err + ")");
        } else {
            if (err) {
                *err = "failed to fetch url and no cache: " + urls[i];
            }
            return false;
        }
        ParseUpstreamBlocklistContent(content, domains);
    }
    return true;
}

bool WriteBlocklistToml(const std::string &path,
                        const std::set<std::string> &domains,
                        std::string *err) {
    std::ostringstream out;
    out << "domains = [\n";
    for (std::set<std::string>::const_iterator it = domains.begin();
         it != domains.end(); ++it) {
        out << "  \"" << *it << "\",\n";
    }
    out << "]\n";
    std::string tmp_path = path + ".tmp";
    if (!WriteFile(tmp_path, out.str(), err)) {
        return false;
    }
    if (rename(tmp_path.c_str(), path.c_str()) != 0) {
        if (err) {
            *err = "rename failed for blocklist";
        }
        unlink(tmp_path.c_str());
        return false;
    }
    return true;
}

std::string CachePathForUrl(const std::string &cache_dir,
                            const std::string &url) {
    std::ostringstream out;
    out << cache_dir << "/upstream_" << HashUrl(url) << ".txt";
    return out.str();
}

UpstreamBlocklistUpdater::UpstreamBlocklistUpdater(
    const UpstreamBlocklistConfig &config,
    const std::string &custom_blocklist_path,
    const std::string &output_path,
    Blocklist *blocklist)
    : config_(config),
      custom_blocklist_path_(custom_blocklist_path),
      output_path_(output_path),
      blocklist_(blocklist),
      thread_(),
      running_(false) {
    pthread_mutex_init(&mutex_, NULL);
    pthread_cond_init(&cv_, NULL);
}

UpstreamBlocklistUpdater::~UpstreamBlocklistUpdater() {
    Stop();
    pthread_cond_destroy(&cv_);
    pthread_mutex_destroy(&mutex_);
}

bool UpstreamBlocklistUpdater::EnsureCacheDir() {
    return EnsureDir(config_.cache_dir);
}

bool UpstreamBlocklistUpdater::UpdateOnce() {
    if (!EnsureCacheDir()) {
        LogError("Upstream blocklist cache dir missing: " + config_.cache_dir);
        return false;
    }
    std::set<std::string> domains;
    std::string err;
    if (!BuildBlocklistFromSources(config_.urls, config_.cache_dir, &domains, &err)) {
        DebugLog("Upstream blocklist update failed: " + err);
        LogError("Upstream blocklist update failed: " + err);
        return false;
    }
    std::set<std::string> custom_domains;
    if (!custom_blocklist_path_.empty()) {
        if (!ConfigLoader::LoadBlocklist(custom_blocklist_path_, &custom_domains, &err)) {
            LogError("Custom blocklist load failed: " + err);
            return false;
        }
    }
    domains.insert(custom_domains.begin(), custom_domains.end());
    if (!WriteBlocklistToml(output_path_, domains, &err)) {
        DebugLog("Failed to write blocklist.toml: " + err);
        LogError("Failed to write blocklist.toml: " + err);
        return false;
    }
    if (blocklist_) {
        blocklist_->SetDomains(domains);
    }
    std::ostringstream out;
    out << "Upstream blocklist updated: " << domains.size() << " domains";
    LogInfo(out.str());
    return true;
}

bool UpstreamBlocklistUpdater::Start() {
    pthread_mutex_lock(&mutex_);
    if (running_) {
        pthread_mutex_unlock(&mutex_);
        return false;
    }
    running_ = true;
    pthread_mutex_unlock(&mutex_);
    if (pthread_create(&thread_, NULL, ThreadEntry, this) != 0) {
        pthread_mutex_lock(&mutex_);
        running_ = false;
        pthread_mutex_unlock(&mutex_);
        LogError("Failed to start upstream blocklist thread");
        return false;
    }
    LogInfo("Upstream blocklist updater started");
    return true;
}

void UpstreamBlocklistUpdater::Stop() {
    pthread_mutex_lock(&mutex_);
    if (!running_) {
        pthread_mutex_unlock(&mutex_);
        return;
    }
    running_ = false;
    pthread_cond_broadcast(&cv_);
    pthread_mutex_unlock(&mutex_);
    pthread_join(thread_, NULL);
    LogInfo("Upstream blocklist updater stopped");
}

void *UpstreamBlocklistUpdater::ThreadEntry(void *arg) {
    UpstreamBlocklistUpdater *self = static_cast<UpstreamBlocklistUpdater *>(arg);
    self->ThreadLoop();
    return NULL;
}

void UpstreamBlocklistUpdater::ThreadLoop() {
    LogInfo("Upstream blocklist initial update");
    UpdateOnce();
    pthread_mutex_lock(&mutex_);
    while (running_) {
        struct timespec ts;
        time_t now = time(NULL);
        ts.tv_sec = now + config_.update_interval_sec;
        ts.tv_nsec = 0;
        pthread_cond_timedwait(&cv_, &mutex_, &ts);
        if (!running_) {
            break;
        }
        pthread_mutex_unlock(&mutex_);
        LogInfo("Upstream blocklist periodic update");
        UpdateOnce();
        pthread_mutex_lock(&mutex_);
    }
    pthread_mutex_unlock(&mutex_);
}

} // namespace gravastar
