#include "sandbox.h"

#include "util.h"

#include <string>
#include <sys/stat.h>
#include <vector>

#if !defined(_WIN32)
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#endif

#if defined(__OpenBSD__)
// OpenBSD declares pledge(2)/unveil(2) in <unistd.h>.
#include <unistd.h>
#endif

namespace gravastar {

bool ApplyOsSandbox(const std::vector<std::string> &read_paths,
                    const std::vector<std::string> &readwrite_paths,
                    const std::vector<std::string> &exec_paths) {
#if defined(__OpenBSD__)
    for (size_t i = 0; i < read_paths.size(); ++i) {
        if (read_paths[i].empty()) {
            continue;
        }
        struct stat st;
        if (stat(read_paths[i].c_str(), &st) != 0) {
            // Candidate path (e.g. distro-specific CA stores); absent is fine.
            continue;
        }
        if (unveil(read_paths[i].c_str(), "r") != 0) {
            LogError("unveil(r) failed for " + read_paths[i]);
            return false;
        }
    }
    for (size_t i = 0; i < readwrite_paths.size(); ++i) {
        if (readwrite_paths[i].empty()) {
            continue;
        }
        struct stat st;
        if (stat(readwrite_paths[i].c_str(), &st) != 0) {
            LogError("unveil(rw) target missing: " + readwrite_paths[i]);
            return false;
        }
        if (unveil(readwrite_paths[i].c_str(), "rw") != 0) {
            LogError("unveil(rw) failed for " + readwrite_paths[i]);
            return false;
        }
    }
    for (size_t i = 0; i < exec_paths.size(); ++i) {
        if (exec_paths[i].empty()) {
            continue;
        }
        struct stat st;
        if (stat(exec_paths[i].c_str(), &st) != 0) {
            continue;
        }
        if (unveil(exec_paths[i].c_str(), "x") != 0) {
            LogError("unveil(x) failed for " + exec_paths[i]);
            return false;
        }
    }
    if (unveil(NULL, NULL) != 0) {
        LogError("unveil lockdown failed");
        return false;
    }
    // stdio: log fds/console; rpath: config + CA reads; wpath/cpath: logs and
    // generated blocklist; inet+dns: upstream resolution; proc+exec: the
    // log-rotation fork/exec of gzip.
    if (pledge("stdio rpath wpath cpath inet dns proc exec", NULL) != 0) {
        LogError("pledge() failed");
        return false;
    }
    LogInfo("OpenBSD sandbox applied (unveil + pledge)");
#else
    (void)read_paths;
    (void)readwrite_paths;
    (void)exec_paths;
#endif
    return true;
}

bool DropPrivileges(const std::string &user) {
#if defined(_WIN32)
    (void)user;
    return true;
#else
    if (user.empty()) {
        return true;
    }
    struct passwd *pw = getpwnam(user.c_str());
    if (!pw) {
        LogError("drop_priv_user: unknown user: " + user);
        return false;
    }
    if (geteuid() == 0) {
        if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
            LogError("drop_priv_user: initgroups failed for " + user);
            return false;
        }
        if (setgid(pw->pw_gid) != 0) {
            LogError("drop_priv_user: setgid failed for " + user);
            return false;
        }
        if (setuid(pw->pw_uid) != 0) {
            LogError("drop_priv_user: setuid failed for " + user);
            return false;
        }
        LogInfo("Dropped privileges to user: " + user);
        return true;
    }
    if (getuid() == pw->pw_uid) {
        // Already running as the requested user (e.g. daemon -u); nothing to do.
        return true;
    }
    LogError("drop_priv_user: not root and not already " + user + "; refusing");
    return false;
#endif
}

} // namespace gravastar
