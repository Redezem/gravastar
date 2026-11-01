#ifndef GRAVASTAR_SANDBOX_H
#define GRAVASTAR_SANDBOX_H

#include <string>
#include <vector>

namespace gravastar {

// Applies OS-level sandboxing where available (OpenBSD unveil+pledge; no-op
// elsewhere). Must be called after all configuration, blocklists, and logs
// have been set up, and with knowledge of every path the process will touch
// at runtime (log rotation opens gzip; DoT reads CA bundles). Returns false
// if sandboxing was attempted but could not be fully applied: the caller
// must treat that as fatal rather than continue unsandboxed.
bool ApplyOsSandbox(const std::vector<std::string> &read_paths,
                    const std::vector<std::string> &readwrite_paths,
                    const std::vector<std::string> &exec_paths);

} // namespace gravastar

#endif // GRAVASTAR_SANDBOX_H
