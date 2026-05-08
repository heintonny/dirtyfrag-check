#!/usr/bin/env python3
"""
DirtyFrag safe detection script.
Read-only: inspects kernel config, module files, blacklists, and sysctl.
Does NOT load any modules, open any sockets, or call any kernel APIs.

Based on the technical conditions documented at:
https://github.com/V4bel/dirtyfrag
"""

import os
import glob
import platform
import subprocess
import sys

RESET = "\033[0m"
RED   = "\033[31m"
YEL   = "\033[33m"
GRN   = "\033[32m"
BOLD  = "\033[1m"
CYA   = "\033[36m"

def color(c, s): return f"{c}{s}{RESET}"
def ok(s):   return color(GRN,  f"  [OK]  {s}")
def warn(s): return color(YEL,  f"  [!!]  {s}")
def bad(s):  return color(RED,   f"  [BAD] {s}")
def info(s): return color(CYA,  f"  [..] {s}")

# ── helpers ────────────────────────────────────────────────────────────────

def read_file(path, default=""):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default

def sysctl(key):
    path = "/proc/sys/" + key.replace(".", "/")
    val = read_file(path, "").strip()
    return val if val else None

def lsmod_loaded():
    out = read_file("/proc/modules", "")
    return {line.split()[0] for line in out.splitlines() if line}

def kernel_config():
    uname = platform.uname().release
    for path in [f"/boot/config-{uname}", "/proc/config.gz"]:
        if os.path.exists(path):
            if path.endswith(".gz"):
                import gzip
                try:
                    return gzip.open(path, "rt").read()
                except Exception:
                    return ""
            return read_file(path)
    return ""

def config_value(cfg, key):
    """Return 'y', 'm', 'n', or None."""
    for line in cfg.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
        if line.strip() == f"# {key} is not set":
            return "n"
    return None

def module_on_disk(name):
    uname = platform.uname().release
    patterns = [
        f"/lib/modules/{uname}/**/{name}.ko",
        f"/lib/modules/{uname}/**/{name}.ko.zst",
        f"/lib/modules/{uname}/**/{name}.ko.xz",
        f"/lib/modules/{uname}/**/{name}.ko.gz",
    ]
    for pat in patterns:
        if glob.glob(pat, recursive=True):
            return True
    return False

def is_blacklisted(name):
    """
    Returns True if the module has an 'install X /bin/false' or
    'blacklist X' entry in any modprobe.d file.
    """
    blocked = False
    unreadable = []
    for d in ["/etc/modprobe.d", "/lib/modprobe.d", "/run/modprobe.d"]:
        if not os.path.isdir(d):
            continue
        for f in glob.glob(os.path.join(d, "*.conf")):
            if not os.access(f, os.R_OK):
                unreadable.append(f)
                continue
            content = read_file(f)
            for line in content.splitlines():
                parts = line.lower().split()
                if not parts or parts[0].startswith("#"):
                    continue
                if len(parts) >= 2 and parts[1] == name:
                    if parts[0] == "blacklist":
                        blocked = True
                    if parts[0] == "install" and "/false" in line:
                        return True   # strongest form — stop immediately
    if unreadable:
        print(warn(f"Could not read {len(unreadable)} modprobe.d file(s) — run as root or fix permissions (chmod 644):"))
        for p in unreadable:
            print(f"         {p}")
    return blocked

# ── main ──────────────────────────────────────────────────────────────────

def main():
    print(color(BOLD, "\n=== DirtyFrag Vulnerability Detection (read-only) ===\n"))

    uname = platform.uname()
    print(info(f"Kernel : {uname.release}"))
    print(info(f"OS     : {uname.system} {uname.version[:80]}"))
    print()

    cfg = kernel_config()
    if not cfg:
        print(warn("Could not read kernel config — some checks will be skipped."))

    loaded = lsmod_loaded()

    # ── Per-module state ──────────────────────────────────────────────────
    modules = {
        "esp4":  "CONFIG_INET_ESP",
        "esp6":  "CONFIG_INET6_ESP",
        "rxrpc": "CONFIG_AF_RXRPC",
    }

    print(color(BOLD, "--- Module state ---"))
    module_status = {}
    for mod, cfg_key in modules.items():
        on_disk  = module_on_disk(mod)
        is_loaded = mod in loaded
        blklisted = is_blacklisted(mod)
        cfg_val   = config_value(cfg, cfg_key) if cfg else "?"

        loadable = on_disk and not blklisted

        if blklisted:
            status_str = ok(f"{mod}: blacklisted (install /bin/false or blacklist entry found)")
        elif is_loaded:
            status_str = bad(f"{mod}: CURRENTLY LOADED — module is active in the kernel")
        elif loadable:
            status_str = warn(f"{mod}: not loaded but present on disk and NOT blacklisted")
        else:
            status_str = ok(f"{mod}: not on disk or not buildable — not reachable")

        print(status_str)
        print(f"         config={cfg_val}  on_disk={on_disk}  loaded={is_loaded}  blacklisted={blklisted}")
        module_status[mod] = loadable or is_loaded

    # ── Namespace restrictions ────────────────────────────────────────────
    print()
    print(color(BOLD, "--- Unprivileged namespace restrictions (affects ESP variant) ---"))

    userns_clone   = sysctl("kernel.unprivileged_userns_clone")
    aa_restrict    = sysctl("kernel.apparmor_restrict_unprivileged_userns")

    if userns_clone == "0":
        print(ok("kernel.unprivileged_userns_clone = 0  (user namespaces blocked at kernel level)"))
        userns_open = False
    elif userns_clone == "1":
        print(warn("kernel.unprivileged_userns_clone = 1  (user namespaces allowed at kernel level)"))
        userns_open = True
    else:
        # Sysctl not present — kernel doesn't have the Ubuntu patch; creation is kernel-policy
        print(warn("kernel.unprivileged_userns_clone not present — assume allowed"))
        userns_open = True

    if aa_restrict == "1":
        print(warn("kernel.apparmor_restrict_unprivileged_userns = 1"
                   "  (AppArmor restricts unconfined processes — partially mitigates ESP variant)"))
    elif aa_restrict == "0":
        print(bad("kernel.apparmor_restrict_unprivileged_userns = 0  (no AppArmor restriction)"))
    else:
        print(info("kernel.apparmor_restrict_unprivileged_userns not found"))

    # ── Per-variant verdict ───────────────────────────────────────────────
    print()
    print(color(BOLD, "--- Variant verdicts ---"))

    esp_reachable   = (module_status.get("esp4") or module_status.get("esp6"))
    rxrpc_reachable = module_status.get("rxrpc", False)

    overall_vulnerable = False

    # ESP variant: needs unshare(CLONE_NEWUSER|CLONE_NEWNET) — affected by AppArmor
    if esp_reachable and userns_open:
        aa_note = " (partially mitigated by AppArmor if aa_restrict=1)" if aa_restrict == "1" else ""
        print(bad(f"ESP (xfrm) variant: REACHABLE{aa_note}"))
        overall_vulnerable = True
    elif esp_reachable and not userns_open:
        print(ok("ESP (xfrm) variant: Kernel blocks unprivileged user namespaces — ESP variant NOT reachable"))
    else:
        print(ok("ESP (xfrm) variant: esp4/esp6 modules not reachable — NOT vulnerable"))

    # RxRPC variant: no namespace privilege needed, works as any unprivileged user
    if rxrpc_reachable:
        print(bad("RxRPC variant      : REACHABLE — no special privilege required, any local user can trigger"))
        overall_vulnerable = True
    else:
        print(ok("RxRPC variant: rxrpc module not reachable — NOT vulnerable via this path"))

    # ── Final verdict ─────────────────────────────────────────────────────
    print()
    print(color(BOLD, "--- Overall verdict ---"))
    if overall_vulnerable:
        print(color(RED + BOLD,
            "  VULNERABLE: At least one attack variant is reachable on this system.\n"
            "  Apply the mitigation (blacklist esp4, esp6, rxrpc) or install a patched kernel."))
    else:
        print(color(GRN + BOLD,
            "  NOT VULNERABLE (by current reachability): all attack paths are blocked."))

    print()
    print(info("NOTE: This script only checks reachability conditions (module availability,"))
    print(info("      blacklists, and sysctl). It does NOT test kernel source code for the"))
    print(info("      actual bug. A patched kernel may still show 'reachable' here — check"))
    print(info("      your distro's USN/advisory for a definitive patched-version answer."))
    print()
    return 1 if overall_vulnerable else 0

if __name__ == "__main__":
    sys.exit(main())
