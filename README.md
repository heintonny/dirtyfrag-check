# dirtyfrag-check

A safe, read-only Python script to detect whether a Linux system is vulnerable to the **DirtyFrag** local privilege escalation vulnerability (CVE pending) — without running any compiled exploit code.

## Background

DirtyFrag is a Linux kernel vulnerability disclosed on 2026-05-07 by Hyunwoo Kim ([@V4bel](https://github.com/V4bel)). It extends the bug class of Dirty Pipe and Copy Fail, and allows any unprivileged local user to gain root on most Linux systems since 2017.

The flaw lives in the in-place decryption fast paths of the `esp4`, `esp6`, and `rxrpc` kernel modules. When a socket buffer carries paged fragments not privately owned by the kernel (e.g. pipe pages attached via `splice(2)` / `MSG_SPLICE_PAGES`), the receive path decrypts directly over those externally-backed pages — exposing or corrupting plaintext that an unprivileged process still holds a reference to.

Two independent variants exist:

| Variant | Modules involved | Privilege required |
|---|---|---|
| **ESP / xfrm** | `esp4`, `esp6` | `unshare(CLONE_NEWUSER\|CLONE_NEWNET)` |
| **RxRPC** | `rxrpc` | None — any local user |

Because it is a deterministic logic bug (no race condition required), it is highly reliable and does not panic the kernel on failure. A working public PoC exists at [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag).

**No CVE has been assigned yet. No official Ubuntu patch is available as of 2026-05-08.**

## What this script checks

The script is purely read-only. It does **not** load any modules, open any sockets, or call any kernel APIs. It inspects:

- `/boot/config-<uname-r>` — kernel build options for `CONFIG_INET_ESP`, `CONFIG_INET6_ESP`, `CONFIG_AF_RXRPC`
- `/lib/modules/<uname-r>/` — whether `.ko` files for the three modules exist on disk
- `/proc/modules` — whether any of the modules are currently loaded
- `/etc/modprobe.d/`, `/lib/modprobe.d/` — whether blacklist or `install /bin/false` entries are in place
- `/proc/sys/kernel/unprivileged_userns_clone` — whether user namespaces are open (affects ESP variant)
- `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` — whether AppArmor partially mitigates the ESP variant

## Requirements

- Python 3.6+
- No third-party packages
- Works as a non-root user

## Usage

```bash
python3 dirtyfrag_check.py
```

Exit code `0` = no reachable attack path found. Exit code `1` = vulnerable.

Example output on a vulnerable system:

```
=== DirtyFrag Vulnerability Detection (read-only) ===

  [..] Kernel : 6.17.0-1013-azure
  [..] OS     : Linux #13~24.04.1-Ubuntu SMP Wed Apr 15 16:52:17 UTC 2026

--- Module state ---
  [!!]  esp4: not loaded but present on disk and NOT blacklisted
         config=m  on_disk=True  loaded=False  blacklisted=False
  [!!]  esp6: not loaded but present on disk and NOT blacklisted
         config=m  on_disk=True  loaded=False  blacklisted=False
  [!!]  rxrpc: not loaded but present on disk and NOT blacklisted
         config=m  on_disk=True  loaded=False  blacklisted=False

--- Unprivileged namespace restrictions (affects ESP variant) ---
  [!!]  kernel.unprivileged_userns_clone = 1
  [!!]  kernel.apparmor_restrict_unprivileged_userns = 1

--- Variant verdicts ---
  [BAD] ESP (xfrm) variant: REACHABLE (partially mitigated by AppArmor if aa_restrict=1)
  [BAD] RxRPC variant: REACHABLE — no special privilege required, any local user can trigger

--- Overall verdict ---
  VULNERABLE: At least one attack variant is reachable on this system.
  Apply the mitigation (blacklist esp4, esp6, rxrpc) or install a patched kernel.
```

## Mitigation

If your system does not use IPsec tunnels, ESP, or AFS/RxRPC, you can block all three modules immediately:

```bash
sudo tee /etc/modprobe.d/dirtyfrag-mitigation.conf <<'EOF'
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF
sudo update-initramfs -u -k all
```

> `install X /bin/false` is stronger than a plain `blacklist` entry — it blocks the module even when requested as a dependency by another module. No reboot is required for the change to take effect on future load attempts.

Re-run the script after applying the mitigation to verify all modules show `[OK]`.

## Limitations

This script checks **reachability**, not the presence of the actual bug in kernel source code. A fully patched kernel may still report `[!!]` if the modules are on disk and not blacklisted — always cross-reference with your distro's official security advisory once patches are released.

## References

- [V4bel/dirtyfrag — original PoC and write-up](https://github.com/V4bel/dirtyfrag)
- [CloudLinux — DirtyFrag mitigation and kernel update](https://blog.cloudlinux.com/dirty-frag-mitigation-and-kernel-update)
- [AlmaLinux — Dirty Frag vulnerability fix ready for testing](https://almalinux.org/blog/2026-05-07-dirty-frag/)
- [Phoronix — Dirty Frag Vulnerability Made Public Early](https://www.phoronix.com/news/Dirty-Frag-Linux)
- [The Hacker News — Linux Kernel Dirty Frag LPE](https://thehackernews.com/2026/05/linux-kernel-dirty-frag-lpe-exploit.html)
- [Red Hat — RHSB-2026-003 Dirty Frag](https://access.redhat.com/security/vulnerabilities/RHSB-2026-003)
