# AppLock

**AppLock** is a lightweight Linux daemon that requires a password before launching selected applications. It supports two backends:

- **proc connector** (`cn_proc`) – receives `PROC_EVENT_EXEC` notifications from the kernel, suspends the target process with `SIGSTOP`, prompts for a password, and either resumes (`SIGCONT`) or kills (`SIGKILL`) the process.
- **fanotify** (`FAN_OPEN_EXEC_PERM`) – intercepts `execve()` **before** the process is created, prompts for a password, and responds with `FAN_ALLOW` or `FAN_DENY`. The process never starts unless authorized.

The daemon is designed for X11 sessions (XFCE, Xubuntu, Fedora XFCE) but should work on any distribution with `systemd`, kernel support for `proc connector` or `fanotify`, and a graphical session. Tested on Xubuntu 24.04, Fedora XFCE 43. Fedora KDE 45, ARCH Linux GNOME. 

---

## ✨ Features

- **Two backends** – choose `proc connector` (default) or `fanotify` in the configuration file.
- **Password protection** – every launch of a protected application requires a password.
- **Authorization inheritance** – child processes (e.g. Firefox tabs, LibreWolf content processes) do not prompt for a password if the main process has already been authenticated.
- **Secure password storage** – PBKDF2-HMAC-SHA256 with a random salt (75,000 iterations) and constant-time comparison (`CRYPTO_memcmp`).
- **Memory hygiene** – all secrets are cleared with `explicit_bzero()`.
- **Marker files** – stored in `/run/applock/` (tmpfs), cleared at daemon startup, and removed immediately on `PROC_EVENT_EXIT` (proc connector) or after a TTL (fanotify).
- **Hardened markers** – `O_NOFOLLOW` prevents symlink attacks.
- **Signal handling** – `SIGTERM`/`SIGINT` shut the daemon down cleanly.
- **No new dependencies** – uses OpenSSL, which is already present on the system.
- **Portable across UIDs** – the UI agent socket and D-Bus address are resolved dynamically from `XDG_RUNTIME_DIR` or `/run/user/<uid>/`, with the UID configurable via `ui_uid`.

---

## 🏗️ Architecture

AppLock consists of two parts:

1. **Daemon (`applock run`)** – runs as root, listens for execution events (via `proc connector` or `fanotify`), detects protected processes, and either prompts for a password or denies execution.
2. **UI Agent (`applock ui`)** – runs as the user in the graphical session, displays a Zenity password prompt, and returns the password to the daemon via a Unix socket.

Communication:
- Daemon ↔ UI Agent: `/run/user/<uid>/applock-ui.sock`
- Internal auth server: `/var/run/applock.sock`
- Markers: `/run/applock/.applock_{ok,pending}_<pid>`

### Backend comparison

| Feature | proc connector | fanotify |
|---|---|---|
| Detection moment | **after** `execve` (process exists, immediately suspended) | **before** `execve` (process never starts) |
| Mechanism | `SIGSTOP` + `SIGCONT` / `SIGKILL` | `FAN_ALLOW` / `FAN_DENY` |
| Deadlock risk | none | **low** (only specific files are marked, not `/`) |
| Required capabilities | `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_KILL` | `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_KILL` |
| Kernel config | `CONFIG_CONNECTOR`, `CONFIG_PROC_EVENTS` | `CONFIG_FANOTIFY`, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` |
| Netlink buffer | `SO_RCVBUF` = 1 MB, `ENOBUFS` handled | `FAN_Q_OVERFLOW` handled |

---

## 📦 Installation

### Requirements

- Linux distribution with `systemd`.
- Kernel with `CONFIG_CONNECTOR` and `CONFIG_PROC_EVENTS` (for proc connector) **or** `CONFIG_FANOTIFY` and `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` (for fanotify). Both are enabled by default in Fedora, Ubuntu, Debian, and Arch.
- `gcc`, `make`, `openssl-devel` (or `libssl-dev`), `zenity`.

**Fedora / RHEL:**
```bash
sudo dnf install gcc make openssl-devel zenity
```

**Ubuntu / Debian:**
```bash
sudo apt install gcc make libssl-dev zenity
```

**Arch Linux:**
```bash
sudo pacman -S gcc make openssl zenity
```

### Build and install

```bash
git clone https://github.com/pleomati/applock.git
cd applock
make clean && make
sudo make install
```

### Configure the password

```bash
sudo applock set-secret
```

### Add protected applications

Use the **actual binary path**, not a shell script wrapper. For example:

```bash
# Fedora
sudo applock add /usr/lib64/firefox/firefox Firefox-Real

# Ubuntu
sudo applock add /usr/lib/firefox/firefox Firefox-Real

# LibreWolf (both)
sudo applock add /usr/share/librewolf/librewolf LibreWolf
```

> **Why the actual binary?** `/usr/bin/firefox` is often a shell script. Both backends report the `execve` of the interpreter (`/usr/bin/bash`), not the script. The daemon reads `/proc/<pid>/exe`, which points to the actual binary. Always use the real binary path.

Check the list:

```bash
sudo applock list
```

Example output:

```
backend = proc
ui_uid = 1000
Firefox-Real -> /usr/lib64/firefox/firefox
LibreWolf -> /usr/share/librewolf/librewolf
```

### Select the backend

Edit `/etc/applock/config`:

```
backend = proc          # default; or: fanotify
ui_uid = 1000
app = /usr/lib64/firefox/firefox|Firefox-Real
app = /usr/share/librewolf/librewolf|LibreWolf
```

- `backend = proc` – uses proc connector (no `CAP_SYS_ADMIN` required).
- `backend = fanotify` – uses fanotify (requires `CAP_SYS_ADMIN`, process never starts without authorization).

### Optional: set the UI agent UID

If the UI agent runs under a UID other than 1000, add:

```
ui_uid = 1001
```

The daemon will use `/run/user/1001/applock-ui.sock` and `/run/user/1001/bus`. Invalid values are rejected and the default (`1000`) is used.

---

## ⚙️ systemd service

Create `/etc/systemd/system/applock.service`:

```ini
[Unit]
Description=AppLock daemon
After=local-fs.target
Requires=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/applock run
Restart=always
RestartSec=2
ProtectProc=default
ProcSubset=all

AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_KILL CAP_NET_ADMIN
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```
Reload and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now applock.service
sudo systemctl status applock.service
```

### UI agent autostart

Create `~/.config/autostart/applock-ui.desktop`:

```ini
[Desktop Entry]
Type=Application
Name=AppLock UI Agent
Exec=/usr/local/bin/applock ui
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
```

The agent starts automatically on the next login. You can also run it manually in an XFCE terminal:

```bash
/usr/local/bin/applock ui
```

---

## 🔧 Tuning

### Netlink buffer (proc connector)

`proc connector` uses a Netlink socket. Under heavy load, the kernel may report `ENOBUFS` (buffer overflow). The daemon:

- Sets `SO_RCVBUF` to **1 MB** (`NETLINK_RCVBUF` in the source).
- Handles `ENOBUFS` gracefully: logs a warning and continues.

If `ENOBUFS` still appears, increase the kernel limit:

```bash
cat /proc/sys/net/core/rmem_max
```

If it is below 4 MB, raise it:

```bash
sudo sysctl -w net.core.rmem_max=4194304
```

Persistent setting in `/etc/sysctl.d/99-applock.conf`:

```
net.core.rmem_max=4194304
```

### Fanotify queue overflow

Fanotify has an analogous limit (`FAN_Q_OVERFLOW`). The daemon logs a warning when it occurs. To reduce the risk, lower the number of marked files or increase kernel limits (`fs.fanotify_max_user_instances`, `fs.fanotify_max_user_marks`).

---

## 📋 Management

| Action | Command |
|---|---|
| Add an application | `sudo applock add <path> <name>` |
| Remove an application | edit `/etc/applock/config`, remove the line, `sudo systemctl restart applock.service` |
| Change password | `sudo applock set-secret` |
| List protected apps and backend | `sudo applock list` |
| Stop protection | `sudo systemctl stop applock.service` + `pkill -f 'applock ui'` |
| Resume protection | `sudo systemctl start applock.service` + start the UI agent |
| Daemon logs | `sudo journalctl -u applock.service -f` |
| Agent logs | the terminal where `applock ui` was started |

---

## 🛠️ Troubleshooting

### Daemon does not detect processes (`exe=(no access)`)

**Cause:** missing `CAP_SYS_PTRACE`.

**Fix:** verify capabilities:

```bash
sudo systemctl show applock.service -p AmbientCapabilities
```

It must contain `cap_sys_ptrace`. If not, fix `applock.service` and reload.

### `proc connector enabled` is missing from logs

**Cause:** missing `CAP_NET_ADMIN` or kernel lacks `CONFIG_CONNECTOR`/`CONFIG_PROC_EVENTS`.

**Fix:** add `CAP_NET_ADMIN` to `AmbientCapabilities`. Verify kernel support:

```bash
grep CONFIG_CONNECTOR /boot/config-$(uname -r)
grep CONFIG_PROC_EVENTS /boot/config-$(uname -r)
```

Both should be `=y` or `=m`.

### `fanotify_init: Operation not permitted`

**Cause:** missing `CAP_SYS_ADMIN` or kernel lacks `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`.

**Fix:** add `CAP_SYS_ADMIN` to `AmbientCapabilities`. Verify kernel support:

```bash
grep CONFIG_FANOTIFY /boot/config-$(uname -r)
grep CONFIG_FANOTIFY_ACCESS_PERMISSIONS /boot/config-$(uname -r)
```

### `ENOBUFS` in logs (proc connector)

**Cause:** Netlink receive buffer overflow.

**Fix:** increase `NETLINK_RCVBUF` in the source and `net.core.rmem_max` (see above). The daemon already handles `ENOBUFS` gracefully.

### `FAN_Q_OVERFLOW` in logs (fanotify)

**Cause:** fanotify queue overflow.

**Fix:** reduce the number of marked files or increase `fs.fanotify_max_user_marks`. The daemon logs a warning and continues.

### Firefox/LibreWolf starts without asking for a password

- Use the **actual binary path** in `applock add`, not the shell script.
- Remove stale markers: `sudo rm -f /run/applock/.applock_*` and restart the daemon.
- Check that the UI agent is running: `ps aux | grep 'applock ui'`.

### Zenity does not appear

- Check the UI agent environment:
  ```bash
  cat /proc/$(pgrep -f 'applock ui' | head -1)/environ 2>/dev/null | tr '\0' '\n' | grep -E 'DISPLAY|XAUTHORITY'
  ```
- On Xubuntu 24.04, `XAUTHORITY` is usually `/home/<user>/.Xauthority`. On Fedora XFCE, it is `/run/lightdm/<user>/xauthority`.
- Start the agent within the XFCE session (autostart), not via `nohup` from another context.

### Process stuck in `T` state after wrong password

The daemon resumes stopped processes with `SIGCONT` instead of killing them immediately. If a process remains in `T` state, the daemon will resume it in the next iteration. If the daemon is not running, resume manually:

```bash
kill -CONT <pid>
```

### Daemon does not ask for a password after reboot

- Check that the UI agent started automatically: `ps aux | grep 'applock ui'`.
- Make sure the protected application was not already running (a new window does not create a new `execve`).
- Verify capabilities: `sudo systemctl show applock.service -p AmbientCapabilities`.

### Daemon does not shut down cleanly

The daemon handles `SIGTERM`/`SIGINT` and logs `[applockd] shutting down`. If the service remains in `deactivating` state, check the logs:

```bash
sudo journalctl -u applock.service -n 20 --no-pager
```
---

### Wayland
AppLock itself is display-server agnostic.

The only X11-specific component is the current Zenity-based UI agent.

Fanotify and proc connector work identically on X11 and Wayland.

Running the UI agent through systemd --user is recommended.

---

## 🗑️ Uninstallation

```bash
sudo systemctl disable --now applock.service
pkill -f 'applock ui'
rm -f ~/.config/autostart/applock-ui.desktop
cd ~/applock && sudo make uninstall
sudo rm -rf /etc/applock /run/applock
sudo rm -f /var/run/applock.sock /run/user/1000/applock-ui.sock
sudo systemctl daemon-reload
```

---

## 🔐 Security

- **PBKDF2-HMAC-SHA256** with a random salt and 75,000 iterations – good protection against dictionary attacks.
- **Constant-time comparison** (`CRYPTO_memcmp`) – resistant to timing attacks.
- **`explicit_bzero()`** – all secrets are cleared from memory after use, immune to compiler optimizations.
- **The password is never stored in plaintext** – only the hash and salt in `/etc/applock/secret` (permissions `600`).
- **Markers in `/run/applock/`** – `tmpfs`, disappear on reboot, only root can write there.
- **`O_NOFOLLOW` on markers** – prevents symlink attacks.
- **`FAN_DENY` on error** (fanotify) – fail-closed by default; the process never starts if the executable path cannot be resolved.
- **Limitations:** root can bypass AppLock (stop the daemon, remove the configuration). The program protects against unauthorized application launches by a regular user, not against an attacker with root privileges.

---

## 📄 License

This project is released under the MIT License. See the `LICENSE` file.

---

## 🤝 Contributing

Bug reports and feature requests are welcome. Open an issue or submit a pull request.

---

**AppLock** – password-based application protection on Linux using `proc connector` or `fanotify`.
