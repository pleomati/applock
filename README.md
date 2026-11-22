# AppLock

**AppLock** is a lightweight Linux daemon that requires a password before launching selected applications. It works by monitoring `/proc` and suspending processes (`SIGSTOP`) until authentication is provided. It was designed with environments like XFCE (Fedora, Xubuntu) in mind, but should work on any distribution with `systemd` and X11.

## ✨ Features

- **Protect selected applications** – every attempt to launch a protected program requires a password.
- **Authorization inheritance** – child processes (e.g. Firefox tabs) do not ask for a password again if the main process has already been authenticated.
- **Secure password storage** – PBKDF2-HMAC-SHA256 with a random salt (75,000 iterations).
- **Low CPU usage** – polls `/proc` every 0.5 s; typical usage is 2–3% CPU.
- **No new dependencies** – uses OpenSSL, which is already present on the system.
- **Simple configuration** – a plain-text list of protected applications.

## 🏗️ Architecture

The program consists of two parts:

1. **Daemon (`applock run`)** – runs as root, monitors `/proc`, detects protected processes and suspends them (`SIGSTOP`).
2. **UI Agent (`applock ui`)** – runs as the user in the graphical session, displays a Zenity password prompt, and returns the password to the daemon via a Unix socket.

Communication takes place over the `/var/run/applock.sock` socket (daemon ↔ agent) and `/run/user/1000/applock-ui.sock` (daemon → UI agent).

## 📦 Installation

### Requirements

- Any Linux distribution with `systemd` and X11.
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
git clone https://github.com/your-user/applock.git
cd applock
make clean && make
sudo make install
```

### Configuration

```bash
# Set the password
sudo applock set-secret

# Add a protected application (use the actual binary!)
sudo applock add /usr/lib64/firefox/firefox Firefox   # Fedora
# or on Ubuntu:
# sudo applock add /snap/bin/firefox Firefox

# Verify the list
sudo applock list
```

> **Note:** Firefox is a shell script. `readlink /proc/<pid>/exe` returns the actual binary, so you must add a path such as `/usr/lib64/firefox/firefox` (Fedora) or `/usr/lib/firefox/firefox` (Ubuntu). Check with: `readlink -f /usr/bin/firefox`.

### Running

1. **Daemon** – as a systemd service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now applock.service
   ```

2. **UI Agent** – as an XFCE autostart entry:
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
   The agent will start automatically on the next login. You can also run it manually in an XFCE terminal:
   ```bash
   /usr/local/bin/applock ui
   ```

## ⚙️ Configuration

### `/etc/applock/config`

Format:
```
app = <path>|<name>
```

Example:
```
app = /usr/lib64/firefox/firefox|Firefox
app = /usr/lib64/chromium-browser/chromium-browser|Chromium
```

### systemd unit `/etc/systemd/system/applock.service`

```ini
[Unit]
Description=AppLock daemon
After=local-fs.target
Requires=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/applock run
Restart=on-failure
RestartSec=2
ProtectProc=default
ProcSubset=all

AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL

[Install]
WantedBy=multi-user.target
```

## 🛠️ Troubleshooting

### Daemon does not see user processes (`exe=(no access)`)

**Cause:** Missing `CAP_SYS_PTRACE`.  
**Fix:** Check `sudo systemctl show applock.service -p AmbientCapabilities` and make sure it contains `cap_sys_ptrace`. If not, fix the systemd unit and reload.

### Firefox starts without asking for a password

- Make sure the configuration contains the **actual binary** (`/usr/lib64/firefox/firefox` or `/usr/lib/firefox/firefox`), not the script `/usr/bin/firefox`.
- Remove stale markers: `sudo rm -f /tmp/.applock_ok_*` and restart the daemon.
- Check that the UI agent is running: `ps aux | grep 'applock ui'`.

### Zenity does not appear

- Check that the UI agent has `DISPLAY` and `XAUTHORITY`:
  ```bash
  cat /proc/$(pgrep -f 'applock ui' | head -1)/environ 2>/dev/null | tr '\0' '\n' | grep -E 'DISPLAY|XAUTHORITY'
  ```
- On Xubuntu 24.04 `XAUTHORITY` is usually `/home/<user>/.Xauthority`. On Fedora XFCE – `/run/lightdm/<user>/xauthority`.
- Start the agent within the XFCE session (autostart), not via `nohup` from another context.

### System freezes when launching an application

This is an issue with the `fanotify` version. The `/proc` polling version does **not block the kernel** – if you experience freezes, make sure you are using the correct version (log: `monitoring /proc every 500 ms`).

### AppLock does not ask for a password after reboot

- Check that the UI agent started automatically: `ps aux | grep 'applock ui'`.
- Make sure Firefox was not already running in the background (a new window does not create a new `execve`).
- Verify capabilities: `sudo systemctl show applock.service -p AmbientCapabilities`.

## 📋 Management

| Action | Command |
|---|---|
| Add an application | `sudo applock add <path> <name>` |
| Remove an application | edit `/etc/applock/config`, remove the line, `sudo systemctl restart applock.service` |
| Change password | `sudo applock set-secret` |
| List protected apps | `sudo applock list` |
| Stop protection | `sudo systemctl stop applock.service` + `pkill -f 'applock ui'` |
| Resume protection | `sudo systemctl start applock.service` + start the UI agent |
| Daemon logs | `sudo journalctl -u applock.service -f` |
| Agent logs | the terminal where `applock ui` was started |

## 🗑️ Uninstallation

```bash
sudo systemctl disable --now applock.service
pkill -f 'applock ui'
rm -f ~/.config/autostart/applock-ui.desktop
cd ~/applock && sudo make uninstall
sudo rm -rf /etc/applock
sudo rm -f /var/run/applock.sock /run/user/1000/applock-ui.sock
sudo rm -f /tmp/.applock_ok_* /tmp/applock-pass-*
sudo systemctl daemon-reload
```

## 🔐 Security

- **PBKDF2-HMAC-SHA256** with a random salt and 75,000 iterations – good protection against dictionary attacks.
- **The password is never stored in plaintext** – only the hash and salt in `/etc/applock/secret` (permissions `600`).
- **Limitations:** root can bypass AppLock (stop the daemon, remove the configuration). The program protects against unauthorized application launches by a regular user, not against an attacker with root privileges.

## 📄 License

This project is released under the MIT License. See the `LICENSE` file.

## 🤝 Contributing

Bug reports and feature requests are welcome. Open an issue or submit a pull request.

---

**AppLock** – a simple, lightweight, and effective way to password-protect selected applications on Linux.