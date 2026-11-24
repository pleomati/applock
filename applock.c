#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <poll.h>
#include <limits.h>
#include <termios.h>
#include <pwd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* ============================================================================
 * CONSTANTS AND PATHS
 * ============================================================================ */

#define SOCK_PATH     "/var/run/applock.sock"
#define CONF_PATH     "/etc/applock/config"
#define SECRET_PATH   "/etc/applock/secret"
#define MARKER_DIR    "/run/applock"
#define MAX_APPS      64
#define MAX_PATH      512
#define SCAN_INTERVAL 500000   /* 0.5 seconds */
#define MARKER_TTL    60000       /* in seconds */
#define AUTH_TIMEOUT  30        /* in seconds timeout for UI agent */

/* ============================================================================
 * PBKDF2 PARAMETERS
 * ============================================================================ */

#define PBKDF2_ITERATIONS 75000
#define PBKDF2_SALT_LEN   16
#define PBKDF2_KEY_LEN    32

/* ============================================================================
 * GLOBAL CONFIGURATION
 * ============================================================================ */

/* UID of the user running the UI agent. Defaults to 1000. */
static uid_t g_ui_uid = 1000;

/* ============================================================================
 * PPID CACHE
 * ============================================================================ */

#define PPID_CACHE_SIZE 512

typedef struct {
    pid_t pid;
    pid_t ppid;
} PpidCacheEntry;

static PpidCacheEntry g_ppid_cache[PPID_CACHE_SIZE];

static void ppid_cache_clear(void) {
    memset(g_ppid_cache, 0, sizeof(g_ppid_cache));
}

static int ppid_cache_lookup(pid_t pid, pid_t *ppid) {
    unsigned int idx = ((unsigned int)pid) % PPID_CACHE_SIZE;
    for (int i = 0; i < PPID_CACHE_SIZE; i++) {
        unsigned int slot = (idx + i) % PPID_CACHE_SIZE;
        if (g_ppid_cache[slot].pid == pid) {
            *ppid = g_ppid_cache[slot].ppid;
            return 1;
        }
        if (g_ppid_cache[slot].pid == 0) return 0;
    }
    return 0;
}

static void ppid_cache_insert(pid_t pid, pid_t ppid) {
    unsigned int idx = ((unsigned int)pid) % PPID_CACHE_SIZE;
    for (int i = 0; i < PPID_CACHE_SIZE; i++) {
        unsigned int slot = (idx + i) % PPID_CACHE_SIZE;
        if (g_ppid_cache[slot].pid == 0 || g_ppid_cache[slot].pid == pid) {
            g_ppid_cache[slot].pid = pid;
            g_ppid_cache[slot].ppid = ppid;
            return;
        }
    }
}

/* ============================================================================
 * AUTH CACHE (PID -> authorized)
 * ============================================================================ */

#define AUTH_CACHE_SIZE 1024

typedef struct {
    pid_t pid;
    int authorized;
} AuthCacheEntry;

static AuthCacheEntry g_auth_cache[AUTH_CACHE_SIZE];

static void auth_cache_clear(void) {
    memset(g_auth_cache, 0, sizeof(g_auth_cache));
}

static int auth_cache_lookup(pid_t pid, int *authorized) {
    unsigned int idx = ((unsigned int)pid) % AUTH_CACHE_SIZE;
    for (int i = 0; i < AUTH_CACHE_SIZE; i++) {
        unsigned int slot = (idx + i) % AUTH_CACHE_SIZE;
        if (g_auth_cache[slot].pid == pid) {
            *authorized = g_auth_cache[slot].authorized;
            return 1;
        }
        if (g_auth_cache[slot].pid == 0) return 0;
    }
    return 0;
}

static void auth_cache_insert(pid_t pid, int authorized) {
    unsigned int idx = ((unsigned int)pid) % AUTH_CACHE_SIZE;
    for (int i = 0; i < AUTH_CACHE_SIZE; i++) {
        unsigned int slot = (idx + i) % AUTH_CACHE_SIZE;
        if (g_auth_cache[slot].pid == 0 || g_auth_cache[slot].pid == pid) {
            g_auth_cache[slot].pid = pid;
            g_auth_cache[slot].authorized = authorized;
            return;
        }
    }
}

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

typedef struct {
    char path[MAX_PATH];
    char name[128];
} AppEntry;

static AppEntry g_apps[MAX_APPS];
static int g_app_count = 0;

/* ============================================================================
 * PATH RESOLUTION (portable across UIDs)
 * ============================================================================ */

/*
 * Returns the path to the UI agent socket.
 *
 * Priority:
 *   1. XDG_RUNTIME_DIR (if set) -> $XDG_RUNTIME_DIR/applock-ui.sock
 *   2. /run/user/<uid>/applock-ui.sock
 *
 * The 'uid' argument is the UID of the user running the UI agent.
 * When called from the daemon (root), it must be the UID from config,
 * not getuid() (which would return 0).
 */
static void get_ui_socket_path(char *path, size_t size, uid_t uid) {
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    if (runtime && *runtime) {
        snprintf(path, size, "%s/applock-ui.sock", runtime);
        return;
    }
    snprintf(path, size, "/run/user/%u/applock-ui.sock", (unsigned)uid);
}

/*
 * Returns the path to the D-Bus session bus for the given UID.
 * Uses XDG_RUNTIME_DIR if available, otherwise /run/user/<uid>/bus.
 */
static void get_dbus_address(char *out, size_t size, uid_t uid) {
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    if (runtime && *runtime) {
        snprintf(out, size, "unix:path=%s/bus", runtime);
        return;
    }
    snprintf(out, size, "unix:path=/run/user/%u/bus", (unsigned)uid);
}

/* ============================================================================
 * CONFIGURATION LOADING
 * ============================================================================ */

/*
 * Loads the configuration file. In addition to 'app' entries, it also
 * recognizes an optional 'ui_uid' key, which specifies the UID of the
 * user running the UI agent. Default: 1000.
 *
 * Example:
 *   ui_uid = 1000
 *   app = /usr/lib64/firefox/firefox|Firefox
 */
static int load_config(void) {
    FILE *f = fopen(CONF_PATH, "r");
    if (!f) { perror("[load_config] fopen"); return -1; }

    char line[1024];
    g_app_count = 0;
    g_ui_uid = 1000;  /* default */

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '#' || line[0] == 0) continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;

        char *k = line, *v = eq + 1;
        while (*k == ' ') k++;
        while (*v == ' ') v++;

        char *kend = k + strlen(k);
        while (kend > k && (kend[-1] == ' ' || kend[-1] == '\t')) *--kend = 0;

        char *vend = v + strlen(v);
        while (vend > v && (vend[-1] == ' ' || vend[-1] == '\t')) *--vend = 0;

        if (strcmp(k, "ui_uid") == 0) {
            g_ui_uid = (uid_t)atoi(v);
        } else if (strcmp(k, "app") == 0 && g_app_count < MAX_APPS) {
            char *pipe = strchr(v, '|');
            if (pipe) {
                *pipe = 0;
                snprintf(g_apps[g_app_count].path, MAX_PATH, "%s", v);
                snprintf(g_apps[g_app_count].name, 128, "%s", pipe + 1);
                g_app_count++;
            }
        }
    }
    fclose(f);
    return g_app_count;
}

static int is_protected(const char *exe) {
    for (int i = 0; i < g_app_count; i++)
        if (strcmp(g_apps[i].path, exe) == 0) return i;
    return -1;
}

/* ============================================================================
 * PASSWORD HASHING (PBKDF2-HMAC-SHA256)
 * ============================================================================ */

static void pbkdf2_hex(const char *password, const unsigned char *salt,
                       size_t salt_len, char out_hex[PBKDF2_KEY_LEN * 2 + 1]) {
    unsigned char derived[PBKDF2_KEY_LEN];

    PKCS5_PBKDF2_HMAC(password, strlen(password),
                      salt, salt_len,
                      PBKDF2_ITERATIONS, EVP_sha256(),
                      PBKDF2_KEY_LEN, derived);

    for (int i = 0; i < PBKDF2_KEY_LEN; i++)
        sprintf(out_hex + i * 2, "%02x", derived[i]);
    out_hex[PBKDF2_KEY_LEN * 2] = 0;

    memset(derived, 0, sizeof(derived));
}

static int verify_password(const char *input) {
    FILE *f = fopen(SECRET_PATH, "r");
    if (!f) return 0;

    char line[256] = {0};
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    fclose(f);
    line[strcspn(line, "\n")] = 0;

    char *colon = strchr(line, ':');
    if (!colon) return 0;
    *colon = 0;

    const char *salt_hex = line;
    const char *stored_hash_hex = colon + 1;

    unsigned char salt[PBKDF2_SALT_LEN];
    if (strlen(salt_hex) != PBKDF2_SALT_LEN * 2) return 0;
    for (int i = 0; i < PBKDF2_SALT_LEN; i++) {
        unsigned int byte;
        if (sscanf(salt_hex + i * 2, "%2x", &byte) != 1) return 0;
        salt[i] = (unsigned char)byte;
    }

    char calc_hex[PBKDF2_KEY_LEN * 2 + 1];
    pbkdf2_hex(input, salt, PBKDF2_SALT_LEN, calc_hex);

    int result = (CRYPTO_memcmp(calc_hex, stored_hash_hex,
                                PBKDF2_KEY_LEN * 2) == 0);

    memset(calc_hex, 0, sizeof(calc_hex));
    memset(salt, 0, sizeof(salt));
    return result;
}

static int read_password(char *buf, size_t len) {
    struct termios old, new;
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);
    char *r = fgets(buf, len, stdin);
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    if (r) buf[strcspn(buf, "\n")] = 0;
    return r != NULL;
}

/* ============================================================================
 * DAEMON <-> UI AGENT COMMUNICATION
 * ============================================================================ */

static int ask_via_ui_agent(const char *name, char *out, size_t len) {
    char ui_sock[256];
    get_ui_socket_path(ui_sock, sizeof(ui_sock), g_ui_uid);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", ui_sock);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 0;
    }

    char req[256];
    snprintf(req, sizeof(req), "AUTH %s\n", name);
    ssize_t w = write(fd, req, strlen(req));
    if (w < 0) { close(fd); return 0; }

    struct timeval tv = { .tv_sec = AUTH_TIMEOUT, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return 0; }
    char *r = fgets(out, len, f);
    fclose(f);

    if (r) {
        out[strcspn(r, "\n")] = 0;
        return 1;
    }
    return 0;
}

/* ============================================================================
 * MARKER FILES (in /run/applock/)
 * ============================================================================ */

static void marker_path(pid_t pid, const char *type, char *out, size_t len) {
    snprintf(out, len, "%s/.applock_%s_%d", MARKER_DIR, type, pid);
}

static int already_handled(pid_t pid) {
    char marker[256];
    marker_path(pid, "ok", marker, sizeof(marker));

    struct stat st;
    if (stat(marker, &st) != 0) return 0;

    if (time(NULL) - st.st_mtime > MARKER_TTL) {
        unlink(marker);
        return 0;
    }
    return 1;
}

static void mark_handled(pid_t pid) {
    char marker[256];
    marker_path(pid, "ok", marker, sizeof(marker));
    int fd = open(marker, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}

static int is_pending(pid_t pid) {
    char marker[256];
    marker_path(pid, "pending", marker, sizeof(marker));
    return access(marker, F_OK) == 0;
}

static void mark_pending(pid_t pid) {
    char marker[256];
    marker_path(pid, "pending", marker, sizeof(marker));
    int fd = open(marker, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}

static void unmark_pending(pid_t pid) {
    char marker[256];
    marker_path(pid, "pending", marker, sizeof(marker));
    unlink(marker);
}

static void clear_all_markers(void) {
    DIR *d = opendir(MARKER_DIR);
    if (!d) return;

    struct dirent *de;
    int count = 0;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, ".applock_", 9) != 0) continue;
        char full[256];
        snprintf(full, sizeof(full), "%s/%s", MARKER_DIR, de->d_name);
        if (unlink(full) == 0) count++;
    }
    closedir(d);
    fprintf(stderr, "[applockd] removed %d stale markers\n", count);
}

/* ============================================================================
 * PROCESS TREE INSPECTION (with PPID and AUTH caches)
 * ============================================================================ */

static pid_t get_ppid(pid_t pid) {
    pid_t cached;
    if (ppid_cache_lookup(pid, &cached)) return cached;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) { ppid_cache_insert(pid, -1); return -1; }

    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        ppid_cache_insert(pid, -1);
        return -1;
    }
    fclose(f);

    char *p = strrchr(buf, ')');
    if (!p) { ppid_cache_insert(pid, -1); return -1; }
    p += 2;

    char state;
    pid_t ppid;
    if (sscanf(p, "%c %d", &state, &ppid) == 2) {
        ppid_cache_insert(pid, ppid);
        return ppid;
    }

    ppid_cache_insert(pid, -1);
    return -1;
}

static int is_ancestor_authorized(pid_t pid) {
    int cached;
    if (auth_cache_lookup(pid, &cached)) return cached;

    pid_t current = pid;
    pid_t path[20];
    int path_len = 0;
    int result = 0;

    while (current > 1 && path_len < 20) {
        if (auth_cache_lookup(current, &cached)) {
            result = cached;
            break;
        }

        path[path_len++] = current;

        if (already_handled(current)) {
            result = 1;
            break;
        }

        current = get_ppid(current);
        if (current <= 0) break;
    }

    for (int i = 0; i < path_len; i++)
        auth_cache_insert(path[i], result);

    return result;
}

/* ============================================================================
 * PROCESS STATE INSPECTION
 * ============================================================================ */

static int is_process_stopped(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);

    char *p = strrchr(buf, ')');
    if (!p) return 0;
    p += 2;

    char state;
    if (sscanf(p, "%c", &state) == 1) return (state == 'T');
    return 0;
}

/* ============================================================================
 * MAIN DAEMON LOOP
 * ============================================================================ */

static void daemon_loop(void) {
    char ui_sock_dbg[256];
    get_ui_socket_path(ui_sock_dbg, sizeof(ui_sock_dbg), g_ui_uid);

    fprintf(stderr, "[applockd] monitoring /proc every %d ms, "
            "%d protected applications\n", SCAN_INTERVAL / 1000, g_app_count);
    fprintf(stderr, "[applockd] UI socket: %s (ui_uid=%u)\n",
            ui_sock_dbg, (unsigned)g_ui_uid);

    for (int i = 0; i < g_app_count; i++)
        fprintf(stderr, "[applockd] protected path #%d: '%s' (name: %s)\n",
                i, g_apps[i].path, g_apps[i].name);

    mkdir(MARKER_DIR, 0700);
    clear_all_markers();

    while (1) {
        ppid_cache_clear();
        auth_cache_clear();

        DIR *d = opendir("/proc");
        if (!d) { perror("opendir /proc"); sleep(1); continue; }

        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            pid_t pid = atoi(de->d_name);
            if (pid <= 1) continue;

            char exe[MAX_PATH];
            char link[64];
            snprintf(link, sizeof(link), "/proc/%d/exe", pid);
            ssize_t n = readlink(link, exe, sizeof(exe) - 1);
            if (n <= 0) continue;
            exe[n] = 0;

            int idx = is_protected(exe);
            if (idx < 0) continue;

            if (is_pending(pid)) continue;

            if (is_ancestor_authorized(pid)) {
                mark_handled(pid);
                continue;
            }

            if (is_process_stopped(pid)) {
                fprintf(stderr,
                        "[applockd] process %d stopped without authorization — resuming\n",
                        pid);
                kill(pid, SIGCONT);
                continue;
            }

            fprintf(stderr, "[applockd] detected %s (pid %d)\n",
                    g_apps[idx].name, pid);

            mark_pending(pid);

            if (kill(pid, SIGSTOP) < 0) {
                perror("kill SIGSTOP");
                unmark_pending(pid);
                continue;
            }

            char pass[256] = {0};
            int ok = 0;
            if (ask_via_ui_agent(g_apps[idx].name, pass, sizeof(pass)) &&
                verify_password(pass)) {
                ok = 1;
                fprintf(stderr, "[applockd] authorization OK\n");
            } else {
                fprintf(stderr, "[applockd] authorization DENIED\n");
            }
            memset(pass, 0, sizeof(pass));

            unmark_pending(pid);

            if (ok) {
                mark_handled(pid);
                kill(pid, SIGCONT);
                auth_cache_insert(pid, 1);
            } else {
                kill(pid, SIGCONT);
                usleep(100000);
                kill(pid, SIGKILL);
                fprintf(stderr, "[applockd] killed %s (pid %d)\n", exe, pid);
            }
        }
        closedir(d);

        /* Remove marker files for PIDs that no longer exist */
        DIR *t = opendir(MARKER_DIR);
        if (t) {
            struct dirent *te;
            while ((te = readdir(t))) {
                pid_t p = 0;
                if (sscanf(te->d_name, ".applock_ok_%d", &p) != 1 &&
                    sscanf(te->d_name, ".applock_pending_%d", &p) != 1)
                    continue;
                if (p <= 0) continue;
                char chk[64];
                snprintf(chk, sizeof(chk), "/proc/%d", p);
                if (access(chk, F_OK) != 0) {
                    char full[256];
                    snprintf(full, sizeof(full), "%s/%s", MARKER_DIR, te->d_name);
                    unlink(full);
                }
            }
            closedir(t);
        }

        usleep(SCAN_INTERVAL);
    }
}

/* ============================================================================
 * AUTHENTICATION SERVER
 * ============================================================================ */

static void auth_server(void) {
    unlink(SOCK_PATH);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCK_PATH);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }

    chmod(SOCK_PATH, 0600);
    listen(srv, 8);
    fprintf(stderr, "[applockd] listening on %s\n", SOCK_PATH);

    while (1) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;

        char buf[512] = {0};
        ssize_t r = read(c, buf, sizeof(buf) - 1);
        if (r <= 0) { close(c); continue; }

        int pid; char name[128];
        if (sscanf(buf, "AUTH %d %127s", &pid, name) == 2) {
            char pass[256] = {0};
            fprintf(stderr,
                    "\n[applockd] application '%s' (pid %d) waiting for password:\n",
                    name, pid);

            if (ask_via_ui_agent(name, pass, sizeof(pass)) &&
                verify_password(pass)) {
                if (write(c, "OK\n", 3) < 0) perror("write OK");
                fprintf(stderr, "[applockd] authorization OK\n");
            } else {
                if (write(c, "FAIL\n", 5) < 0) perror("write FAIL");
                fprintf(stderr, "[applockd] authorization DENIED\n");
            }
            memset(pass, 0, sizeof(pass));
        }
        close(c);
    }
}

/* ============================================================================
 * UI AGENT: ZENITY PASSWORD PROMPT
 * ============================================================================ */

static int run_zenity_password(const char *title, char *out, size_t len) {
    char tmpfile[] = "/tmp/applock-pass-XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) { perror("mkstemp"); return 0; }
    close(fd);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        unlink(tmpfile);
        return 0;
    }

    if (pid == 0) {
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }

        int outfd = open(tmpfile, O_WRONLY | O_TRUNC);
        if (outfd >= 0) { dup2(outfd, STDOUT_FILENO); close(outfd); }

        int errfd = open("/dev/null", O_WRONLY);
        if (errfd >= 0) { dup2(errfd, STDERR_FILENO); close(errfd); }

        const char *disp = getenv("DISPLAY");
        const char *xauth = getenv("XAUTHORITY");
        const char *dbus = getenv("DBUS_SESSION_BUS_ADDRESS");

        /* Only override DISPLAY if it's not already set */
        if (!disp || !*disp) setenv("DISPLAY", ":0.0", 1);

        /* Only override XAUTHORITY if it's not already set */
        if (!xauth || !*xauth) {
            const char *home = getenv("HOME");
            if (home && *home) {
                char xauth_path[512];
                snprintf(xauth_path, sizeof(xauth_path), "%s/.Xauthority", home);
                setenv("XAUTHORITY", xauth_path, 1);
            }
        }

        /* Only override DBUS if it's not already set */
        if (!dbus || !*dbus) {
            char dbus_addr[256];
            get_dbus_address(dbus_addr, sizeof(dbus_addr), getuid());
            setenv("DBUS_SESSION_BUS_ADDRESS", dbus_addr, 1);
        }

        setenv("GTK_USE_PORTAL", "0", 1);

        execl("/usr/bin/zenity", "zenity",
              "--password", "--title", title, (char *)NULL);
        perror("[zenity-child] execl");
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        unlink(tmpfile);
        return 0;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        unlink(tmpfile);
        return 0;
    }

    FILE *f = fopen(tmpfile, "r");
    if (!f) { unlink(tmpfile); return 0; }
    char *r = fgets(out, len, f);
    fclose(f);
    unlink(tmpfile);

    if (r) {
        out[strcspn(r, "\n")] = 0;
        return 1;
    }
    return 0;
}

static void ui_agent_loop(void) {
    char sockpath[256];
    get_ui_socket_path(sockpath, sizeof(sockpath), getuid());

    unlink(sockpath);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind ui"); exit(1);
    }

    chmod(sockpath, 0600);
    listen(srv, 8);
    fprintf(stderr, "[applock-ui] listening on %s\n", sockpath);
    fprintf(stderr, "[applock-ui] DISPLAY=%s XAUTHORITY=%s\n",
            getenv("DISPLAY") ? getenv("DISPLAY") : "(null)",
            getenv("XAUTHORITY") ? getenv("XAUTHORITY") : "(null)");
    fprintf(stderr, "[applock-ui] uid=%u\n", (unsigned)getuid());

    while (1) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;

        char buf[512] = {0};
        ssize_t r = read(c, buf, sizeof(buf) - 1);
        if (r <= 0) { close(c); continue; }

        char name[128] = {0};
        if (sscanf(buf, "AUTH %127s", name) == 1) {
            char title[256];
            char pass[256] = {0};
            snprintf(title, sizeof(title), "AppLock — %s", name);

            int ok = run_zenity_password(title, pass, sizeof(pass));
            if (ok) {
                if (write(c, pass, strlen(pass)) < 0) perror("write pass");
                if (write(c, "\n", 1) < 0) perror("write nl");
            } else {
                if (write(c, "FAIL\n", 5) < 0) perror("write FAIL");
            }
            memset(pass, 0, sizeof(pass));
        }
        close(c);
    }
}

/* ============================================================================
 * COMMAND-LINE CLIENT
 * ============================================================================ */

static int cmd_set_secret(void) {
    char p1[256], p2[256];
    printf("New password: ");
    fflush(stdout);
    if (!read_password(p1, sizeof(p1))) return 1;

    printf("Repeat password: ");
    fflush(stdout);
    if (!read_password(p2, sizeof(p2))) return 1;

    if (strcmp(p1, p2) != 0) {
        fprintf(stderr, "Passwords do not match.\n");
        memset(p1, 0, sizeof(p1));
        memset(p2, 0, sizeof(p2));
        return 1;
    }

    unsigned char salt[PBKDF2_SALT_LEN];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Failed to generate salt.\n");
        memset(p1, 0, sizeof(p1));
        memset(p2, 0, sizeof(p2));
        return 1;
    }

    char hash_hex[PBKDF2_KEY_LEN * 2 + 1];
    pbkdf2_hex(p1, salt, sizeof(salt), hash_hex);

    memset(p1, 0, sizeof(p1));
    memset(p2, 0, sizeof(p2));

    mkdir("/etc/applock", 0700);
    FILE *f = fopen(SECRET_PATH, "w");
    if (!f) { perror("secret"); return 1; }

    for (int i = 0; i < PBKDF2_SALT_LEN; i++)
        fprintf(f, "%02x", salt[i]);
    fprintf(f, ":");
    fprintf(f, "%s\n", hash_hex);
    fclose(f);
    chmod(SECRET_PATH, 0600);

    memset(hash_hex, 0, sizeof(hash_hex));
    memset(salt, 0, sizeof(salt));

    printf("Password set.\n");
    return 0;
}

static int cmd_add_app(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: applock add <path> <name>\n");
        return 1;
    }

    if (access(argv[2], X_OK) != 0) { perror(argv[2]); return 1; }

    mkdir("/etc/applock", 0700);
    FILE *f = fopen(CONF_PATH, "a");
    if (!f) { perror(CONF_PATH); return 1; }

    fprintf(f, "app = %s|%s\n", argv[2], argv[3]);
    fclose(f);

    printf("Added: %s (%s)\n", argv[3], argv[2]);
    return 0;
}

static int cmd_list(void) {
    if (load_config() <= 0) {
        printf("No protected applications.\n");
        return 0;
    }
    printf("ui_uid = %u\n", (unsigned)g_ui_uid);
    for (int i = 0; i < g_app_count; i++)
        printf("%s -> %s\n", g_apps[i].name, g_apps[i].path);
    return 0;
}

static int cmd_run(void) {
    if (load_config() <= 0) {
        fprintf(stderr, "No protected applications in %s\n", CONF_PATH);
        return 1;
    }

    if (fork() == 0) {
        auth_server();
        _exit(0);
    }

    daemon_loop();
    return 0;
}

static int cmd_ui(void) {
    ui_agent_loop();
    return 0;
}

static void usage(void) {
    printf("Usage: applock <command>\n"
           "  set-secret            set the authentication password\n"
           "  add <path> <name>     add an application to protect\n"
           "  list                  list protected applications\n"
           "  run                   start the daemon (/proc monitor, as root)\n"
           "  ui                    start the UI agent (Zenity, as user)\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }

    if (strcmp(argv[1], "set-secret") == 0) return cmd_set_secret();
    if (strcmp(argv[1], "add") == 0)        return cmd_add_app(argc, argv);
    if (strcmp(argv[1], "list") == 0)       return cmd_list();
    if (strcmp(argv[1], "run") == 0)        return cmd_run();
    if (strcmp(argv[1], "ui") == 0)         return cmd_ui();

    usage();
    return 1
