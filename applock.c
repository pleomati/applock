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

/* ============================================================================
 * CONSTANTS AND PATHS
 * ============================================================================ */

/* Unix socket path used by the daemon to listen for authentication requests */
#define SOCK_PATH     "/var/run/applock.sock"

/* Unix socket path used by the UI agent to listen for password prompts */
#define UI_SOCK_PATH  "/run/user/1000/applock-ui.sock"

/* Path to the configuration file listing protected applications */
#define CONF_PATH     "/etc/applock/config"

/* Path to the file storing the password hash and salt */
#define SECRET_PATH   "/etc/applock/secret"

/* Maximum number of protected applications that can be configured */
#define MAX_APPS      64

/* Maximum length of a file path */
#define MAX_PATH      512

/* How often the daemon scans /proc for new processes (in microseconds) */
#define SCAN_INTERVAL 500000   /* 0.5 seconds */

/* How long a marker file remains valid before it expires (in seconds) */
#define MARKER_TTL    60000    /* 60 seconds */

/* ============================================================================
 * PBKDF2 PARAMETERS
 * ============================================================================ */

/* Number of iterations for PBKDF2-HMAC-SHA256. Higher = more secure but slower. */
#define PBKDF2_ITERATIONS 75000

/* Length of the random salt in bytes */
#define PBKDF2_SALT_LEN   16

/* Length of the derived key (hash) in bytes */
#define PBKDF2_KEY_LEN    32

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/* Represents a single protected application entry from the config file */
typedef struct {
    char path[MAX_PATH];   /* Full path to the executable */
    char name[128];        /* Human-readable name shown in the password prompt */
} AppEntry;

/* Global array holding all protected applications loaded from config */
static AppEntry g_apps[MAX_APPS];

/* Number of protected applications currently loaded */
static int g_app_count = 0;

/* ============================================================================
 * CONFIGURATION LOADING
 * ============================================================================ */

/*
 * Loads the configuration file (CONF_PATH) into the global g_apps array.
 * Each line has the format:  app = /path/to/executable|Display Name
 * Lines starting with '#' or empty lines are ignored.
 *
 * Returns the number of applications loaded, or -1 on file open error.
 */
static int load_config(void) {
    FILE *f = fopen(CONF_PATH, "r");
    if (!f) { perror("[load_config] fopen"); return -1; }

    char line[1024];
    g_app_count = 0;

    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline */
        line[strcspn(line, "\n")] = 0;

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == 0) continue;

        /* Find the '=' separator */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;

        /* Extract key (left of '=') and value (right of '=') */
        char *k = line, *v = eq + 1;
        while (*k == ' ') k++;
        while (*v == ' ') v++;

        /* Trim trailing whitespace from key */
        char *kend = k + strlen(k);
        while (kend > k && (kend[-1] == ' ' || kend[-1] == '\t')) *--kend = 0;

        /* Trim trailing whitespace from value */
        char *vend = v + strlen(v);
        while (vend > v && (vend[-1] == ' ' || vend[-1] == '\t')) *--vend = 0;

        /* If the key is "app", parse the value as "path|name" */
        if (strcmp(k, "app") == 0 && g_app_count < MAX_APPS) {
            char *pipe = strchr(v, '|');
            if (pipe) {
                *pipe = 0;
                strncpy(g_apps[g_app_count].path, v, MAX_PATH - 1);
                strncpy(g_apps[g_app_count].name, pipe + 1, 127);
                g_app_count++;
            }
        }
    }
    fclose(f);
    return g_app_count;
}

/*
 * Checks whether the given executable path is in the protected list.
 * Returns the index in g_apps if found, or -1 if not protected.
 */
static int is_protected(const char *exe) {
    for (int i = 0; i < g_app_count; i++)
        if (strcmp(g_apps[i].path, exe) == 0) return i;
    return -1;
}

/* ============================================================================
 * PASSWORD HASHING (PBKDF2-HMAC-SHA256)
 * ============================================================================ */

/*
 * Derives a hex-encoded hash from the given password and salt using
 * PBKDF2-HMAC-SHA256 with PBKDF2_ITERATIONS iterations.
 *
 * The output buffer must be at least PBKDF2_KEY_LEN * 2 + 1 bytes.
 */
static void pbkdf2_hex(const char *password, const unsigned char *salt,
                       size_t salt_len, char out_hex[PBKDF2_KEY_LEN * 2 + 1]) {
    unsigned char derived[PBKDF2_KEY_LEN];

    /* Perform the PBKDF2 derivation */
    PKCS5_PBKDF2_HMAC(password, strlen(password),
                      salt, salt_len,
                      PBKDF2_ITERATIONS, EVP_sha256(),
                      PBKDF2_KEY_LEN, derived);

    /* Convert the binary hash to a hex string */
    for (int i = 0; i < PBKDF2_KEY_LEN; i++)
        sprintf(out_hex + i * 2, "%02x", derived[i]);
    out_hex[PBKDF2_KEY_LEN * 2] = 0;

    /* Clear the derived key from memory */
    memset(derived, 0, sizeof(derived));
}

/*
 * Verifies the given password against the stored hash in SECRET_PATH.
 * The file format is: <hex_salt>:<hex_hash>
 *
 * Returns 1 if the password is correct, 0 otherwise.
 */
static int verify_password(const char *input) {
    FILE *f = fopen(SECRET_PATH, "r");
    if (!f) return 0;

    char line[256] = {0};
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    fclose(f);
    line[strcspn(line, "\n")] = 0;

    /* Split into salt and hash at the ':' separator */
    char *colon = strchr(line, ':');
    if (!colon) return 0;
    *colon = 0;

    const char *salt_hex = line;
    const char *stored_hash_hex = colon + 1;

    /* Convert the hex salt back to binary */
    unsigned char salt[PBKDF2_SALT_LEN];
    if (strlen(salt_hex) != PBKDF2_SALT_LEN * 2) return 0;
    for (int i = 0; i < PBKDF2_SALT_LEN; i++) {
        unsigned int byte;
        if (sscanf(salt_hex + i * 2, "%2x", &byte) != 1) return 0;
        salt[i] = (unsigned char)byte;
    }

    /* Compute the hash of the input password using the same salt */
    char calc_hex[PBKDF2_KEY_LEN * 2 + 1];
    pbkdf2_hex(input, salt, PBKDF2_SALT_LEN, calc_hex);

    /* Compare the computed hash with the stored one */
    int result = (strcmp(calc_hex, stored_hash_hex) == 0);

    /* Clear sensitive data from memory */
    memset(calc_hex, 0, sizeof(calc_hex));
    memset(salt, 0, sizeof(salt));
    return result;
}

/*
 * Reads a password from the terminal without echoing it.
 * Returns 1 on success, 0 on failure.
 */
static int read_password(char *buf, size_t len) {
    struct termios old, new;
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;  /* Disable echo */
    tcsetattr(STDIN_FILENO, TCSANOW, &new);

    char *r = fgets(buf, len, stdin);

    tcsetattr(STDIN_FILENO, TCSANOW, &old);  /* Restore echo */
    if (r) buf[strcspn(buf, "\n")] = 0;
    return r != NULL;
}

/* ============================================================================
 * DAEMON <-> UI AGENT COMMUNICATION
 * ============================================================================ */

/*
 * Asks the UI agent to display a password prompt for the given application.
 * The agent's response is written into the 'out' buffer.
 *
 * Returns 1 if a password was received, 0 on error or timeout.
 */
static int ask_via_ui_agent(const char *name, char *out, size_t len) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, UI_SOCK_PATH, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 0;
    }

    /* Send the authentication request */
    char req[256];
    snprintf(req, sizeof(req), "AUTH %s\n", name);
    ssize_t w = write(fd, req, strlen(req));
    if (w < 0) { close(fd); return 0; }

    /* Set a 30-second timeout for the response */
    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Read the password from the agent */
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
 * MARKER FILES (for tracking already-authenticated processes)
 * ============================================================================ */

/*
 * Checks whether a marker file exists for the given PID and is still valid.
 * A marker file is considered stale after MARKER_TTL seconds and is removed.
 *
 * Returns 1 if the process has already been authenticated, 0 otherwise.
 */
static int already_handled(pid_t pid) {
    char marker[128];
    snprintf(marker, sizeof(marker), "/tmp/.applock_ok_%d", pid);

    struct stat st;
    if (stat(marker, &st) != 0) return 0;

    /* If the marker is too old, delete it and treat as not handled */
    if (time(NULL) - st.st_mtime > MARKER_TTL) {
        unlink(marker);
        return 0;
    }
    return 1;
}

/*
 * Creates a marker file for the given PID, indicating that this process
 * has been successfully authenticated and should not be prompted again.
 */
static void mark_handled(pid_t pid) {
    char marker[128];
    snprintf(marker, sizeof(marker), "/tmp/.applock_ok_%d", pid);
    int fd = open(marker, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}

/*
 * Removes all marker files from /tmp at daemon startup.
 * This prevents stale markers from a previous run from interfering.
 */
static void clear_all_markers(void) {
    DIR *d = opendir("/tmp");
    if (!d) return;

    struct dirent *de;
    int count = 0;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, ".applock_ok_", 12) != 0) continue;
        char full[256];
        snprintf(full, sizeof(full), "/tmp/%s", de->d_name);
        if (unlink(full) == 0) count++;
    }
    closedir(d);
    fprintf(stderr, "[applockd] removed %d stale markers\n", count);
}

/* ============================================================================
 * PROCESS TREE INSPECTION (authorization inheritance)
 * ============================================================================ */

/*
 * Reads the parent PID (PPID) of the given process from /proc/<pid>/stat.
 * Returns the PPID, or -1 on error.
 */
static pid_t get_ppid(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);

    /* Find the last ')' in the stat line, which terminates the process name.
     * The format after that is: <state> <ppid> ... */
    char *p = strrchr(buf, ')');
    if (!p) return -1;
    p += 2;

    char state;
    pid_t ppid;
    if (sscanf(p, "%c %d", &state, &ppid) == 2) return ppid;
    return -1;
}

/*
 * Checks whether the given process or any of its ancestors has a valid
 * marker file (i.e., has already been authenticated).
 *
 * This is how authorization inheritance works: if the main Firefox process
 * has been authenticated, all its child processes are automatically allowed
 * without prompting for a password again.
 *
 * Returns 1 if an ancestor is authorized, 0 otherwise.
 */
static int is_ancestor_authorized(pid_t pid) {
    pid_t current = pid;
    int depth = 0;

    /* Walk up the process tree (max 20 levels to prevent infinite loops) */
    while (current > 1 && depth < 20) {
        if (already_handled(current)) return 1;
        current = get_ppid(current);
        depth++;
    }
    return 0;
}

/* ============================================================================
 * PROCESS STATE INSPECTION
 * ============================================================================ */

/*
 * Checks whether the given process is in a stopped state ('T') according to
 * /proc/<pid>/stat. This is used to detect processes that were suspended by
 * the daemon in a previous iteration but never got authenticated.
 *
 * Returns 1 if the process is stopped, 0 otherwise.
 */
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

/*
 * The core monitoring loop. Periodically scans /proc for processes whose
 * executable matches a protected application. When such a process is found:
 *   1. If an ancestor is already authenticated, mark it and continue.
 *   2. If the process is already stopped (from a previous iteration) and
 *      still unauthorized, kill it immediately to avoid a 30-second hang.
 *   3. Otherwise, suspend it (SIGSTOP), ask the UI agent for a password,
 *      and either resume it (SIGCONT) on success or kill it (SIGKILL) on
 *      failure.
 */
static void daemon_loop(void) {
    fprintf(stderr, "[applockd] monitoring /proc every %d ms, "
            "%d protected applications\n", SCAN_INTERVAL / 1000, g_app_count);

    for (int i = 0; i < g_app_count; i++)
        fprintf(stderr, "[applockd] protected path #%d: '%s' (name: %s)\n",
                i, g_apps[i].path, g_apps[i].name);

    clear_all_markers();

    while (1) {
        DIR *d = opendir("/proc");
        if (!d) { perror("opendir /proc"); sleep(1); continue; }

        struct dirent *de;
        while ((de = readdir(d))) {
            /* Only numeric entries are PIDs */
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            pid_t pid = atoi(de->d_name);
            if (pid <= 1) continue;

            /* Read the actual executable path of the process */
            char exe[MAX_PATH];
            char link[64];
            snprintf(link, sizeof(link), "/proc/%d/exe", pid);
            ssize_t n = readlink(link, exe, sizeof(exe) - 1);
            if (n <= 0) continue;
            exe[n] = 0;

            /* Skip if this executable is not protected */
            int idx = is_protected(exe);
            if (idx < 0) continue;

            /* If the process or an ancestor is already authenticated, skip */
            if (is_ancestor_authorized(pid)) {
                mark_handled(pid);
                continue;
            }

            /*
             * If the process is already stopped (from a previous iteration)
             * and still unauthorized, kill it immediately. This prevents
             * processes from hanging for 30 seconds after a wrong password.
             */
            if (is_process_stopped(pid)) {
                fprintf(stderr, "[applockd] process %d stopped without "
                        "authorization — killing\n", pid);
                kill(pid, SIGKILL);
                mark_handled(pid);
                continue;
            }

            fprintf(stderr, "[applockd] detected %s (pid %d)\n",
                    g_apps[idx].name, pid);

            /* Suspend the process while we ask for the password */
            if (kill(pid, SIGSTOP) < 0) {
                perror("kill SIGSTOP");
                continue;
            }

            /* Ask the UI agent for a password */
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

            if (ok) {
                /* Mark as authenticated and resume the process */
                mark_handled(pid);
                kill(pid, SIGCONT);
            } else {
                /* Wrong password or timeout — kill the process */
                kill(pid, SIGKILL);
                mark_handled(pid);
                fprintf(stderr, "[applockd] killed %s (pid %d)\n", exe, pid);
            }
        }
        closedir(d);

        /* Remove marker files for PIDs that no longer exist */
        DIR *t = opendir("/tmp");
        if (t) {
            struct dirent *te;
            while ((te = readdir(t))) {
                if (strncmp(te->d_name, ".applock_ok_", 12) != 0) continue;
                pid_t p = atoi(te->d_name + 12);
                if (p <= 0) continue;
                char chk[64];
                snprintf(chk, sizeof(chk), "/proc/%d", p);
                if (access(chk, F_OK) != 0) {
                    char full[256];
                    snprintf(full, sizeof(full), "/tmp/%s", te->d_name);
                    unlink(full);
                }
            }
            closedir(t);
        }

        usleep(SCAN_INTERVAL);
    }
}

/* ============================================================================
 * AUTHENTICATION SERVER (used internally by the daemon)
 * ============================================================================ */

/*
 * A simple Unix socket server that listens on SOCK_PATH for authentication
 * requests from other parts of the system (e.g., the daemon's own monitoring
 * loop). It uses the same ask_via_ui_agent() and verify_password() helpers.
 */
static void auth_server(void) {
    unlink(SOCK_PATH);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
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

/*
 * Launches Zenity to ask the user for a password. The password is written
 * to a temporary file (to avoid it being visible in process arguments), and
 * then read back into 'out'.
 *
 * Returns 1 if a password was obtained, 0 otherwise.
 */
static int run_zenity_password(const char *title, char *out, size_t len) {
    /* Create a temporary file to hold the password */
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
        /* Child process: redirect standard streams and exec Zenity */

        /* Redirect stdin from /dev/null to prevent Zenity from blocking */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }

        /* Redirect stdout to the temporary file */
        int outfd = open(tmpfile, O_WRONLY | O_TRUNC);
        if (outfd >= 0) { dup2(outfd, STDOUT_FILENO); close(outfd); }

        /* Redirect stderr to /dev/null to suppress warnings */
        int errfd = open("/dev/null", O_WRONLY);
        if (errfd >= 0) { dup2(errfd, STDERR_FILENO); close(errfd); }

        /* Ensure the graphical environment is properly set */
        const char *disp = getenv("DISPLAY");
        const char *xauth = getenv("XAUTHORITY");
        const char *dbus = getenv("DBUS_SESSION_BUS_ADDRESS");
        setenv("DISPLAY", disp && *disp ? disp : ":0.0", 1);
        setenv("XAUTHORITY", xauth && *xauth ? xauth : "/home/ap/.Xauthority", 1);
        setenv("DBUS_SESSION_BUS_ADDRESS",
               dbus && *dbus ? dbus : "unix:path=/run/user/1000/bus", 1);
        setenv("GTK_USE_PORTAL", "0", 1);

        execl("/usr/bin/zenity", "zenity",
              "--password", "--title", title, (char *)NULL);
        perror("[zenity-child] execl");
        _exit(127);
    }

    /* Parent process: wait for Zenity to finish */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        unlink(tmpfile);
        return 0;
    }

    /* If Zenity exited with an error, clean up and return 0 */
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        unlink(tmpfile);
        return 0;
    }

    /* Read the password from the temporary file */
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

/*
 * The UI agent's main loop. Listens on a Unix socket (UI_SOCK_PATH) for
 * authentication requests from the daemon, and responds with the password
 * entered by the user via Zenity.
 */
static void ui_agent_loop(void) {
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    char sockpath[256];
    if (runtime && *runtime)
        snprintf(sockpath, sizeof(sockpath), "%s/applock-ui.sock", runtime);
    else
        snprintf(sockpath, sizeof(sockpath), "%s", UI_SOCK_PATH);

    unlink(sockpath);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind ui"); exit(1);
    }

    chmod(sockpath, 0600);
    listen(srv, 8);
    fprintf(stderr, "[applock-ui] listening on %s\n", sockpath);
    fprintf(stderr, "[applock-ui] DISPLAY=%s XAUTHORITY=%s\n",
            getenv("DISPLAY") ? getenv("DISPLAY") : "(null)",
            getenv("XAUTHORITY") ? getenv("XAUTHORITY") : "(null)");

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

/*
 * Implements the "set-secret" command: prompts the user for a new password,
 * generates a random salt, computes the PBKDF2 hash, and writes both to
 * SECRET_PATH in the format <hex_salt>:<hex_hash>.
 */
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

    /* Generate a random salt */
    unsigned char salt[PBKDF2_SALT_LEN];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Failed to generate salt.\n");
        memset(p1, 0, sizeof(p1));
        memset(p2, 0, sizeof(p2));
        return 1;
    }

    /* Compute the PBKDF2 hash */
    char hash_hex[PBKDF2_KEY_LEN * 2 + 1];
    pbkdf2_hex(p1, salt, sizeof(salt), hash_hex);

    /* Clear the plaintext passwords from memory */
    memset(p1, 0, sizeof(p1));
    memset(p2, 0, sizeof(p2));

    /* Write the salt and hash to the secret file */
    mkdir("/etc/applock", 0700);
    FILE *f = fopen(SECRET_PATH, "w");
    if (!f) { perror("secret"); return 1; }

    for (int i = 0; i < PBKDF2_SALT_LEN; i++)
        fprintf(f, "%02x", salt[i]);
    fprintf(f, ":");
    fprintf(f, "%s\n", hash_hex);
    fclose(f);
    chmod(SECRET_PATH, 0600);

    /* Clear sensitive data from memory */
    memset(hash_hex, 0, sizeof(hash_hex));
    memset(salt, 0, sizeof(salt));

    printf("Password set.\n");
    return 0;
}

/*
 * Implements the "add" command: appends a new protected application entry
 * to the configuration file.
 */
static int cmd_add_app(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: applock add <path> <name>\n");
        return 1;
    }

    /* Verify that the path exists and is executable */
    if (access(argv[2], X_OK) != 0) { perror(argv[2]); return 1; }

    mkdir("/etc/applock", 0700);
    FILE *f = fopen(CONF_PATH, "a");
    if (!f) { perror(CONF_PATH); return 1; }

    fprintf(f, "app = %s|%s\n", argv[2], argv[3]);
    fclose(f);

    printf("Added: %s (%s)\n", argv[3], argv[2]);
    return 0;
}

/*
 * Implements the "list" command: prints all protected applications.
 */
static int cmd_list(void) {
    if (load_config() <= 0) {
        printf("No protected applications.\n");
        return 0;
    }
    for (int i = 0; i < g_app_count; i++)
        printf("%s -> %s\n", g_apps[i].name, g_apps[i].path);
    return 0;
}

/*
 * Implements the "run" command: loads the config and starts both the
 * authentication server (in a child process) and the monitoring loop
 * (in the parent process).
 */
static int cmd_run(void) {
    if (load_config() <= 0) {
        fprintf(stderr, "No protected applications in %s\n", CONF_PATH);
        return 1;
    }

    /* Fork: child runs the auth server, parent runs the monitor loop */
    if (fork() == 0) {
        auth_server();
        _exit(0);
    }

    daemon_loop();
    return 0;
}

/*
 * Implements the "ui" command: starts the UI agent that displays Zenity
 * password prompts.
 */
static int cmd_ui(void) {
    ui_agent_loop();
    return 0;
}

/*
 * Prints usage information.
 */
static void usage(void) {
    printf("Usage: applock <command>\n"
           "  set-secret            set the authentication password\n"
           "  add <path> <name>     add an application to protect\n"
           "  list                  list protected applications\n"
           "  run                   start the daemon (/proc monitor, as root)\n"
           "  ui                    start the UI agent (Zenity, as user)\n");
}

/* ============================================================================
 * MAIN ENTRY POINT
 * ============================================================================ */

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }

    if (strcmp(argv[1], "set-secret") == 0) return cmd_set_secret();
    if (strcmp(argv[1], "add") == 0)        return cmd_add_app(argc, argv);
    if (strcmp(argv[1], "list") == 0)       return cmd_list();
    if (strcmp(argv[1], "run") == 0)        return cmd_run();
    if (strcmp(argv[1], "ui") == 0)         return cmd_ui();

    usage();
    return 1;
}
