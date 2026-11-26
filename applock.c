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

/* Proc connector headers */
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

/* Fanotify headers */
#include <sys/fanotify.h>

/* ============================================================================
 * CONSTANTS AND PATHS
 * ============================================================================ */

#define SOCK_PATH     "/var/run/applock.sock"
#define CONF_PATH     "/etc/applock/config"
#define SECRET_PATH   "/etc/applock/secret"
#define MARKER_DIR    "/run/applock"
#define MAX_APPS      64
#define MAX_PATH      512
#define MARKER_TTL    60000       /* seconds */
#define AUTH_TIMEOUT  30        /* seconds timeout for UI agent */
#define NETLINK_RCVBUF (1024 * 1024)  /* 1 MB receive buffer */

/* ============================================================================
 * PBKDF2 PARAMETERS
 * ============================================================================ */

#define PBKDF2_ITERATIONS 75000
#define PBKDF2_SALT_LEN   16
#define PBKDF2_KEY_LEN    32

/* ============================================================================
 * BACKEND SELECTION
 * ============================================================================ */

#define BACKEND_PROC      0
#define BACKEND_FANOTIFY  1

static int g_backend = BACKEND_PROC;

/* ============================================================================
 * GLOBAL CONFIGURATION
 * ============================================================================ */

static uid_t g_ui_uid = 1000;

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
 * PATH RESOLUTION
 * ============================================================================ */

static void get_ui_socket_path(char *path, size_t size, uid_t uid) {
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    if (runtime && *runtime) {
        snprintf(path, size, "%s/applock-ui.sock", runtime);
        return;
    }
    snprintf(path, size, "/run/user/%u/applock-ui.sock", (unsigned)uid);
}

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

static int load_config(void) {
    FILE *f = fopen(CONF_PATH, "r");
    if (!f) { perror("[load_config] fopen"); return -1; }

    char line[1024];
    g_app_count = 0;
    g_ui_uid = 1000;
    g_backend = BACKEND_PROC;

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

        if (strcmp(k, "backend") == 0) {
            if (strcmp(v, "fanotify") == 0) {
                g_backend = BACKEND_FANOTIFY;
            } else if (strcmp(v, "proc") == 0) {
                g_backend = BACKEND_PROC;
            } else {
                fprintf(stderr,
                        "[load_config] unknown backend '%s', using 'proc'\n", v);
                g_backend = BACKEND_PROC;
            }
        } else if (strcmp(k, "ui_uid") == 0) {
            char *endptr = NULL;
            errno = 0;
            unsigned long val = strtoul(v, &endptr, 10);

            if (errno != 0 || endptr == v || *endptr != '\0' || val > 65535) {
                fprintf(stderr,
                        "[load_config] invalid ui_uid '%s', using default 1000\n", v);
                g_ui_uid = 1000;
            } else {
                g_ui_uid = (uid_t)val;
            }
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
 * UNIFIED AUTHORIZATION
 * ============================================================================ */

/*
 * Prompts the user for a password and verifies it.
 * Returns 1 if the password is correct, 0 otherwise.
 *
 * This function is used by BOTH backends (proc connector and fanotify),
 * keeping the authentication logic in one place.
 */
static int authorize_application(const char *path, const char *name) {
    char pass[256] = {0};
    int ok = ask_via_ui_agent(name, pass, sizeof(pass)) &&
             verify_password(pass);

    /* Clear the password from memory regardless of the result */
    explicit_bzero(pass, sizeof(pass));

    if (ok)
        fprintf(stderr, "[applockd] authorization OK (%s)\n", path);
    else
        fprintf(stderr, "[applockd] authorization DENIED (%s)\n", path);

    return ok;
}

/* ============================================================================
 * MARKER FILES
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
 * PROCESS TREE INSPECTION (used by proc connector backend)
 * ============================================================================ */

static pid_t get_ppid(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char buf[1024];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);

    char *p = strrchr(buf, ')');
    if (!p) return -1;
    p += 2;

    char state;
    pid_t ppid;
    if (sscanf(p, "%c %d", &state, &ppid) == 2) return ppid;
    return -1;
}

static int is_ancestor_authorized(pid_t pid) {
    pid_t current = pid;
    int depth = 0;

    while (current > 1 && depth < 20) {
        if (already_handled(current)) return 1;
        current = get_ppid(current);
        if (current <= 0) break;
        depth++;
    }
    return 0;
}

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
 * BACKEND: PROC CONNECTOR
 * ============================================================================ */

static int cn_proc_open(void) {
    int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (fd < 0) {
        perror("[cn_proc] socket");
        return -1;
    }

    int rcvbuf = NETLINK_RCVBUF;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("[cn_proc] setsockopt SO_RCVBUF");
    }

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = CN_IDX_PROC,
        .nl_pid = getpid()
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[cn_proc] bind");
        close(fd);
        return -1;
    }

    char buf[NLMSG_SPACE(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op))];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    nh->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
    nh->nlmsg_type = NLMSG_DONE;
    nh->nlmsg_flags = 0;
    nh->nlmsg_seq = 0;
    nh->nlmsg_pid = getpid();

    struct cn_msg *cm = (struct cn_msg *)NLMSG_DATA(nh);
    cm->id.idx = CN_IDX_PROC;
    cm->id.val = CN_VAL_PROC;
    cm->seq = 0;
    cm->ack = 0;
    cm->len = sizeof(enum proc_cn_mcast_op);

    enum proc_cn_mcast_op *op = (enum proc_cn_mcast_op *)cm->data;
    *op = PROC_CN_MCAST_LISTEN;

    if (send(fd, nh, nh->nlmsg_len, 0) < 0) {
        perror("[cn_proc] send PROC_CN_MCAST_LISTEN");
        close(fd);
        return -1;
    }

    fprintf(stderr, "[applockd] proc connector enabled (rcvbuf=%d)\n", rcvbuf);
    return fd;
}

static void cn_proc_handle_exec(pid_t pid) {
    char exe[MAX_PATH];
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t n = readlink(link, exe, sizeof(exe) - 1);
    if (n <= 0) return;
    exe[n] = 0;

    int idx = is_protected(exe);
    if (idx < 0) return;

    if (is_pending(pid)) return;

    if (is_ancestor_authorized(pid)) {
        mark_handled(pid);
        return;
    }

    if (is_process_stopped(pid)) {
        fprintf(stderr,
                "[applockd] process %d stopped without authorization — resuming\n",
                pid);
        kill(pid, SIGCONT);
        return;
    }

    fprintf(stderr, "[applockd] detected %s (pid %d)\n",
            g_apps[idx].name, pid);

    mark_pending(pid);

    if (kill(pid, SIGSTOP) < 0) {
        perror("kill SIGSTOP");
        unmark_pending(pid);
        return;
    }

    int ok = authorize_application(exe, g_apps[idx].name);

    unmark_pending(pid);

    if (ok) {
        mark_handled(pid);
        kill(pid, SIGCONT);
    } else {
        kill(pid, SIGCONT);
        usleep(100000);
        kill(pid, SIGKILL);
        fprintf(stderr, "[applockd] killed %s (pid %d)\n", exe, pid);
    }
}

static void proc_backend_run(void) {
    int fd = cn_proc_open();
    if (fd < 0) {
        fprintf(stderr, "[applockd] failed to initialize proc connector\n");
        exit(1);
    }

    char buf[4096];
    unsigned long enobufs_count = 0;

    while (1) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                enobufs_count++;
                if (enobufs_count <= 5 || enobufs_count % 100 == 0) {
                    fprintf(stderr,
                            "[cn_proc] ENOBUFS (%lu occurrences) — some events lost, continuing\n",
                            enobufs_count);
                }
                continue;
            }
            perror("[cn_proc] recv");
            break;
        }
        if (len == 0) continue;

        struct nlmsghdr *nh;
        for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {

            if (nh->nlmsg_type != NLMSG_DONE) continue;

            struct cn_msg *cm = (struct cn_msg *)NLMSG_DATA(nh);
            if (cm->id.idx != CN_IDX_PROC || cm->id.val != CN_VAL_PROC) continue;

            struct proc_event *ev = (struct proc_event *)cm->data;

            if (ev->what == PROC_EVENT_EXEC) {
                pid_t pid = ev->event_data.exec.process_pid;
                cn_proc_handle_exec(pid);
            }
        }
    }

    close(fd);
}

/*
 * Fanotify backend.
 *
 * Key design decisions:
 *   - Uses FAN_CLASS_CONTENT + O_RDONLY (NOT O_RDWR, which causes ETXTBSY).
 *   - Marks ONLY the protected binaries (NOT the whole filesystem), which
 *     eliminates the risk of deadlock when Zenity loads shared libraries.
 *   - Uses authorize_application() for authentication.
 *   - Uses authorization inheritance: if an ancestor of the process has
 *     already been authorized (has a valid "ok" marker), the process is
 *     allowed without prompting.
 *   - Sends FAN_ALLOW / FAN_DENY to the kernel; the process is not started
 *     until the daemon responds.
 */
static void fan_backend_run(void) {
    int fanfd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, O_RDONLY);
    if (fanfd < 0) {
        perror("[fan] fanotify_init");
        fprintf(stderr, "[applockd] fanotify requires CAP_SYS_ADMIN\n");
        exit(1);
    }

    /* Mark ONLY the protected binaries — NOT the whole filesystem. */
    for (int i = 0; i < g_app_count; i++) {
        if (fanotify_mark(fanfd, FAN_MARK_ADD, FAN_OPEN_EXEC_PERM,
                          AT_FDCWD, g_apps[i].path) < 0) {
            fprintf(stderr, "[fan] fanotify_mark(%s): %s\n",
                    g_apps[i].path, strerror(errno));
        } else {
            fprintf(stderr, "[fan] monitoring: %s (name: %s)\n",
                    g_apps[i].path, g_apps[i].name);
        }
    }

    fprintf(stderr, "[applockd] fanotify backend active, %d markers\n",
            g_app_count);

    char buf[4096];
    while (1) {
        ssize_t len = read(fanfd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("[fan] read");
            break;
        }

        struct fanotify_event_metadata *meta = (void *)buf;
        while (FAN_EVENT_OK(meta, len)) {
            if (meta->fd >= 0) {
                char exe[MAX_PATH];
                char procfd[64];
                snprintf(procfd, sizeof(procfd), "/proc/self/fd/%d", meta->fd);
                ssize_t n = readlink(procfd, exe, sizeof(exe) - 1);

                struct fanotify_response resp;
                resp.fd = meta->fd;

                if (n > 0) {
                    exe[n] = 0;
                    int idx = is_protected(exe);

                    if (idx < 0) {
                        /* Not protected — allow without prompting */
                        resp.response = FAN_ALLOW;
                    } else {
                        pid_t pid = meta->pid;

                        /*
                         * Authorization inheritance: if the process or any
                         * of its ancestors has already been authorized
                         * (has a valid "ok" marker), allow without prompting.
                         *
                         * This handles the case where Firefox spawns a child
                         * process (e.g. content process) after the main
                         * process has been authenticated.
                         */
                        if (is_ancestor_authorized(pid)) {
                            fprintf(stderr,
                                    "[applockd] %s (pid %d) — ancestor already authorized, allowing\n",
                                    g_apps[idx].name, pid);
                            mark_handled(pid);
                            resp.response = FAN_ALLOW;
                        } else {
                            fprintf(stderr,
                                    "[applockd] detected %s (pid %d)\n",
                                    g_apps[idx].name, pid);

                            int ok = authorize_application(exe, g_apps[idx].name);
                            if (ok) {
                                mark_handled(pid);
                                resp.response = FAN_ALLOW;
                            } else {
                                resp.response = FAN_DENY;
                            }
                        }
                    }
                } else {
                    /* Cannot resolve path — deny by default */
                    resp.response = FAN_DENY;
                }

                if (write(fanfd, &resp, sizeof(resp)) < 0)
                    perror("[fan] write response");

                close(meta->fd);
            }
            meta = FAN_EVENT_NEXT(meta, len);
        }
    }

    close(fanfd);
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

        if (!disp || !*disp) setenv("DISPLAY", ":0.0", 1);

        if (!xauth || !*xauth) {
            const char *home = getenv("HOME");
            if (home && *home) {
                char xauth_path[512];
                snprintf(xauth_path, sizeof(xauth_path), "%s/.Xauthority", home);
                setenv("XAUTHORITY", xauth_path, 1);
            }
        }

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
    printf("backend = %s\n",
           g_backend == BACKEND_FANOTIFY ? "fanotify" : "proc");
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

    mkdir(MARKER_DIR, 0700);
    clear_all_markers();

    fprintf(stderr, "[applockd] backend: %s\n",
            g_backend == BACKEND_FANOTIFY ? "fanotify" : "proc connector");
    fprintf(stderr, "[applockd] %d protected applications\n", g_app_count);
    for (int i = 0; i < g_app_count; i++)
        fprintf(stderr, "[applockd] protected path #%d: '%s' (name: %s)\n",
                i, g_apps[i].path, g_apps[i].name);

    if (g_backend == BACKEND_FANOTIFY) {
        fan_backend_run();
    } else {
        proc_backend_run();
    }

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
           "  list                  list protected applications and backend\n"
           "  run                   start the daemon (as root)\n"
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
    return 1;
}
