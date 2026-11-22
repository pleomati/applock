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

#define SOCK_PATH     "/var/run/applock.sock"
#define UI_SOCK_PATH  "/run/user/1000/applock-ui.sock"
#define CONF_PATH     "/etc/applock/config"
#define SECRET_PATH   "/etc/applock/secret"
#define MAX_APPS      64
#define MAX_PATH      512
#define SCAN_INTERVAL 500000   /* 0.5 s w mikrosekundach */
#define MARKER_TTL    60000    /* 60 s — po tym czasie znacznik wygasa */

/* ---------- PBKDF2 ---------- */
#define PBKDF2_ITERATIONS 75000
#define PBKDF2_SALT_LEN   16
#define PBKDF2_KEY_LEN    32

/* ---------- Konfiguracja ---------- */
typedef struct {
    char path[MAX_PATH];
    char name[128];
} AppEntry;

static AppEntry g_apps[MAX_APPS];
static int g_app_count = 0;

static int load_config(void) {
    FILE *f = fopen(CONF_PATH, "r");
    if (!f) { perror("[load_config] fopen"); return -1; }
    char line[1024];
    g_app_count = 0;
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

static int is_protected(const char *exe) {
    for (int i = 0; i < g_app_count; i++)
        if (strcmp(g_apps[i].path, exe) == 0) return i;
    return -1;
}

/* ---------- Hasło (PBKDF2) ---------- */
/*
 * Format pliku /etc/applock/secret:
 *   <hex_salt>:<hex_hash>
 * np.:
 *   a1b2c3d4e5f6...:0123456789abcdef...
 */
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

    /* Format: <hex_salt>:<hex_hash> */
    char *colon = strchr(line, ':');
    if (!colon) return 0;
    *colon = 0;

    const char *salt_hex = line;
    const char *stored_hash_hex = colon + 1;

    /* Hex salt -> binarny salt */
    unsigned char salt[PBKDF2_SALT_LEN];
    if (strlen(salt_hex) != PBKDF2_SALT_LEN * 2) return 0;
    for (int i = 0; i < PBKDF2_SALT_LEN; i++) {
        unsigned int byte;
        if (sscanf(salt_hex + i * 2, "%2x", &byte) != 1) return 0;
        salt[i] = (unsigned char)byte;
    }

    /* Oblicz hash z podanego hasła + salt */
    char calc_hex[PBKDF2_KEY_LEN * 2 + 1];
    pbkdf2_hex(input, salt, PBKDF2_SALT_LEN, calc_hex);

    int result = (strcmp(calc_hex, stored_hash_hex) == 0);
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

/* ---------- Gniazdo demona (root) ---------- */
static int connect_daemon(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ---------- Demon: pytanie do agenta UI (z limitem czasu) ---------- */
static int ask_via_ui_agent(const char *name, char *out, size_t len) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, UI_SOCK_PATH, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return 0;
    }
    char req[256];
    snprintf(req, sizeof(req), "AUTH %s\n", name);
    write(fd, req, strlen(req));

    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
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

/* ---------- Demon: znaczniki ---------- */
static int already_handled(pid_t pid) {
    char marker[128];
    snprintf(marker, sizeof(marker), "/tmp/.applock_ok_%d", pid);
    struct stat st;
    if (stat(marker, &st) != 0) return 0;
    if (time(NULL) - st.st_mtime > MARKER_TTL) {
        unlink(marker);
        return 0;
    }
    return 1;
}

static void mark_handled(pid_t pid) {
    char marker[128];
    snprintf(marker, sizeof(marker), "/tmp/.applock_ok_%d", pid);
    int fd = open(marker, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) close(fd);
}

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
    fprintf(stderr, "[applockd] usunięto %d starych znaczników\n", count);
}

/* ---------- Demon: dziedziczenie autoryzacji ---------- */
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
        depth++;
    }
    return 0;
}

/* ---------- Demon: monitorowanie /proc ---------- */
static void daemon_loop(void) {
    fprintf(stderr, "[applockd] monitorowanie /proc co %d ms, "
            "%d chronionych aplikacji\n", SCAN_INTERVAL / 1000, g_app_count);

    for (int i = 0; i < g_app_count; i++)
        fprintf(stderr, "[applockd] chroniona ścieżka #%d: '%s' (nazwa: %s)\n",
                i, g_apps[i].path, g_apps[i].name);

    clear_all_markers();

    while (1) {
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

            if (is_ancestor_authorized(pid)) {
                mark_handled(pid);
                continue;
            }

            fprintf(stderr, "[applockd] wykryto %s (pid %d)\n",
                    g_apps[idx].name, pid);

            if (kill(pid, SIGSTOP) < 0) {
                perror("kill SIGSTOP");
                continue;
            }

            char pass[256] = {0};
            int ok = 0;
            if (ask_via_ui_agent(g_apps[idx].name, pass, sizeof(pass)) &&
                verify_password(pass)) {
                ok = 1;
                fprintf(stderr, "[applockd] autoryzacja OK\n");
            } else {
                fprintf(stderr, "[applockd] autoryzacja ODRZUCONA\n");
            }
            memset(pass, 0, sizeof(pass));

            if (ok) {
                mark_handled(pid);
                kill(pid, SIGCONT);
            } else {
                kill(pid, SIGKILL);
                mark_handled(pid);
                fprintf(stderr, "[applockd] zabito %s (pid %d)\n", exe, pid);
            }
        }
        closedir(d);

        /* Usuń znaczniki dla PID-ów, które już nie istnieją */
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

/* ---------- Demon: serwer auth (root) ---------- */
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
    fprintf(stderr, "[applockd] nasłuch na %s\n", SOCK_PATH);

    while (1) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        char buf[512] = {0};
        read(c, buf, sizeof(buf) - 1);
        int pid; char name[128];
        if (sscanf(buf, "AUTH %d %127s", &pid, name) == 2) {
            char pass[256] = {0};
            fprintf(stderr,
                    "\n[applockd] Aplikacja '%s' (pid %d) czeka na hasło:\n",
                    name, pid);
            if (ask_via_ui_agent(name, pass, sizeof(pass)) &&
                verify_password(pass)) {
                write(c, "OK\n", 3);
                fprintf(stderr, "[applockd] autoryzacja OK\n");
            } else {
                write(c, "FAIL\n", 5);
                fprintf(stderr, "[applockd] autoryzacja ODRZUCONA\n");
            }
            memset(pass, 0, sizeof(pass));
        }
        close(c);
    }
}

/* ---------- Agent UI: Zenity przez plik tymczasowy ---------- */
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
        setenv("DISPLAY", disp && *disp ? disp : ":0.0", 1);
        setenv("XAUTHORITY", xauth && *xauth ? xauth : "/run/lightdm/ap/xauthority", 1);
        setenv("DBUS_SESSION_BUS_ADDRESS",
               dbus && *dbus ? dbus : "unix:path=/run/user/1000/bus", 1);
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
    fprintf(stderr, "[applock-ui] nasłuch na %s\n", sockpath);
    fprintf(stderr, "[applock-ui] DISPLAY=%s XAUTHORITY=%s\n",
            getenv("DISPLAY") ? getenv("DISPLAY") : "(null)",
            getenv("XAUTHORITY") ? getenv("XAUTHORITY") : "(null)");

    while (1) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        char buf[512] = {0};
        read(c, buf, sizeof(buf) - 1);
        char name[128] = {0};
        if (sscanf(buf, "AUTH %127s", name) == 1) {
            char title[256];
            char pass[256] = {0};
            snprintf(title, sizeof(title), "AppLock — %s", name);
            int ok = run_zenity_password(title, pass, sizeof(pass));
            if (ok) {
                write(c, pass, strlen(pass));
                write(c, "\n", 1);
            } else {
                write(c, "FAIL\n", 5);
            }
            memset(pass, 0, sizeof(pass));
        }
        close(c);
    }
}

/* ---------- Klient ---------- */
static int cmd_set_secret(void) {
    char p1[256], p2[256];
    printf("Nowe hasło: ");
    fflush(stdout);
    if (!read_password(p1, sizeof(p1))) return 1;
    printf("Powtórz hasło: ");
    fflush(stdout);
    if (!read_password(p2, sizeof(p2))) return 1;
    if (strcmp(p1, p2) != 0) {
        fprintf(stderr, "Hasła się różnią.\n");
        memset(p1, 0, sizeof(p1));
        memset(p2, 0, sizeof(p2));
        return 1;
    }

    /* Wygeneruj losową sól */
    unsigned char salt[PBKDF2_SALT_LEN];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Błąd generowania soli.\n");
        memset(p1, 0, sizeof(p1));
        memset(p2, 0, sizeof(p2));
        return 1;
    }

    /* Oblicz hash PBKDF2 */
    char hash_hex[PBKDF2_KEY_LEN * 2 + 1];
    pbkdf2_hex(p1, salt, sizeof(salt), hash_hex);

    memset(p1, 0, sizeof(p1));
    memset(p2, 0, sizeof(p2));

    /* Zapisz w formacie: <hex_salt>:<hex_hash> */
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
    printf("Hasło ustawione.\n");
    return 0;
}

static int cmd_add_app(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Użycie: applock add <ścieżka> <nazwa>\n");
        return 1;
    }
    if (access(argv[2], X_OK) != 0) { perror(argv[2]); return 1; }
    mkdir("/etc/applock", 0700);
    FILE *f = fopen(CONF_PATH, "a");
    if (!f) { perror(CONF_PATH); return 1; }
    fprintf(f, "app = %s|%s\n", argv[2], argv[3]);
    fclose(f);
    printf("Dodano: %s (%s)\n", argv[3], argv[2]);
    return 0;
}

static int cmd_list(void) {
    if (load_config() <= 0) {
        printf("Brak chronionych aplikacji.\n");
        return 0;
    }
    for (int i = 0; i < g_app_count; i++)
        printf("%s -> %s\n", g_apps[i].name, g_apps[i].path);
    return 0;
}

static int cmd_run(void) {
    if (load_config() <= 0) {
        fprintf(stderr, "Brak chronionych aplikacji w %s\n", CONF_PATH);
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
    printf("Użycie: applock <polecenie>\n"
           "  set-secret            ustaw hasło uwierzytelniające\n"
           "  add <path> <name>     dodaj aplikację do ochrony\n"
           "  list                  pokaż chronione aplikacje\n"
           "  run                   uruchom demona (/proc, jako root)\n"
           "  ui                    uruchom agenta UI (Zenity, jako user)\n");
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