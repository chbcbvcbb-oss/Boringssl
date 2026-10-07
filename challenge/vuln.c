#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
#pragma GCC diagnostic ignored "-Wunused-result"

#define PORT 1337
#define MAX_NOTES 16
#define MAX_NOTE_SIZE 0x400
#define MAX_USERNAME 32
#define FLAG_PATH "/flag.txt"

typedef struct {
    char *content;
    size_t size;
    size_t capacity;
    int in_use;
    uint64_t cookie;
} note_t;

typedef struct {
    int fd;
    char username[MAX_USERNAME];
    note_t notes[MAX_NOTES];
    uint64_t session_cookie;
    int authenticated;
} client_t;

note_t *g_notes = NULL;
int g_note_count = 0;
uint64_t g_global_cookie = 0;
char g_flag[256] = {0};

void init_random_cookie() {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, &g_global_cookie, sizeof(g_global_cookie));
        close(fd);
    } else {
        g_global_cookie = (uint64_t)time(NULL) ^ (uint64_t)getpid() << 32;
    }
}

void load_flag() {
    int fd = open(FLAG_PATH, O_RDONLY);
    if (fd >= 0) {
        read(fd, g_flag, sizeof(g_flag) - 1);
        close(fd);
    } else {
        snprintf(g_flag, sizeof(g_flag), "flag{this_is_a_fake_flag_for_testing}");
    }
}

void setup_socket(int *server_fd) {
    struct sockaddr_in addr;
    int opt = 1;

    *server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*server_fd < 0) {
        perror("socket");
        exit(1);
    }

    setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(*server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(*server_fd, 10) < 0) {
        perror("listen");
        exit(1);
    }
}

void send_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return;
        p += n;
        len -= n;
    }
}

int recv_line(int fd, char *buf, size_t max) {
    size_t i = 0;
    char c;
    while (i < max - 1) {
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

void hexdump(const void *data, size_t len) {
    const uint8_t *p = data;
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

int find_free_note(client_t *c) {
    for (int i = 0; i < MAX_NOTES; i++) {
        if (!c->notes[i].in_use) return i;
    }
    return -1;
}

int parse_index(const char *str, int max) {
    long idx = strtol(str, NULL, 10);
    if (idx < 0 || idx >= max) return -1;
    return (int)idx;
}

void cmd_help(int fd) {
    const char *help =
        "Commands:\n"
        "  register <username>  - Register new account\n"
        "  login <username>     - Login to account\n"
        "  create <size>        - Create new note\n"
        "  write <idx> <data>   - Write to note (format string vuln here)\n"
        "  read <idx>           - Read note\n"
        "  edit <idx> <offset> <data> - Edit note at offset (heap overflow)\n"
        "  delete <idx>         - Delete note (UAF)\n"
        "  list                 - List notes\n"
        "  profile              - Show profile (format string)\n"
        "  logout               - Logout\n"
        "  exit                 - Exit\n";
    send_all(fd, help, strlen(help));
}

void cmd_register(client_t *c, char *args) {
    if (c->authenticated) {
        send_all(c->fd, "Already logged in\n", 18);
        return;
    }
    if (!args || !*args) {
        send_all(c->fd, "Usage: register <username>\n", 27);
        return;
    }
    strncpy(c->username, args, MAX_USERNAME - 1);
    c->username[MAX_USERNAME - 1] = '\0';
    c->session_cookie = g_global_cookie ^ (uint64_t)c->fd;
    c->authenticated = 1;
    memset(c->notes, 0, sizeof(c->notes));
    char msg[128];
    snprintf(msg, sizeof(msg), "Registered: %s\n", c->username);
    send_all(c->fd, msg, strlen(msg));
}

void cmd_login(client_t *c, char *args) {
    if (c->authenticated) {
        send_all(c->fd, "Already logged in\n", 18);
        return;
    }
    if (!args || !*args) {
        send_all(c->fd, "Usage: login <username>\n", 24);
        return;
    }
    strncpy(c->username, args, MAX_USERNAME - 1);
    c->username[MAX_USERNAME - 1] = '\0';
    c->session_cookie = g_global_cookie ^ (uint64_t)c->fd;
    c->authenticated = 1;
    memset(c->notes, 0, sizeof(c->notes));
    char msg[128];
    snprintf(msg, sizeof(msg), "Welcome back: %s\n", c->username);
    send_all(c->fd, msg, strlen(msg));
}

void cmd_logout(client_t *c) {
    if (!c->authenticated) {
        send_all(c->fd, "Not logged in\n", 14);
        return;
    }
    for (int i = 0; i < MAX_NOTES; i++) {
        if (c->notes[i].in_use && c->notes[i].content) {
            free(c->notes[i].content);
            c->notes[i].content = NULL;
            c->notes[i].in_use = 0;
        }
    }
    c->authenticated = 0;
    send_all(c->fd, "Logged out\n", 11);
}

void cmd_create(client_t *c, char *args) {
    if (!c->authenticated) {
        send_all(c->fd, "Login required\n", 15);
        return;
    }
    if (!args || !*args) {
        send_all(c->fd, "Usage: create <size>\n", 21);
        return;
    }
    size_t size = strtoul(args, NULL, 10);
    if (size == 0 || size > MAX_NOTE_SIZE) {
        send_all(c->fd, "Invalid size\n", 13);
        return;
    }
    int idx = find_free_note(c);
    if (idx < 0) {
        send_all(c->fd, "No free slots\n", 14);
        return;
    }
    c->notes[idx].content = malloc(size);
    if (!c->notes[idx].content) {
        send_all(c->fd, "Alloc failed\n", 13);
        return;
    }
    c->notes[idx].size = 0;
    c->notes[idx].capacity = size;
    c->notes[idx].in_use = 1;
    c->notes[idx].cookie = c->session_cookie ^ (uint64_t)idx;
    char msg[64];
    snprintf(msg, sizeof(msg), "Created note %d (size=%zu)\n", idx, size);
    send_all(c->fd, msg, strlen(msg));
}

void cmd_write(client_t *c, char *args) {
    if (!c->authenticated) {
        send_all(c->fd, "Login required\n", 15);
        return;
    }
    char *idx_str = strtok(args, " ");
    char *data = strtok(NULL, "");
    if (!idx_str || !data) {
        send_all(c->fd, "Usage: write <idx> <data>\n", 26);
        return;
    }
    int idx = parse_index(idx_str, MAX_NOTES);
    if (idx < 0 || !c->notes[idx].in_use) {
        send_all(c->fd, "Invalid note\n", 13);
        return;
    }
    if (c->notes[idx].cookie != (c->session_cookie ^ (uint64_t)idx)) {
        send_all(c->fd, "Cookie mismatch\n", 16);
        return;
    }
    size_t len = strlen(data);
    if (len >= c->notes[idx].capacity) {
        len = c->notes[idx].capacity - 1;
    }
    memcpy(c->notes[idx].content, data, len);
    c->notes[idx].content[len] = '\0';
    c->notes[idx].size = len;

    char buf[1024];
    snprintf(buf, sizeof(buf), "Written %zu bytes\n", len);
    send_all(c->fd, buf, strlen(buf));

    char fmtbuf[1024];
    snprintf(fmtbuf, sizeof(fmtbuf), data);
    send_all(c->fd, fmtbuf, strlen(fmtbuf));
}

void cmd_read(client_t *c, char *args) {
    if (!c->authenticated) {
        send_all(c->fd, "Login required\n", 15);
        return;
    }
    if (!args || !*args) {
        send_all(c->fd, "Usage: read <idx>\n", 18);
        return;
    }
    int idx = parse_index(args, MAX_NOTES);
    if (idx < 0 || !c->notes[idx].in_use) {
        send_all(c->fd, "Invalid note\n", 13);
        return;
    }
    if (c->notes[idx].cookie != (c->session_cookie ^ (uint64_t)idx)) {
        send_all(c->fd, "Cookie mismatch\n", 16);
        return;
    }
    char msg[128];
    snprintf(msg, sizeof(msg), "Note %d (%zu bytes):\n", idx, c->notes[idx].size);
    send_all(c->fd, msg, strlen(msg));
    send_all(c->fd, c->notes[idx].content, c->notes[idx].size);
    send_all(c->fd, "\n", 1);
}

void cmd_edit(client_t *c, char *args) {
    if (!c->authenticated) {
        send_all(c->fd, "Login required\n", 15);
        return;
    }
    char *idx_str = strtok(args, " ");
    char *off_str = strtok(NULL, " ");
    char *data = strtok(NULL, "");
    if (!idx_str || !off_str || !data) {
        send_all(c->fd, "Usage: edit <idx> <offset> <data>\n", 34);
        return;
    }
    int idx = parse_index(idx_str, MAX_NOTES);
    if (idx < 0 || !c->notes[idx].in_use) {
        send_all(c->fd, "Invalid note\n", 13);
        return;
    }
    if (c->notes[idx].cookie != (c->session_cookie ^ (uint64_t)idx)) {
        send_all(c->fd, "Cookie mismatch\n", 16);
        return;
    }
    size_t offset = strtoul(off_str, NULL, 10);
    size_t len = strlen(data);
    if (offset + len > c->notes[idx].capacity) {
        send_all(c->fd, "Out of bounds\n", 14);
        return;
    }
    memcpy(c->notes[idx].content + offset, data, len);
    if (offset + len > c->notes[idx].size) {
        c->notes[idx].size = offset + len;
    }
    c->notes[idx].content[c->notes[idx].size] = '\0';
    char msg[64];
    snprintf(msg, sizeof(msg), "Edited at offset %zu\n", offset);
    send_all(c->fd, msg, strlen(msg));
}

void cmd_delete(client_t *c, char *args) {
    if (!c->authenticated) {
        send_all(c->fd, "Login required\n", 15);
        return;
    }
    if (!args || !*args) {
        send_all(c->fd, "Usage: delete <idx>\n", 20);
        return;
    }
    int idx = parse_index(args, MAX_NOTES);
    if (idx < 0 || !c->notes[idx].in_use) {
        send_all(c->fd, "Invalid note\n", 13);
        return;
    }
    if (c->notes[idx].cookie != (c->session_cookie ^ (uint64_t)idx)) {
        send_all(c->fd, "Cookie mismatch\n", 16);
        return;
    }
    free(c->notes[idx].content);
    c->notes[idx].content = NULL;
    c->notes[idx].in_use = 0;
    c->notes[idx].size = 0;
    c->notes[idx].capacity = 0;
    send_all(c->fd, "Deleted\n", 8);
}

void cmd_list(client_t *c) {
    if (!c->authenticated) {
        send_all(c->fd, "Login required\n", 15);
        return;
    }
    send_all(c->fd, "Notes:\n", 7);
    for (int i = 0; i < MAX_NOTES; i++) {
        if (c->notes[i].in_use) {
            char msg[128];
            snprintf(msg, sizeof(msg), "  [%d] size=%zu cap=%zu cookie=%lx\n",
                     i, c->notes[i].size, c->notes[i].capacity, c->notes[i].cookie);
            send_all(c->fd, msg, strlen(msg));
        }
    }
}

void cmd_profile(client_t *c) {
    if (!c->authenticated) {
        send_all(c->fd, "Login required\n", 15);
        return;
    }
    char buf[512];
    snprintf(buf, sizeof(buf), "Profile for: %s\nSession: %lx\nNotes: %d\n",
             c->username, c->session_cookie, g_note_count);
    send_all(c->fd, buf, strlen(buf));
    char fmtbuf[512];
    snprintf(fmtbuf, sizeof(fmtbuf), buf);
    send_all(c->fd, fmtbuf, strlen(fmtbuf));
}

void handle_client(int client_fd) {
    client_t client = {0};
    client.fd = client_fd;
    char buf[2048];

    send_all(client_fd, "Welcome to NoteService v2.0\n", 28);
    send_all(client_fd, "Type 'help' for commands\n", 24);

    while (1) {
        send_all(client_fd, "> ", 2);
        int len = recv_line(client_fd, buf, sizeof(buf));
        if (len <= 0) break;

        char *cmd = strtok(buf, " ");
        char *args = strtok(NULL, "");

        if (!cmd) continue;

        if (strcmp(cmd, "help") == 0) {
            cmd_help(client_fd);
        } else if (strcmp(cmd, "register") == 0) {
            cmd_register(&client, args);
        } else if (strcmp(cmd, "login") == 0) {
            cmd_login(&client, args);
        } else if (strcmp(cmd, "logout") == 0) {
            cmd_logout(&client);
        } else if (strcmp(cmd, "create") == 0) {
            cmd_create(&client, args);
        } else if (strcmp(cmd, "write") == 0) {
            cmd_write(&client, args);
        } else if (strcmp(cmd, "read") == 0) {
            cmd_read(&client, args);
        } else if (strcmp(cmd, "edit") == 0) {
            cmd_edit(&client, args);
        } else if (strcmp(cmd, "delete") == 0) {
            cmd_delete(&client, args);
        } else if (strcmp(cmd, "list") == 0) {
            cmd_list(&client);
        } else if (strcmp(cmd, "profile") == 0) {
            cmd_profile(&client);
        } else if (strcmp(cmd, "exit") == 0) {
            break;
        } else {
            send_all(client_fd, "Unknown command\n", 16);
        }
    }

    cmd_logout(&client);
    close(client_fd);
}

void sigchld_handler(int sig __attribute__((unused))) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGCHLD, sigchld_handler);
    signal(SIGPIPE, SIG_IGN);

    init_random_cookie();
    load_flag();

    int server_fd;
    setup_socket(&server_fd);

    printf("NoteService listening on port %d\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            close(server_fd);
            handle_client(client_fd);
            exit(0);
        } else if (pid > 0) {
            close(client_fd);
        } else {
            perror("fork");
            close(client_fd);
        }
    }

    close(server_fd);
    return 0;
}

#pragma GCC diagnostic pop