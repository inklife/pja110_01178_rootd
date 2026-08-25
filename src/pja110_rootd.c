#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT 27391
#define PIDPATH "/data/local/tmp/pja110_rootd.pid"
#define OKPATH "/data/local/tmp/pja110_rootd.ok"
#define COMP_MAX 400

static void write_file(const char *path, const char *s) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd < 0) return;
  write(fd, s, strlen(s));
  close(fd);
  chmod(path, 0666);
}

static void daemonize(void) {
  int nfd;
  pid_t p = fork();
  if (p < 0) _exit(1);
  if (p > 0) _exit(0);
  setsid();
  p = fork();
  if (p < 0) _exit(1);
  if (p > 0) _exit(0);
  chdir("/");
  umask(022);
  nfd = open("/dev/null", O_RDWR);
  if (nfd >= 0) {
    dup2(nfd, 0);
    dup2(nfd, 1);
    dup2(nfd, 2);
    if (nfd > 2) close(nfd);
  }
}

static void banner(void) {
  char buf[512];
  snprintf(buf, sizeof(buf), "pid=%d uid=%d euid=%d gid=%d\n",
           getpid(), getuid(), geteuid(), getgid());
  write_file(OKPATH, buf);
  snprintf(buf, sizeof(buf), "%d\n", getpid());
  write_file(PIDPATH, buf);
}

static int run_cmd(int outfd, const char *cmd) {
  int p[2];
  pid_t pid;
  char buf[4096];
  ssize_t n;
  int st = 0;
  if (pipe(p) < 0) return 1;
  pid = fork();
  if (pid < 0) {
    close(p[0]);
    close(p[1]);
    return 1;
  }
  if (pid == 0) {
    dup2(p[1], 1);
    dup2(p[1], 2);
    close(p[0]);
    close(p[1]);
    execl("/system/bin/sh", "sh", "-c", cmd, (char *)0);
    _exit(127);
  }
  close(p[1]);
  while ((n = read(p[0], buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(outfd, buf + off, (size_t)(n - off));
      if (w <= 0) break;
      off += w;
    }
  }
  close(p[0]);
  waitpid(pid, &st, 0);
  return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

static int read_line(int fd, char *cmd, int cap) {
  int n = 0;
  while (n < cap - 1) {
    int r = (int)read(fd, cmd + n, 1);
    if (r <= 0) return -1;
    if (cmd[n] == '\n') break;
    n++;
  }
  cmd[n] = 0;
  while (n && cmd[n - 1] == '\r')
    cmd[--n] = 0;
  return n;
}

static void send_end(int cfd, int rc) {
  char end[64];
  snprintf(end, sizeof(end), "__PJA110_END__ %d\n", rc);
  write(cfd, end, strlen(end));
}

static int do_cd(int cfd, char *line) {
  char *dir = line + 2;
  char cwd[512];
  while (*dir == ' ' || *dir == '\t') dir++;
  if (*dir == '"' || *dir == '\'') {
    char q = *dir++;
    char *e = strrchr(dir, q);
    if (e) *e = 0;
  }
  if (!*dir) {
    dir = getenv("HOME");
    if (!dir || !*dir) dir = "/";
  }
  if (chdir(dir) != 0) {
    char err[256];
    int n = snprintf(err, sizeof(err), "cd: %s: %s\n", dir, strerror(errno));
    write(cfd, err, n);
    return 1;
  }
  if (getcwd(cwd, sizeof(cwd))) {
    write(cfd, cwd, strlen(cwd));
    write(cfd, "\n", 1);
  }
  return 0;
}

static void emit_ln(int cfd, const char *s) {
  write(cfd, s, strlen(s));
  write(cfd, "\n", 1);
}

static int path_isdir(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int g_comp_n;

static void emit_match(int cfd, const char *s) {
  if (g_comp_n >= COMP_MAX) return;
  g_comp_n++;
  emit_ln(cfd, s);
}

static void complete_names(int cfd, const char *dir, const char *prefix,
                           const char *out_prefix, int as_cmd) {
  DIR *dp;
  struct dirent *de;
  size_t plen = strlen(prefix);
  const char *open_dir = (dir && dir[0]) ? dir : ".";
  dp = opendir(open_dir);
  if (!dp) return;
  while ((de = readdir(dp))) {
    const char *n = de->d_name;
    char full[1024], out[1024];
    if (!strcmp(n, ".") || !strcmp(n, "..")) {
      if (strcmp(prefix, n) != 0) continue;
    }
    if (strncmp(n, prefix, plen) != 0) continue;
    if (!strcmp(open_dir, "/"))
      snprintf(full, sizeof(full), "/%s", n);
    else if (!strcmp(open_dir, "."))
      snprintf(full, sizeof(full), "%s", n);
    else
      snprintf(full, sizeof(full), "%s/%s", open_dir, n);
    if (as_cmd) {
      struct stat st;
      if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) continue;
      if (access(full, X_OK) != 0) continue;
      snprintf(out, sizeof(out), "%s", n);
    } else
      snprintf(out, sizeof(out), "%s%s", out_prefix, n);
    if (!as_cmd && path_isdir(full)) {
      size_t L = strlen(out);
      if (L + 1 < sizeof(out)) {
        out[L] = '/';
        out[L + 1] = 0;
      }
    }
    emit_match(cfd, out);
  }
  closedir(dp);
}

static void split_token(const char *tok, char *dir, size_t dsz,
                        char *pre, size_t psz, char *opfx, size_t osz) {
  const char *slash = strrchr(tok, '/');
  if (!slash) {
    snprintf(dir, dsz, ".");
    snprintf(pre, psz, "%s", tok);
    snprintf(opfx, osz, "%s", "");
    return;
  }
  size_t dlen = (size_t)(slash - tok);
  if (dlen == 0) {
    snprintf(dir, dsz, "/");
    snprintf(opfx, osz, "/");
  } else {
    if (dlen >= dsz) dlen = dsz - 1;
    memcpy(dir, tok, dlen);
    dir[dlen] = 0;
    snprintf(opfx, osz, "%s/", dir);
  }
  snprintf(pre, psz, "%s", slash + 1);
}

static void do_comp(int cfd, char *line) {
  static const char *path_dirs[] = {
      "/system/bin", "/system/xbin", "/vendor/bin", "/product/bin",
      "/system_ext/bin", "/data/local/tmp", 0};
  static const char *builtins[] = {
      "cd", "pwd", "exit", "quit", "clear", "cls", "logout",
      "setcon", "getcon", 0};
  char *tok = line;
  int first = 1;
  char *p;
  int pathish;
  g_comp_n = 0;
  for (p = line; *p; p++) {
    if (*p == ' ' || *p == '\t') {
      first = 0;
      tok = p + 1;
    }
  }
  pathish = (!first) || (strchr(tok, '/') != 0) || (tok[0] == '.');
  if (!pathish) {
    size_t plen = strlen(tok);
    const char **b;
    for (b = builtins; *b; b++) {
      if (!strncmp(*b, tok, plen)) emit_match(cfd, *b);
    }
    for (b = path_dirs; *b; b++) complete_names(cfd, *b, tok, "", 1);
    return;
  }
  {
    char dir[512], pre[256], opfx[512];
    split_token(tok, dir, sizeof(dir), pre, sizeof(pre), opfx, sizeof(opfx));
    complete_names(cfd, dir, pre, opfx, 0);
  }
}


static int write_attr(const char *path, const char *s) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  ssize_t n;
  if (fd < 0) return -1;
  n = write(fd, s, strlen(s));
  close(fd);
  return (n == (ssize_t)strlen(s)) ? 0 : -1;
}

static int read_attr(const char *path, char *buf, int cap) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  int n;
  if (fd < 0) return -1;
  n = (int)read(fd, buf, cap - 1);
  close(fd);
  if (n < 0) return -1;
  while (n && (buf[n - 1] == 0 || buf[n - 1] == '\n')) n--;
  buf[n] = 0;
  return n;
}

static int do_getcon(int cfd) {
  char buf[256];
  if (read_attr("/proc/self/attr/current", buf, sizeof(buf)) < 0) {
    char err[128];
    int n = snprintf(err, sizeof(err), "getcon: %s\n", strerror(errno));
    write(cfd, err, n);
    return 1;
  }
  write(cfd, buf, strlen(buf));
  write(cfd, "\n", 1);
  return 0;
}

static const char *map_con(const char *s) {
  if (!strcmp(s, "shell")) return "u:r:shell:s0";
  if (!strcmp(s, "init")) return "u:r:init:s0";
  if (!strcmp(s, "kernel")) return "u:r:kernel:s0";
  if (!strcmp(s, "su")) return "u:r:su:s0";
  if (!strcmp(s, "toolbox")) return "u:r:toolbox:s0";
  return s;
}

static int do_setcon(int cfd, char *line) {
  char *ctx = line + 6;
  const char *want;
  char err[320];
  int n;
  while (*ctx == ' ' || *ctx == '\t') ctx++;
  if (!*ctx) {
    n = snprintf(err, sizeof(err),
                 "usage: setcon <context>|shell|init|kernel|su|toolbox\n");
    write(cfd, err, n);
    return 1;
  }
  if ((*ctx == '"' || *ctx == '\'') && ctx[strlen(ctx) - 1] == *ctx) {
    ctx[strlen(ctx) - 1] = 0;
    ctx++;
  }
  want = map_con(ctx);
  if (write_attr("/proc/self/attr/current", want) < 0) {
    n = snprintf(err, sizeof(err), "setcon current %s: %s\n", want, strerror(errno));
    write(cfd, err, n);
    return 1;
  }
  if (write_attr("/proc/self/attr/exec", want) < 0) {
    n = snprintf(err, sizeof(err), "setcon exec %s: %s\n", want, strerror(errno));
    write(cfd, err, n);
    return 1;
  }
  n = snprintf(err, sizeof(err), "ok %s\n", want);
  write(cfd, err, n);
  return do_getcon(cfd);
}

static void repl(int cfd) {
  char cmd[8192];
  for (;;) {
    int n = read_line(cfd, cmd, sizeof(cmd));
    int rc;
    if (n < 0) break;
    if (!strncmp(cmd, "__comp__", 8) &&
        (cmd[8] == 0 || isspace((unsigned char)cmd[8]))) {
      char *arg = cmd + 8;
      while (*arg == ' ' || *arg == '\t') arg++;
      do_comp(cfd, arg);
      send_end(cfd, 0);
      continue;
    }
    if (!cmd[0]) {
      send_end(cfd, 0);
      continue;
    }
    if (!strcmp(cmd, "exit") || !strcmp(cmd, "quit") || !strcmp(cmd, "logout")) {
      send_end(cfd, 0);
      break;
    }
    if (!strncmp(cmd, "cd", 2) && (cmd[2] == 0 || isspace((unsigned char)cmd[2]))) {
      rc = do_cd(cfd, cmd);
      send_end(cfd, rc);
      continue;
    }
    if (!strcmp(cmd, "pwd")) {
      char cwd[512];
      if (getcwd(cwd, sizeof(cwd))) {
        write(cfd, cwd, strlen(cwd));
        write(cfd, "\n", 1);
        send_end(cfd, 0);
      } else {
        send_end(cfd, 1);
      }
      continue;
    }
    if (!strcmp(cmd, "getcon")) {
      send_end(cfd, do_getcon(cfd));
      continue;
    }
    if (!strncmp(cmd, "setcon", 6) &&
        (cmd[6] == 0 || isspace((unsigned char)cmd[6]))) {
      send_end(cfd, do_setcon(cfd, cmd));
      continue;
    }
    rc = run_cmd(cfd, cmd);
    send_end(cfd, rc);
  }
}

static void handle(int cfd) {
  char cmd[8192];
  int n = read_line(cfd, cmd, sizeof(cmd));
  if (n < 0) return;
  if (!cmd[0] || !strcmp(cmd, "__ping__")) {
    write(cfd, "PONG\n", 5);
    send_end(cfd, 0);
    return;
  }
  if (!strcmp(cmd, "__id__")) {
    send_end(cfd, run_cmd(cfd, "id; /system/bin/getenforce; cat /proc/self/attr/current; echo"));
    return;
  }
  if (!strcmp(cmd, "__repl__") || !strcmp(cmd, "__exec_sh__")) {
    repl(cfd);
    return;
  }
  send_end(cfd, run_cmd(cfd, cmd));
}

int main(void) {
  int sfd, cfd, one = 1;
  struct sockaddr_in addr;
  prctl(PR_SET_NAME, "PJA110D", 0, 0, 0);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  if (!getenv("PATH") || !getenv("PATH")[0])
    setenv("PATH", "/system/bin:/system/xbin:/vendor/bin:/data/local/tmp", 1);
  daemonize();
  prctl(PR_SET_NAME, "PJA110D", 0, 0, 0);
  banner();
  sfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sfd < 0) return 1;
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    write_file("/data/local/tmp/pja110_rootd.err", "bind failed\n");
    return 1;
  }
  listen(sfd, 8);
  for (;;) {
    pid_t pid;
    cfd = accept(sfd, 0, 0);
    if (cfd < 0) continue;
    pid = fork();
    if (pid < 0) {
      close(cfd);
      continue;
    }
    if (pid == 0) {
      close(sfd);
      signal(SIGCHLD, SIG_DFL);
      handle(cfd);
      close(cfd);
      _exit(0);
    }
    close(cfd);
  }
}
