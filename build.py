#!/usr/bin/env python3
"""Build PJA110 adbroot native bins + FuseStall.dex + pja110_adbroot.pyz.

Requires:
  - Python 3
  - Android NDK (aarch64-linux-android21-clang)
  - Optional: Android SDK (javac + d8) to rebuild FuseStall.dex
    If SDK/JDK is missing, prebuilt/FuseStall.dex is used.

Env (optional):
  ANDROID_NDK_HOME / ANDROID_NDK_ROOT
  ANDROID_HOME / ANDROID_SDK_ROOT
  JAVA_HOME
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
OUT = HERE / "out"
PRE = HERE / "prebuilt"
API = "21"
NATIVE = [
    ("pja110_rootd.c", "pja110_rootd"),
    ("e1c6_slotrd.c", "e1c6_slotrd"),
    ("e1c6_ret2dir.c", "e1c6_ret2dir"),
    ("e1c5_ks_window.c", "e1c5_ks_window"),
]


def log(msg):
    print("[build] " + msg, flush=True)


def die(msg, code=1):
    print("[!] " + msg, file=sys.stderr)
    sys.exit(code)


def run(cmd, cwd=None, env=None):
    pretty = " ".join(str(x) for x in cmd)
    log("$ " + pretty)
    r = subprocess.run(cmd, cwd=cwd, env=env)
    if r.returncode != 0:
        die("command failed (%d): %s" % (r.returncode, pretty))


def is_exe(p: Path) -> bool:
    return p.is_file()


def ndk_host_tag():
    if os.name == "nt":
        return "windows-x86_64"
    if sys.platform == "darwin":
        return "darwin-x86_64"
    return "linux-x86_64"


def iter_ndk_roots():
    seen = set()

    def add(p):
        if not p:
            return
        p = Path(p)
        try:
            p = p.resolve()
        except Exception:
            p = Path(p)
        if p in seen or not p.exists():
            return
        seen.add(p)
        yield p

    for k in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_ROOT"):
        v = os.environ.get(k)
        if v:
            yield from add(v)
    sdk_cands = []
    for k in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(k)
        if v:
            sdk_cands.append(Path(v))
    home = Path.home()
    sdk_cands += [
        Path(r"D:\Apps\Android\Sdk"),
        home / "AppData" / "Local" / "Android" / "Sdk",
        Path("/opt/android-sdk"),
        Path.home() / "Android" / "Sdk",
        Path("/usr/lib/android-sdk"),
    ]
    for sdk in sdk_cands:
        ndk = sdk / "ndk"
        if ndk.is_dir():
            vers = sorted((p for p in ndk.iterdir() if p.is_dir()), reverse=True)
            for v in vers:
                yield from add(v)
        bundled = sdk / "ndk-bundle"
        if bundled.is_dir():
            yield from add(bundled)


def find_clang() -> Path:
    host = ndk_host_tag()
    names = []
    if os.name == "nt":
        names += [
            "aarch64-linux-android%s-clang.exe" % API,
            "aarch64-linux-android%s-clang.cmd" % API,
            "aarch64-linux-android-clang.exe",
            "clang.exe",
        ]
    names += [
        "aarch64-linux-android%s-clang" % API,
        "aarch64-linux-android-clang",
        "clang",
    ]
    for ndk in iter_ndk_roots():
        bindir = ndk / "toolchains" / "llvm" / "prebuilt" / host / "bin"
        if not bindir.is_dir():
            continue
        for name in names:
            p = bindir / name
            if is_exe(p):
                log("NDK clang: %s" % p)
                return p
        extra = sorted(bindir.glob("aarch64-linux-android*-clang*"))
        for p in extra:
            if p.suffix.lower() in (".exe", ".cmd", "") or p.name.endswith("clang"):
                log("NDK clang: %s" % p)
                return p
    die(
        "cannot find NDK aarch64 clang. Set ANDROID_NDK_HOME "
        "(need toolchains/llvm/prebuilt/%s/bin/aarch64-linux-android%s-clang)"
        % (host, API)
    )


def wrap_cmd(path: Path):
    path = Path(path)
    if os.name == "nt" and path.suffix.lower() in (".cmd", ".bat"):
        return ["cmd", "/c", str(path)]
    return [str(path)]


def compile_native(clang: Path):
    OUT.mkdir(parents=True, exist_ok=True)
    for src_name, out_name in NATIVE:
        src = SRC / src_name
        dst = OUT / out_name
        if not src.is_file():
            die("missing source %s" % src)
        cmd = wrap_cmd(clang) + [
            "-static",
            "-O2",
            "-pthread",
            "-fno-strict-aliasing",
            "-I",
            str(SRC),
            "-o",
            str(dst),
            str(src),
        ]
        run(cmd)
        if not dst.is_file():
            die("clang produced no output: %s" % dst)
        log("ok %s (%d bytes)" % (dst.name, dst.stat().st_size))


def iter_sdk_roots():
    seen = set()

    def add(p):
        if not p:
            return
        p = Path(p)
        if not p.exists() or p in seen:
            return
        seen.add(p)
        yield p

    for k in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(k)
        if v:
            yield from add(v)
    home = Path.home()
    for p in (
        Path(r"D:\Apps\Android\Sdk"),
        home / "AppData" / "Local" / "Android" / "Sdk",
        Path.home() / "Android" / "Sdk",
        Path("/opt/android-sdk"),
    ):
        yield from add(p)


def find_android_jar() -> Path | None:
    jars = []
    for sdk in iter_sdk_roots():
        plat = sdk / "platforms"
        if not plat.is_dir():
            continue
        jars.extend(plat.glob("android-*/android.jar"))
    if not jars:
        return None
    jars.sort(key=lambda p: p.parent.name, reverse=True)
    return jars[0]


def find_d8() -> Path | None:
    cands = []
    for sdk in iter_sdk_roots():
        bt = sdk / "build-tools"
        if not bt.is_dir():
            continue
        if os.name == "nt":
            cands.extend(bt.glob("*/d8.bat"))
            cands.extend(bt.glob("*/d8.cmd"))
        cands.extend(bt.glob("*/d8"))
    if not cands:
        return None
    cands.sort(key=lambda p: p.parent.name, reverse=True)
    return cands[0]


def find_javac() -> Path | None:
    names = ["javac.exe", "javac"]
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        binp = Path(java_home) / "bin"
        for n in names:
            p = binp / n
            if is_exe(p):
                return p
    w = shutil.which("javac")
    return Path(w) if w else None


def build_dex():
    java_src = SRC / "FuseStall.java"
    dst = OUT / "FuseStall.dex"
    javac = find_javac()
    jar = find_android_jar()
    d8 = find_d8()
    if not (javac and jar and d8):
        log(
            "SDK/JDK incomplete (javac=%s android.jar=%s d8=%s) -> prebuilt dex"
            % (javac, jar, d8)
        )
        shutil.copy2(PRE / "FuseStall.dex", dst)
        log("ok FuseStall.dex (prebuilt %d bytes)" % dst.stat().st_size)
        return
    classes = OUT / "fuse_classes"
    if classes.exists():
        shutil.rmtree(classes)
    classes.mkdir(parents=True)
    run(
        wrap_cmd(javac)
        + [
            "-encoding",
            "UTF-8",
            "-source",
            "1.8",
            "-target",
            "1.8",
            "-Xlint:-options",
            "-bootclasspath",
            str(jar),
            "-classpath",
            str(jar),
            "-d",
            str(classes),
            str(java_src),
        ]
    )
    class_files = sorted(classes.rglob("*.class"))
    if not class_files:
        die("javac produced no .class")
    dexdir = OUT / "fuse_dex"
    if dexdir.exists():
        shutil.rmtree(dexdir)
    dexdir.mkdir()
    run(wrap_cmd(d8) + ["--min-api", API, "--lib", str(jar), "--output", str(dexdir)] + [str(p) for p in class_files])
    produced = dexdir / "classes.dex"
    if not produced.is_file():
        die("d8 did not write classes.dex")
    shutil.copy2(produced, dst)
    log("ok FuseStall.dex (rebuilt %d bytes)" % dst.stat().st_size)


def pack_pyz():
    py = HERE / "pja110_adbroot.py"
    if not py.is_file():
        die("missing pja110_adbroot.py")
    bins = ["e1c6_ret2dir", "e1c5_ks_window", "pja110_rootd", "e1c6_slotrd", "FuseStall.dex"]
    for n in bins:
        p = OUT / n
        if not p.is_file():
            die("missing build output %s" % p)
    out = HERE / "pja110_adbroot.pyz"
    main = b"from pja110_adbroot import main\nif __name__ == '__main__':\n    main()\n"
    mod = py.read_bytes()
    if mod.startswith(b"\xef\xbb\xbf"):
        mod = mod[3:]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("__main__.py", main)
        z.writestr("pja110_adbroot.py", mod)
        for name in bins:
            z.write(OUT / name, "bins/" + name)
            log("zip bins/%s" % name)
    log("ok %s (%d bytes)" % (out.name, out.stat().st_size))


def main():
    ap = argparse.ArgumentParser(description="Build pja110_adbroot.pyz")
    ap.add_argument("--pack-only", action="store_true", help="only zip out/ into pyz")
    ap.add_argument("--no-dex", action="store_true", help="use prebuilt FuseStall.dex")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if not args.pack_only:
        clang = find_clang()
        compile_native(clang)
        if args.no_dex:
            shutil.copy2(PRE / "FuseStall.dex", OUT / "FuseStall.dex")
            log("ok FuseStall.dex (prebuilt)")
        else:
            build_dex()
    pack_pyz()
    print()
    print("build done.")
    print("  %s" % (HERE / "pja110_adbroot.pyz"))
    print("run:")
    print("  python pja110_adbroot.pyz")
    print("  python pja110_adbroot.pyz -c id")
    print("  python pja110_adbroot.pyz shell")


if __name__ == "__main__":
    main()
