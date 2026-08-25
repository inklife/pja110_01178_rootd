# PJA110 adbroot Source and Build

The single file is `pja110_adbroot.pyz` (only Python 3 and adb are required to run it).

The offsets are hardcoded in `pja110_adbroot.py` and are valid only for the **PJA110_16.0.5.702(CN01)** OTA build.

## Risk Notice

> **For security research and testing only. Run only on authorized devices. Do not use for any illegal purpose.**

## Directory Structure

```
pja110_01178_rootd/
  build.cmd / build.py     Build entry points
  pja110_adbroot.py        Host-side orchestration (exploit + rootd client)
  pja110_adbroot.cmd       Launches the pyz package
  src/
    pja110_rootd.c         On-device uid0 daemon (port 27391 framed REPL)
    e1c6_ret2dir.c         8-byte atomic_add write primitive
    e1c5_ks_window.c       KernelSnitch leak holder
    e1c6_slotrd.c          Resident reader for user_reserve_kbytes
    FuseStall.java         FUSE stall (app_process + StorageManager)
    kernelsnitch/          KernelSnitch headers (header-only)
  prebuilt/FuseStall.dex   Fallback when JDK/SDK is unavailable
  out/                     Build output
```

## Build Dependencies

Required:

- Python 3
- Android NDK (`aarch64-linux-android21-clang`)
  - Set `ANDROID_NDK_HOME`, or install the NDK under `ANDROID_SDK_ROOT\ndk\<ver>`.
  - Locally verified with NDK 29.0.14206865.

Optional (for rebuilding `FuseStall.dex`):

- JDK (`javac`)
- Android SDK `platforms/android-*/android.jar` + `build-tools/*/d8`

If JDK/SDK is unavailable, the build automatically uses `prebuilt/FuseStall.dex`.

## Build

Windows:

```
build.cmd
```

Any platform:

```
python build.py
```

Package an existing `out/` directory only:

```
python build.py --pack-only
```

Force use of the prebuilt dex file:

```
python build.py --no-dex
```

A successful build produces:

- `out/pja110_rootd`
- `out/e1c6_ret2dir`
- `out/e1c5_ks_window`
- `out/e1c6_slotrd`
- `out/FuseStall.dex`
- `pja110_adbroot.pyz`

## Usage

```
python pja110_adbroot.pyz
python pja110_adbroot.pyz status
python pja110_adbroot.pyz -c "id"
python pja110_adbroot.pyz shell
```

In `shell`, Tab completes commands and paths; `cls`/`clear` clears the screen; `getcon` and `setcon shell|init|kernel` change the SELinux context for the current session (run `setcon shell` before `./reboot`); `exit` leaves the daemon running. Each new shell still defaults to `u:r:kernel:s0`.

After a reboot, rootd is no longer running; run the pyz package again. USB debugging and adb are required.
