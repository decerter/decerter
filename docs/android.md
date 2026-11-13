# Android
decerter runs on rooted Android 15 or newer with a GKI kernel android15-6.6 or newer (android15-6.6, android16-6.12, android17-6.18), on x86_64 emulators and arm64 devices. Every app has its own UID, so `--package` (or `--uid`) selects one app. Only the x86_64 Android 15 emulator (Google APIs image, `adb root`) was tested; real devices are accepted as **experimental**, and arm64 at runtime, Magisk, KernelSU and Android 16 and 17 are not verified.

The [quickstart](../README.md#quickstart-android) goes through `decerter android setup` with Chrome on the emulator.

## decerter android setup
`decerter android setup` runs on the Linux host as your user, not as root: adb and the emulator belong to your user, and adb as root would start a second adb server.

```sh
./decerter android setup --package com.example.app                  # the one running device or emulator
./decerter android setup --avd decerter-a15 --package com.example.app   # boot the AVD first, without a window
./decerter android setup --serial 0A1B2C3D --binary ./decerter-arm64 --port 8080
./decerter android setup --remove --serial emulator-5554            # undo it
```

What it does:
- adb comes from `ADB`, then `ANDROID_HOME`, `ANDROID_SDK_ROOT`, `PATH` and `~/Android/Sdk`. The device is the one adb sees, the one `--serial` names, or the emulator of `--avd`, which setup boots without a window (`-no-snapshot`, a cold boot) when it doesn't run; that emulator keeps running, `adb -s <serial> emu kill` stops it.
- It reads the ABI, the Android release, the API level and the kernel, and refuses other ABIs, Android before 15 and kernels before android15-6.6, with the reason. Then `adb root`; a Google Play image is a production build where adbd can't be root, and setup says so (a Google APIs image works). On a rooted production build (Magisk, KernelSU) it uses `su` instead and prints the command with `su -c`; that path is not tested. A real device gets a warning that it is experimental.
- It pushes the static binary for the device's ABI to `/data/local/tmp/decerter`: itself for x86_64, `decerter-arm64` next to it for arm64 (from the arm64 release tarball or `make build-arm64`), or `--binary`. A dynamically linked binary or one for another architecture is refused before the device is touched, and so is a push while a decerter runs on the device. It then runs the pushed binary's `--version`.
- It checks that decerter has Conscrypt offsets for the Android release (15, 16 and 17 today); without them it warns, and decerter on the device relays TLS without decrypting it.
- With `--package` it looks the package up on the device the way `decerter run --package` does, so a typo fails before anything is pushed, and runs `decerter android tls --package <name>` there: the `app` line says whether the app's TLS goes through Conscrypt, or whether it is a Flutter or Chromium app and decerter has the offsets of its version. Without `--package` the printed command has `PACKAGE` in its place.
- It forwards a host port to the API's abstract socket `@decerter-api`: `--port`, or the forward an earlier setup made, or a free port adb picks. adb forward's port is open to every local user of the workstation.
- It prints the command that starts decerter on the device (`adb -s <serial> shell -t /data/local/tmp/decerter run --intercept --api-socket @decerter-api --package <name>`, so Ctrl-C reaches decerter), the `decerter ui` command for the host, and the `--remove` command.
- `--remove` undoes it: refused while decerter runs, it puts back netd's hooks a killed decerter left shared (`decerter android restore` on the device), then removes the binary, `/data/local/tmp/decerter.d` and the forwards to `@decerter-api`.

## --package
`run`, `capture` and `keylog` take `--package <name>`, repeatable or comma separated. decerter reads the app's UID from `/data/system/packages.list` on the device when it starts and adds it to the UIDs of `--uid`, so a package selects exactly what `--uid <its uid>` selects, also together with `--filter`, `--dst-cidr` and `--dst-port`. An unknown name fails before anything is attached and lists the closest installed packages:

```
unknown package "no.such.app", the closest installed packages: android, com.android.mtp, com.android.bips, com.android.egg, com.android.nfc (adb shell pm list packages lists all of them)
```

The UID is the app's UID in user 0, the device owner; for a work profile or another user, select with `--uid <user>*100000+<app uid>` (not tested). Some system packages share a UID (`android.uid.system`, 1000, is also `system_server`); decerter warns, because then every process of that UID is selected. On Linux there is no packages list, and `--package` fails with an error that points to `--uid` and `--pid`.

## TLS on Android
`decerter android tls --package <name>` on the device prints what decerter would hook for an app; setup runs it for its package.

```
$ adb shell /data/local/tmp/decerter android tls --package com.android.chrome
com.android.chrome: Chrome 124.0.6367.219 of com.google.android.trichromelibrary_636771938, BoringSSL offsets known, ssl_log_secret found through 7 key log labels in /data/app/…/com.google.android.trichromelibrary_636771938-…/TrichromeLibrary.apk!/lib/x86_64/libmonochrome_64.so
```

- **Conscrypt:** Java and Kotlin apps using the platform TLS stack go through Conscrypt's BoringSSL (`/apex/com.android.conscrypt/lib64/libssl.so`). decerter finds its internal `ssl_log_secret` through the library's MiniDebugInfo and picks the offsets by `ro.build.version.release`. A Conscrypt APEX whose layout drifted is caught by a version check in the BPF program and logged as one clear error.
- **Flutter:** `dart:io`'s TLS (`HttpClient`, `SecureSocket`, and the `http` and `dio` packages on top) runs in the BoringSSL linked into the app's stripped `libflutter.so`. decerter looks in the install directory `/data/app/…/<package>-…/` for an extracted `lib/<isa>/libflutter.so`, or the library stored uncompressed and page aligned in `base.apk` or a split APK (the Android Gradle plugin's default), where the uprobe goes on the APK at the library's offset. It finds `ssl_log_secret` without symbols through the code that loads its seven key log labels (`lea` on x86_64, `adrp`+`add` on arm64, also with outlined functions in between), and reads the Dart version the engine prints, which picks the BoringSSL offsets (Flutter 3.24.0 to 3.50.0 today: 38 Dart versions, 10 BoringSSL revisions). Tested with Flutter 3.35.7 and 3.50.0 on the x86_64 emulator; arm64 engines only by the unit tests.
- **Chrome, WebView and Cronet** link BoringSSL into one large stripped library, hooked with the same label search. decerter looks for the library of a selected package in its install directory (`libchrome.so`, `libmonochrome.so`, `libmonochrome_64.so`, `libwebviewchromium.so`, `libcronet.<version>.so`, extracted or stored in the APK), in the Trichrome library package of Chrome from Play (`com.google.android.trichromelibrary_<versionCode>`), and in the executable mappings of the selected UIDs' running processes (`/proc/<pid>/maps`, at start and every 2 s), which finds Cronet in system apps such as YouTube, the Cronet Play services loads from its data directory, and WebView inside an app. The version (`Chrome/<version>` in the library, the version in a Cronet library's name, or the APK's `versionName`) picks the offsets: every release branch from Chrome 124 to 160 with its patch ranges and a few listed builds. Tested with Chrome 124.0.6367.219 (Trichrome) and a ChromePublic 160.0.8161.0 snapshot; YouTube's Cronet 125.0.6383.0 is found and hooked; WebView in an app was not tested. The Mainline Cronet of the tethering APEX (`libmainlinecronet`, Android's `HttpEngine`) uses the APEX's `libssl.so` and is not hooked.
- Each library gets its own offsets in the BPF program, keyed by the uprobe's cookie. A uprobe is per file, so an app started after decerter is covered, and decerter looks for new install directories of the selected packages every 2 s, so an app installed or updated while decerter runs is hooked too. A library found only in a process's mappings is hooked once that process runs, so the sessions it opens before the next scan have no secrets: start the app after decerter, or start it again.
- An app whose version is not in the tables, whose library is compressed in the APK, or where the labels don't lead to one function, is logged as an error with the reason (for a version: the nearest known one and the `make` target that adds it, see [development](development.md#tls-offsets)); its TLS is relayed and captured without secrets. 32-bit apps and libraries are not hooked. Apps with another statically linked TLS library are relayed without secrets.
- An app's DNS is sent by netd as root, so it is not in the app's UID scope (`--uid 0` sees it).

### --block-quic
Chrome and Cronet use QUIC wherever the server offers it, and decerter doesn't decrypt QUIC. `run` and `capture` take `--block-quic`: a UDP `connect()` or `sendmsg()` to port 443 of a selected process fails with `EPERM` in the cgroup hook, before anything is sent and whatever the destination filters say, and Chrome and Cronet fall back to TLS over TCP. Other UDP and other processes are not touched. netd's cgroup hooks run next to decerter's and every one of them has to allow a socket call, so decerter's refusal is final there too. The same flag works on Linux.

## netd and restore
netd holds most cgroup hooks exclusively. Right before attaching, decerter queries each hook it needs; an exclusive one is written to a state file in `/data/local/tmp/decerter.d` and attached again in shared mode next to decerter's programs; the hook is empty for 36–104 µs in between. On exit, also on SIGHUP when the adb shell closes, decerter puts netd's hooks back as they were. After a `kill -9` they stay shared, and a netd restart then fails until they are exclusive again:

```sh
adb shell /data/local/tmp/decerter android restore
```

`restore` checks each program's name and tag (ids can be reused after a reboot) and is refused while another decerter runs. A decerter that starts over a leftover state file restores first by itself. A lock file keeps a second decerter out. On Linux an exclusive cgroup hook stops decerter with an error that names the program; sharing only happens on Android.

## By hand
Without `decerter android setup`, the same steps with adb:

```sh
adb root                    # the emulator's adbd as root; its su takes no -c, so decerter runs directly in adb shell
adb push decerter /data/local/tmp/decerter                  # decerter-arm64 for an arm64 device
adb shell pm list packages -U | grep chrome         # an app's uid for --uid, e.g. uid:10145

# run mode, stdout and the logs in the adb shell
adb shell /data/local/tmp/decerter run --package com.android.chrome --decrypt --block-quic

# live capture into tshark on the host; adb exec-out shares one pty for stdout and stderr, so the logs go to a file on the device
adb exec-out sh -c '/data/local/tmp/decerter capture --package com.android.chrome -w - 2>/data/local/tmp/decerter.log' | tshark -l -i - -Y 'http or http2'

# the control API and the UI on the workstation
adb shell /data/local/tmp/decerter run --package com.android.chrome --intercept --api-socket @decerter-api
adb forward tcp:8080 localabstract:decerter-api
./decerter ui --api-socket 127.0.0.1:8080

# capture mode with the API: captures and the live stream through the same forward
adb shell /data/local/tmp/decerter capture --package com.android.chrome --api-socket @decerter-api
curl -N http://127.0.0.1:8080/api/v1/captures/stream | tshark -l -i - -Y 'http or http2'

# after decerter was killed with SIGKILL: put netd's hooks back
adb shell /data/local/tmp/decerter android restore

# clean up
adb shell rm -rf /data/local/tmp/decerter /data/local/tmp/decerter.d
adb forward --remove tcp:8080
```

The binary and its data directory need different names. decerter on the device writes its state, the lock and capture files into `/data/local/tmp/decerter.d`. Through `adb forward` the API's abstract socket accepts root and adb's shell user (adbd connects as root after `adb root`).

## Real devices
A rooted arm64 phone with a GKI kernel android15-6.6 or newer should work the same way with `decerter-arm64`, but nothing of it was run: the arm64 build of every BPF object, the arm64 offsets and the `su` path of setup are untested, and `make generate-vmlinux-arm64` (the BTF header of an arm64 device, needed only to rebuild the BPF objects) was only tried against the x86_64 emulator. Treat it as experimental and check `decerter android tls --package <app>` first.
