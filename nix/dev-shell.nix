# The pinned toolchains on PATH, for the scripts and Gradle commands in BUILDING.md.
{
  mkShell,
  runCommand,
  go,
  zig_0_17,
  python3,
  curl,
  rustToolchain,
  jdk,
  androidSdk,
  androidNdk,
}:
let
  # The scripts expect sdkmanager's layout, which names the command-line tools "latest".
  sdk = runCommand "android-sdk-dev-shell" { } ''
    mkdir -p $out/cmdline-tools
    for entry in ${androidSdk}/*; do
      [ "$(basename "$entry")" = cmdline-tools ] || ln -s "$entry" $out/
    done
    ln -s ${androidSdk}/cmdline-tools/* $out/cmdline-tools/latest
  '';
in
mkShell {
  packages = [
    rustToolchain
    go
    zig_0_17
    python3
    curl
    jdk
  ];
  env = {
    ANDROID_HOME = "${sdk}";
    ANDROID_NDK_HOME = androidNdk;
    JAVA_HOME = jdk.home;
    # go.mod's minimum is met by this Go; never download another toolchain.
    GOTOOLCHAIN = "local";
  };
  shellHook = ''
    export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
  '';
}
