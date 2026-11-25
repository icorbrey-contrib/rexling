# libghostty-vt for Android arm64, built like rexling-core/scripts/build_native.py does.
{
  stdenv,
  callPackage,
  zig_0_17,
  ghosttySrc,
  androidNdk,
  androidApi,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "libghostty-vt-android-arm64";
  version = builtins.substring 0 10 ghosttySrc.rev;
  src = ghosttySrc;

  # Ghostty generates this lock of its Zig packages from build.zig.zon.
  deps = callPackage "${ghosttySrc}/deps/packages.nix" { };

  nativeBuildInputs = [ zig_0_17 ];
  dontSetZigDefaultFlags = true;
  zigBuildFlags = [
    "--system"
    "${finalAttrs.deps}"
    "-Demit-lib-vt"
    "-Demit-macos-app=false"
    "-Demit-xcframework=false"
    "-Doptimize=ReleaseFast"
    "-Dtarget=aarch64-linux-android.${toString androidApi}"
  ];
  # Ghostty finds the Android libc headers and CRT objects through this variable.
  env.ANDROID_NDK_HOME = androidNdk;
  # The install step builds everything; a separate build step would compile it twice.
  dontBuild = true;
  doCheck = false;
  # The host's strip rewrites Android archives into a format the linker cannot read.
  dontStrip = true;
})
