# The Rust JNI library, built like rexling-core/scripts/build_native.py does.
{
  lib,
  stdenv,
  libiconv,
  rustPlatform,
  rustToolchain,
  libghostty-vt,
  rexling-network,
  ndkClang,
  ndkToolchain,
}:
stdenv.mkDerivation {
  pname = "rexling-jni-android-arm64";
  version = "0";
  src = lib.fileset.toSource {
    root = ../rexling-core;
    fileset = ../rexling-core;
  };
  cargoDeps = rustPlatform.importCargoLock { lockFile = ../rexling-core/Cargo.lock; };

  nativeBuildInputs = [
    rustToolchain
    rustPlatform.cargoSetupHook
  ];
  # Host build scripts link against libiconv on Darwin.
  buildInputs = lib.optional stdenv.hostPlatform.isDarwin libiconv;

  env = {
    CC_aarch64_linux_android = ndkClang;
    CXX_aarch64_linux_android = "${ndkClang}++";
    AR_aarch64_linux_android = "${ndkToolchain}/bin/llvm-ar";
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = ndkClang;
    CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS = "-C link-arg=-Wl,-z,max-page-size=16384";
    GHOSTTY_PREFIX = "${libghostty-vt}";
    REXLING_NETWORK_PREFIX = "${rexling-network}/lib";
  };

  # Host strip tools do not handle Android binaries; AGP strips them with the NDK.
  dontStrip = true;

  buildPhase = ''
    runHook preBuild
    export CARGO_HOME=$TMPDIR/cargo-home CARGO_TARGET_DIR=$TMPDIR/target
    cargo build --offline --locked --release --target aarch64-linux-android -p rexling-jni
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    install -Dm444 $CARGO_TARGET_DIR/aarch64-linux-android/release/librex_android.so $out/lib/librex_android.so
    runHook postInstall
  '';
}
