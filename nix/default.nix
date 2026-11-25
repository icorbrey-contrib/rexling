# Toolchains and build steps for the arm64 Android APK, shared by the packages and the development shell.
{
  lib,
  stdenv,
  newScope,
  androidenv,
  gradle-packages,
  jdk25,
  rust-bin,
  ghosttySrc,
  revision,
  sourceDateEpoch,
}:
let
  ghosttyManifest = lib.importJSON ../rexling-core/native/ghostty-source.json;
  gradleWrapper = builtins.listToAttrs (
    map (line: {
      name = builtins.head line;
      value = builtins.elemAt line 1;
    }) (builtins.filter (x: x != null) (map (builtins.match "([^=]+)=(.*)") (lib.splitString "\n" (builtins.readFile ../rexling-android/gradle/wrapper/gradle-wrapper.properties))))
  );
in
assert lib.assertMsg (ghosttySrc.rev == ghosttyManifest.revision)
  "flake input ghostty (${ghosttySrc.rev}) must match rexling-core/native/ghostty-source.json (${ghosttyManifest.revision})";
lib.makeScope newScope (self: {
  inherit ghosttySrc ghosttyManifest revision sourceDateEpoch;

  androidComposition = androidenv.composeAndroidPackages {
    platformVersions = [ "37.0" ];
    buildToolsVersions = [ "36.0.0" ];
    includeNDK = true;
    ndkVersions = [ ghosttyManifest.android_ndk_version ];
    includeEmulator = false;
    includeSystemImages = false;
    includeSources = false;
    includeCmake = false;
  };
  androidSdk = "${self.androidComposition.androidsdk}/libexec/android-sdk";
  androidNdk = "${self.androidSdk}/ndk/${ghosttyManifest.android_ndk_version}";
  # The NDK ships one x86_64 build per host OS; Apple silicon runs the universal Darwin binaries.
  ndkToolchain = "${self.androidNdk}/toolchains/llvm/prebuilt/${
    if stdenv.hostPlatform.isDarwin then "darwin-x86_64" else "linux-x86_64"
  }";
  androidApi = ghosttyManifest.android_api;
  ndkClang = "${self.ndkToolchain}/bin/aarch64-linux-android${toString self.androidApi}-clang";

  # The same Gradle release and checksum as the wrapper, so Nix and ./gradlew build alike.
  gradle =
    (gradle-packages.mkGradle {
      version = lib.removeSuffix "-bin.zip" (lib.last (lib.splitString "gradle-" gradleWrapper.distributionUrl));
      hash = "sha256:${gradleWrapper.distributionSha256Sum}";
      defaultJava = jdk25;
    }).wrapped;
  jdk = jdk25;

  rustToolchain = rust-bin.stable.latest.default.override {
    targets = [ "aarch64-linux-android" ];
  };

  libghostty-vt = self.callPackage ./libghostty-vt.nix { };
  rexling-network = self.callPackage ./rexling-network.nix { };
  rexling-jni = self.callPackage ./rexling-jni.nix { };
  jniLibs = self.callPackage ./jni-libs.nix { };
  rexling-apk = self.callPackage ./rexling-apk.nix { };
  devShell = self.callPackage ./dev-shell.nix { };
})
