# The unsigned arm64-v8a release APK, built offline from the prebuilt native libraries.
{
  lib,
  stdenv,
  gradle,
  jdk,
  androidSdk,
  jniLibs,
  revision,
  sourceDateEpoch,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "rexling-apk";
  version = revision;
  src = lib.fileset.toSource {
    root = ../rexling-android;
    fileset = ../rexling-android;
  };

  nativeBuildInputs = [
    gradle
    jdk
  ];

  # Regenerate with: $(nix build --no-link --print-out-paths .#rexling-apk.mitmCache.updateScript)
  mitmCache = gradle.fetchDeps {
    pkg = finalAttrs.finalPackage;
    data = ./gradle-deps.json;
  };

  env = {
    ANDROID_HOME = androidSdk;
    JAVA_HOME = jdk.home;
    REXLING_GIT_REVISION = revision;
    SOURCE_DATE_EPOCH = toString sourceDateEpoch;
  };

  gradleFlags = [
    "-Prexling.prebuiltJniLibs=${jniLibs}"
    "-Prexling.unsignedRelease=true"
    # The SDK's aapt2 runs on this host; the one AGP downloads from Maven is not in the dependency lock.
    "-Pandroid.aapt2FromMavenOverride=${androidSdk}/build-tools/36.0.0/aapt2"
    # A Kotlin daemon would outlive the build and keep state outside it.
    "-Pkotlin.compiler.execution.strategy=in-process"
  ];
  gradleBuildTask = ":app:assembleRelease";
  # Record exactly what the release build downloads; resolving every configuration fails on the benchmark module.
  gradleUpdateTask = finalAttrs.gradleBuildTask;

  # Nix on macOS builds without a sandbox, and the dependency update runs as the user. Java
  # takes user.home from the account database rather than HOME, so AGP and Gradle workers
  # would otherwise write to the real ~/.android.
  preConfigure = ''
    export HOME="$(mktemp -d)"
    export ANDROID_USER_HOME="$HOME/.android"
    export JAVA_TOOL_OPTIONS="-Duser.home=$HOME"
  '';

  installPhase = ''
    runHook preInstall
    install -Dm444 app/build/outputs/apk/release/app-release-unsigned.apk \
      $out/rexling-arm64-release-unsigned.apk
    runHook postInstall
  '';

  passthru = { inherit jniLibs; };
})
