# The arm64-v8a directory that Gradle packages, with the same three libraries the native helper copies.
{
  runCommand,
  rexling-jni,
  rexling-network,
  ndkToolchain,
}:
runCommand "rexling-jni-libs" { } ''
  mkdir -p $out/arm64-v8a
  cp ${rexling-jni}/lib/librex_android.so ${rexling-network}/lib/librex_network.so \
    ${ndkToolchain}/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so $out/arm64-v8a/
''
