# The Go SSH and Tailscale library, built like rexling-core/scripts/build_native.py does.
{
  lib,
  buildGoModule,
  ndkClang,
}:
buildGoModule {
  pname = "rexling-network";
  version = "0";
  src = lib.fileset.toSource {
    root = ../rexling-network;
    fileset = ../rexling-network;
  };
  # Keep a module cache instead of a vendor directory, so the build runs with -mod=readonly as the helper does.
  proxyVendor = true;
  vendorHash = "sha256-/RZ8O+9MeN8SfT3gabWXqXH69eR972yUdmMSAn1PZnA=";

  buildPhase = ''
    runHook preBuild
    export GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=${ndkClang} CGO_LDFLAGS="-Wl,-z,max-page-size=16384"
    go build -mod=readonly -trimpath -buildmode=c-shared -ldflags="-s -w" -o librex_network.so .
    runHook postBuild
  '';
  doCheck = false;
  # Host strip tools do not handle Android binaries; AGP strips them with the NDK.
  dontStrip = true;
  installPhase = ''
    runHook preInstall
    install -Dm444 librex_network.so $out/lib/librex_network.so
    runHook postInstall
  '';
}
