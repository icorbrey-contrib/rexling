{
  description = "Rexling, an unofficial Android client for Rex";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Keep in step with rexling-core/native/ghostty-source.json; nix/default.nix checks the revision.
    ghostty = {
      url = "github:ghostty-org/ghostty/108cacb17ed8990840cd14abfce43d8ed8503ca1";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      ghostty,
    }:
    let
      lib = nixpkgs.lib;
      # The Android NDK runs only on x86_64 Linux and on macOS.
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      rexlingFor =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
            config = {
              android_sdk.accept_license = true;
              # The Android SDK components are the only unfree software in the build.
              allowUnfreePredicate =
                pkg:
                lib.hasPrefix "android-sdk-" (lib.getName pkg)
                || builtins.elem (lib.getName pkg) [
                  "androidsdk"
                  "build-tools"
                  "cmdline-tools"
                  "ndk"
                  "platform-tools"
                  "platforms"
                  "tools"
                ];
            };
          };
        in
        pkgs.callPackage ./nix {
          ghosttySrc = ghostty;
          revision = self.shortRev or self.dirtyShortRev or "unknown";
          sourceDateEpoch = self.lastModified;
        };
    in
    {
      packages = lib.genAttrs systems (
        system:
        let
          rexling = rexlingFor system;
        in
        {
          inherit (rexling)
            libghostty-vt
            rexling-network
            rexling-jni
            rexling-apk
            ;
          default = rexling.rexling-apk;
        }
      );
      devShells = lib.genAttrs systems (system: {
        default = (rexlingFor system).devShell;
      });
    };
}
