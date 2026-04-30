{
  description = "swaylock - screen locker for Wayland";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          # Override linux-pam to use /sbin/unix_chkpwd (the path on
          # Debian/Ubuntu systems) instead of the NixOS-specific wrapper
          # at /run/wrappers/bin/unix_chkpwd that is baked into the
          # Nixpkgs linux-pam build via its postPatch.
          linux-pam-sbindir = pkgs.linux-pam.overrideAttrs (_old: {
            postPatch = ''
              substituteInPlace modules/module-meson.build \
                --replace-fail "sbindir / 'unix_chkpwd'" "'/sbin/unix_chkpwd'"
            '';
          });
        in
        {
          default = pkgs.mkShell {
            hardeningDisable = [ "fortify" ];

            nativeBuildInputs = with pkgs; [
              meson
              ninja
              pkg-config
              wayland-scanner
              scdoc
              git
              clang-tools
            ];

            buildInputs = with pkgs; [
              wayland
              wayland-protocols
              libxkbcommon
              cairo
              gdk-pixbuf
              linux-pam-sbindir
              cjson
              qrencode
            ];
          };
        }
      );
    };
}
