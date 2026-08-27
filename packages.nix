# Every package this repo provides, as a plain function of `pkgs`.
#
# Kept separate from flake.nix so non-flake users get the same derivations:
#
#   (import (fetchTarball "https://github.com/n8henrie/ttlock-rs/archive/main.tar.gz")
#     + "/packages.nix") { pkgs = import <nixpkgs> { }; }
#
# The version comes from the Cargo workspace so the CLI, the Python wheel and
# the Home Assistant component can never drift apart.
{
  pkgs ? import <nixpkgs> { },
}:
let
  inherit (pkgs) lib;
  version = (lib.importTOML ./Cargo.toml).workspace.package.version;
in
lib.makeScope pkgs.newScope (
  self:
  {
    inherit version;

    # The `ttlock` CLI, including the MQTT `daemon` subcommand.
    ttlock = self.callPackage ./nix/ttlock.nix { };

    # `ttlock` for Python, built against the default interpreter.
    ttlock-python = pkgs.python3Packages.callPackage ./nix/ttlock-python.nix { inherit version; };

    default = self.ttlock;
  }
  # The Home Assistant custom component exists only where Home Assistant itself
  # is packaged, which is Linux. Defining it unconditionally makes the whole
  # attrset fail to evaluate on darwin, including for people who only want the
  # CLI.
  // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
    # Its `ttlock` dependency must be built against Home Assistant's own
    # Python, not the default interpreter, or the extension module will not
    # import inside the Home Assistant environment.
    ttlock-ble-component = self.callPackage ./nix/ttlock-ble-component.nix {
      ttlock-python = pkgs.home-assistant.python3Packages.callPackage ./nix/ttlock-python.nix {
        inherit version;
      };
    };
  }
)
