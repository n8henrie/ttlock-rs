{
  description = "Control TTLock Bluetooth locks: Rust CLI, MQTT bridge, Python bindings, and a Home Assistant component";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      eachSystem =
        with nixpkgs.lib;
        f: foldAttrs mergeAttrs { } (map (s: mapAttrs (_: v: { ${s} = v; }) (f s)) systems);
    in
    {
      # System-independent outputs. The packages themselves live in
      # packages.nix so non-flake users get exactly the same derivations.
      nixosModules.ttlock = ./module.nix;
      nixosModules.default = self.nixosModules.ttlock;

      overlays.default =
        final: _prev:
        let
          ours = import ./packages.nix { pkgs = final; };
        in
        {
          inherit (ours) ttlock ttlock-python;
        }
        // final.lib.optionalAttrs final.stdenv.hostPlatform.isLinux {
          inherit (ours) ttlock-ble-component;
        };
    }
    // eachSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        ours = import ./packages.nix { inherit pkgs; };
      in
      {
        packages = {
          inherit (ours) ttlock ttlock-python default;
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          inherit (ours) ttlock-ble-component;
        };

        # `nix run github:n8henrie/ttlock-rs -- scan`
        apps.default = {
          type = "app";
          program = pkgs.lib.getExe ours.ttlock;
        };

        # `nix flake check` builds the packages and runs the same Nix linters CI
        # runs, so a green local check means a green CI.
        checks = {
          inherit (ours) ttlock ttlock-python;

          # Evaluates module.nix into two complete NixOS systems and asserts on
          # the unit it produces. Pure evaluation, so it runs on darwin too —
          # unlike `nixos-module` below, which needs KVM and a Linux builder.
          module-eval = import ./nix/checks/module-eval.nix {
            inherit pkgs;
            inherit (pkgs) lib;
            inherit (nixpkgs.lib) nixosSystem;
            module = ./module.nix;
          };

          # Static type check for the Home Assistant component.
          #
          # `ruff` cannot see attribute typos on our own classes; a type checker
          # can. A stale `self._lock_version` shipped once, was classified as a
          # retryable BLE error by `bleak-retry-connector` (which lists
          # `AttributeError`), retried four times, and surfaced as a connection
          # failure rather than the bug it was.
          #
          # Neither Home Assistant nor `ttlock` is in the closure, so
          # `unresolved-import` is ignored and both resolve to Unknown. That is
          # deliberate: `ttlock` is a compiled extension with no `.pyi`, so
          # putting it on the path makes every binding member look missing
          # rather than checking anything. Our own types are still checked,
          # which is the point. (A stub for the bindings would let this go
          # further — worth doing, but it is another surface to keep in step.)
          types =
            pkgs.runCommand "ttlock-component-types"
              {
                nativeBuildInputs = [ pkgs.ty ];
                src = pkgs.lib.cleanSource ./.;
              }
              ''
                cd "$src"
                ty check --ignore unresolved-import custom_components/ttlock_ble
                touch "$out"
              '';

          lint =
            pkgs.runCommand "ttlock-nix-lint"
              {
                nativeBuildInputs = with pkgs; [
                  statix
                  deadnix
                  nixfmt
                ];
                src = pkgs.lib.cleanSource ./.;
              }
              ''
                cd "$src"
                statix check .
                deadnix --fail .
                nixfmt --check .
                touch "$out"
              '';
        }
        # Boots the module in a VM against a real MQTT broker. NixOS VM tests
        # are Linux-only, so this is absent on darwin rather than failing there.
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          nixos-module = import ./nix/checks/nixos-test.nix {
            inherit pkgs;
            inherit (ours) ttlock;
            module = ./module.nix;
            sampleLockData = ./sample-lockData.json;
          };
        };

        # Used only for `cargo publish --workspace`.
        #
        # Deliberately does NOT use `inputsFrom = [ ours.ttlock ]` like the
        # default shell: that pulls in nixpkgs' `auditable-cargo`, which shadows
        # plain `cargo` on PATH. `cargo publish --workspace` verifies `ttlock`
        # against the not-yet-published `ttlock-core` by unpacking it into a
        # temporary registry under target/package, and auditable-cargo's
        # `cargo metadata` subprocess does not inherit that override — so it
        # fails to resolve `ttlock-core` and the publish dies at the verify step.
        devShells.release = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cargo
            rustc
            pkg-config
          ];
          buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.dbus ];
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ ours.ttlock ];
          buildInputs = with pkgs; [
            bacon
            cargo
            clippy
            deadnix
            maturin
            nixfmt
            ruff
            rust-analyzer
            rustfmt
            statix
            # Catches attribute typos on our own classes, which `ruff` cannot.
            ty
            (python312.withPackages (ps: [
              ps.pycryptodome
              ps.pytest
            ]))
          ];
        };
      }
    );
}
