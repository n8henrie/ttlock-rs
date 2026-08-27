# Pure-evaluation check for `module.nix`.
#
# Builds two complete NixOS systems around the module and asserts on the unit
# it produces. Nothing here boots, so it needs neither KVM nor a Linux host —
# this is the module check a macOS developer can actually run, and it is where
# a renamed CLI flag or a secret drifting into the store gets caught.
#
# It cannot catch anything that only appears once the daemon runs; that is what
# `nixos-test.nix` next door is for.
{
  pkgs,
  lib,
  nixosSystem,
  module,
}:
let
  # Deliberately out-of-store paths, exactly as the module documents.
  lockDataFile = "/run/secrets/ttlock-lockdata";
  credentialsFile = "/run/secrets/ttlock-mqtt";

  baseModule = {
    nixpkgs.hostPlatform = "x86_64-linux";
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "/dev/vda1";
      fsType = "ext4";
    };
    system.stateVersion = "25.05";
  };

  # Every option set to a non-default value, so a flag that stops being wired
  # through shows up as a missing string rather than as a silent default.
  configured = nixosSystem {
    modules = [
      module
      baseModule
      {
        services.ttlock = {
          enable = true;
          inherit lockDataFile;
          address = "AA:BB:CC:DD:EE:FF";
          mqtt = {
            host = "broker.example";
            port = 8883;
            inherit credentialsFile;
          };
          discoveryPrefix = "ha-discovery";
          baseTopic = "locks/front";
          offlineAfterSeconds = 45;
          connectAttempts = 9;
          logLevel = "ttlock=debug";
          extraArgs = [ "-v" ];
        };
      }
    ];
  };

  # The other half of every `lib.optional` in the module: no address, no broker
  # credentials, no extra arguments.
  minimal = nixosSystem {
    modules = [
      module
      baseModule
      {
        services.ttlock = {
          enable = true;
          inherit lockDataFile;
        };
      }
    ];
  };

  # String context is discarded so this derivation only inspects the *text* of
  # the unit. Keeping it would make a darwin evaluation try to build the
  # x86_64-linux ttlock package just to read its path.
  text = builtins.unsafeDiscardStringContext;
  unitOf = machine: machine.config.systemd.services.ttlock;
  execStartOf = machine: text (unitOf machine).serviceConfig.ExecStart;

  execStart = execStartOf configured;
  minimalExecStart = execStartOf minimal;
  # Named for what it is rather than matching the attribute, so `statix` does
  # not read it as an `inherit` waiting to happen.
  sandbox = (unitOf configured).serviceConfig;

  # Assert on the flag and its value *together*, so a value that drifts onto
  # the wrong flag fails — matching a bare `9` anywhere in the command line
  # would prove nothing. Escaped the same way the module builds it, since
  # `lib.escapeShellArgs` quotes only the arguments that need it.
  hasArg =
    haystack: flag: value:
    lib.hasInfix (lib.escapeShellArgs [
      flag
      (builtins.toString value)
    ]) haystack;

  checks = [
    {
      name = "the configured system instantiates as a whole";
      ok = lib.hasSuffix ".drv" (text configured.config.system.build.toplevel.drvPath);
    }
    {
      name = "the minimal system instantiates as a whole";
      ok = lib.hasSuffix ".drv" (text minimal.config.system.build.toplevel.drvPath);
    }
    {
      name = "ExecStart runs the ttlock binary's daemon subcommand";
      ok = lib.hasInfix "/bin/ttlock daemon " execStart;
    }
    {
      name = "lockData is passed by out-of-store path";
      ok = hasArg execStart "--file" lockDataFile;
    }
    {
      name = "the lock address is passed when set";
      ok = hasArg execStart "--address" "AA:BB:CC:DD:EE:FF";
    }
    {
      name = "--address is omitted when unset";
      ok = !(lib.hasInfix "--address" minimalExecStart);
    }
    {
      name = "broker host and port are wired through";
      ok = hasArg execStart "--mqtt-host" "broker.example" && hasArg execStart "--mqtt-port" 8883;
    }
    {
      name = "topic options are wired through";
      ok =
        hasArg execStart "--discovery-prefix" "ha-discovery"
        && hasArg execStart "--base-topic" "locks/front";
    }
    {
      name = "tuning options are wired through";
      ok = hasArg execStart "--offline-after-seconds" 45 && hasArg execStart "--connect-attempts" 9;
    }
    {
      name = "extraArgs are appended";
      ok = lib.hasSuffix " -v" execStart;
    }
    {
      name = "RUST_LOG comes from logLevel";
      ok = (unitOf configured).environment.RUST_LOG == "ttlock=debug";
    }
    # The whole point of `credentialsFile`: the broker password reaches the
    # daemon through systemd, never through a command line that any local user
    # could read out of `ps`.
    {
      name = "broker credentials arrive via EnvironmentFile";
      ok = map text sandbox.EnvironmentFile == [ credentialsFile ];
    }
    {
      name = "no password ever appears on the command line";
      ok = !(lib.hasInfix "--mqtt-password" execStart) && !(lib.hasInfix "--mqtt-username" execStart);
    }
    {
      name = "EnvironmentFile is omitted when no credentials are configured";
      ok = (unitOf minimal).serviceConfig.EnvironmentFile == [ ];
    }
    {
      name = "the unit keeps its sandbox";
      ok =
        sandbox.ProtectSystem == "strict"
        && sandbox.NoNewPrivileges
        && sandbox.ProtectHome
        && sandbox.CapabilityBoundingSet == [ "" ];
    }
    {
      name = "AF_BLUETOOTH stays reachable through the sandbox";
      ok = lib.elem "AF_BLUETOOTH" sandbox.RestrictAddressFamilies;
    }
    {
      name = "enabling the service enables Bluetooth";
      ok = configured.config.hardware.bluetooth.enable;
    }
  ];

  failures = lib.filter (check: !check.ok) checks;
in
if failures != [ ] then
  throw ''
    module.nix evaluation check failed:
    ${lib.concatMapStringsSep "\n" (check: "  - ${check.name}") failures}

    ExecStart was:
      ${execStart}
  ''
else
  pkgs.runCommand "ttlock-module-eval" { } ''
    cat > "$out" <<'EOF'
    ${lib.concatMapStringsSep "\n" (check: "ok: ${check.name}") checks}
    EOF
  ''
