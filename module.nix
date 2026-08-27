# NixOS module running the `ttlock daemon` MQTT bridge.
#
# Every secret is referenced by path and read at runtime, never interpolated
# into a derivation: anything in the Nix store is world-readable, so lock
# credentials and broker passwords must stay out of it. Both options below are
# designed to take a sops-nix `config.sops.secrets.<name>.path` directly.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.ttlock;
in
{
  options.services.ttlock = {
    enable = lib.mkEnableOption "the TTLock BLE to MQTT bridge";

    package = lib.mkOption {
      type = lib.types.package;
      default = (import ./packages.nix { inherit pkgs; }).ttlock;
      defaultText = lib.literalExpression "ttlock-rs.packages.\${system}.ttlock";
      description = "The ttlock package providing the `ttlock` binary.";
    };

    lockDataFile = lib.mkOption {
      type = lib.types.path;
      example = "/run/secrets/ttlock-lockdata";
      description = ''
        Path to `lockData.json`, holding the lock's AES key and unlock key.

        Must be an out-of-store path — a sops-nix secret path, or any file
        readable by the service user. Putting this in the Nix store would make
        the credentials that open your door world-readable.
      '';
    };

    address = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "AA:BB:CC:DD:EE:FF";
      description = ''
        BLE address of the lock. When null, the daemon takes the address from
        {option}`lockDataFile`, which is usually what you want.
      '';
    };

    mqtt = {
      host = lib.mkOption {
        type = lib.types.str;
        default = "localhost";
        description = "MQTT broker hostname.";
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 1883;
        description = "MQTT broker port.";
      };

      credentialsFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        example = "/run/secrets/ttlock-mqtt";
        description = ''
          Path to an EnvironmentFile holding broker credentials, e.g.

          ```
          TTLOCK_MQTT_USERNAME=homeassistant
          TTLOCK_MQTT_PASSWORD=hunter2
          ```

          Read by systemd at start, so the password never reaches the store or
          the process command line (where any user could read it from `ps`).
        '';
      };
    };

    discoveryPrefix = lib.mkOption {
      type = lib.types.str;
      default = "homeassistant";
      description = "Home Assistant MQTT discovery prefix.";
    };

    baseTopic = lib.mkOption {
      type = lib.types.str;
      default = "ttlock";
      description = "Base topic for this lock's state/command/availability topics.";
    };

    offlineAfterSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 120;
      description = "Seconds without an advertisement before the lock is marked offline.";
    };

    connectAttempts = lib.mkOption {
      type = lib.types.ints.positive;
      default = 6;
      description = ''
        Scan-and-connect attempts per command. Weak links commonly fail the
        first few attempts and then succeed; raise this if commands fail.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "ttlock=info";
      example = "ttlock=debug";
      description = "Value for `RUST_LOG`.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra arguments appended to the `ttlock daemon` invocation.";
    };
  };

  config = lib.mkIf cfg.enable {
    # The daemon talks to BlueZ over D-Bus and needs a running adapter.
    hardware.bluetooth.enable = lib.mkDefault true;

    systemd.services.ttlock = {
      description = "TTLock BLE to MQTT bridge";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network-online.target"
        "bluetooth.target"
      ];
      wants = [ "network-online.target" ];
      requires = [ "bluetooth.target" ];

      environment.RUST_LOG = cfg.logLevel;

      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe cfg.package)
            "daemon"
            "--file"
            cfg.lockDataFile
            "--mqtt-host"
            cfg.mqtt.host
            "--mqtt-port"
            (toString cfg.mqtt.port)
            "--discovery-prefix"
            cfg.discoveryPrefix
            "--base-topic"
            cfg.baseTopic
            "--offline-after-seconds"
            (toString cfg.offlineAfterSeconds)
            "--connect-attempts"
            (toString cfg.connectAttempts)
          ]
          ++ lib.optionals (cfg.address != null) [
            "--address"
            cfg.address
          ]
          ++ cfg.extraArgs
        );

        EnvironmentFile = lib.optional (cfg.mqtt.credentialsFile != null) cfg.mqtt.credentialsFile;

        Restart = "always";
        RestartSec = 5;

        # BlueZ denies D-Bus access to unprivileged callers by default, so this
        # runs as root. The hardening below is what keeps that reasonable:
        # everything not needed to reach D-Bus and the network is taken away.
        DynamicUser = false;
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateMounts = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_BLUETOOTH"
        ];
        CapabilityBoundingSet = [ "" ];
        AmbientCapabilities = [ "" ];
        DeviceAllow = [ "" ];
      };
    };
  };
}
