# Full-system VM test for `module.nix`.
#
# Boots a NixOS guest with the module enabled next to a real MQTT broker and
# drives the daemon end to end: it authenticates to the broker, publishes Home
# Assistant discovery, and accepts a LOCK command over MQTT.
#
# The guest has no Bluetooth adapter, which is the interesting part rather than
# a limitation — the daemon is supposed to survive a radio it cannot use, and
# everything except the actuation itself is exercised. `scan_until_interrupt`
# logs the failure and retries, so a regression that made a missing adapter
# fatal would fail this test.
#
# Requires KVM and a Linux builder; see `module-eval.nix` for the check that
# runs anywhere.
{
  pkgs,
  ttlock,
  module,
  sampleLockData,
}:
let
  # Test fixtures. Both are written into the guest at runtime rather than
  # through the Nix store, mirroring how real deployments pass secrets — and
  # letting the test assert that the password never reaches the store.
  mqttUser = "ttlock-test";
  mqttPassword = "not-a-real-password";

  secretsDir = "/run/ttlock-test";
  passwordFile = "${secretsDir}/mosquitto-password";
  lockDataFile = "${secretsDir}/lockData.json";
  credentialsFile = "${secretsDir}/mqtt.env";

  mosquitto_sub = "${pkgs.mosquitto}/bin/mosquitto_sub";
in
pkgs.testers.runNixOSTest {
  name = "ttlock-module";

  nodes.machine =
    { lib, ... }:
    {
      imports = [ module ];

      services.ttlock = {
        enable = true;
        package = ttlock;
        inherit lockDataFile;
        mqtt = {
          host = "127.0.0.1";
          inherit credentialsFile;
        };
        # Short enough that the offline timeout fires during the test: with no
        # adapter no advertisement can ever arrive, so this must trip.
        offlineAfterSeconds = 5;
        logLevel = "ttlock=debug";
      };

      services.mosquitto = {
        enable = true;
        listeners = [
          {
            address = "127.0.0.1";
            port = 1883;
            users.${mqttUser} = {
              # A runtime path, so the plaintext password exists only inside the
              # booted guest. The store-hygiene assertions below depend on this.
              inherit passwordFile;
              acl = [ "readwrite #" ];
            };
          }
        ];
      };

      # Neither service may start before the test script has written the files
      # they read, so the test drives startup explicitly.
      systemd.services.ttlock.wantedBy = lib.mkForce [ ];
      systemd.services.mosquitto.wantedBy = lib.mkForce [ ];

      environment.systemPackages = [ pkgs.mosquitto ];
    };

  testScript = ''
    import json

    NODE = "ttlock_aa_bb_cc_dd_ee_ff"
    LOCK_DISCOVERY = f"homeassistant/lock/{NODE}/config"
    BATTERY_DISCOVERY = f"homeassistant/sensor/{NODE}_battery/config"
    BASE = f"ttlock/{NODE}"

    AUTH = "-h 127.0.0.1 -u ${mqttUser} -P ${mqttPassword}"


    def read_retained(topic, timeout=20):
        """Read one retained message, as Home Assistant would on startup."""
        return machine.succeed(
            f"timeout {timeout} mosquitto_sub {AUTH} -t '{topic}' -C 1"
        ).strip()


    def publish(topic, payload):
        machine.succeed(f"mosquitto_pub {AUTH} -t '{topic}' -m '{payload}'")


    with subtest("secrets are delivered out of the store, at runtime"):
        machine.wait_for_unit("multi-user.target")
        machine.succeed("mkdir -p ${secretsDir} && chmod 0700 ${secretsDir}")
        machine.succeed("printf '%s' '${mqttPassword}' > ${passwordFile}")
        machine.succeed(
            "printf 'TTLOCK_MQTT_USERNAME=%s\\nTTLOCK_MQTT_PASSWORD=%s\\n'"
            " '${mqttUser}' '${mqttPassword}' > ${credentialsFile}"
        )
        machine.succeed("chmod 0600 ${passwordFile} ${credentialsFile}")
        # The repository's own sample file, so a change that breaks it is caught
        # here rather than by the first person to follow the README.
        machine.succeed("cp ${sampleLockData} ${lockDataFile}")

    with subtest("the sandboxed unit starts and reaches the broker"):
        machine.systemctl("start mosquitto.service")
        machine.wait_for_unit("mosquitto.service")
        machine.wait_for_open_port(1883)

        # Record every availability message from before the daemon starts, so
        # the assertions below can say what was *never* published, not just what
        # the topic holds at the end.
        machine.succeed(
            "systemd-run --unit=availability-log --collect"
            f" ${mosquitto_sub} {AUTH} -t '{BASE}/availability'"
        )

        machine.systemctl("start ttlock.service")
        machine.wait_for_unit("ttlock.service")
        # Anonymous access is off, so connecting at all proves the credentials
        # travelled from the EnvironmentFile into the daemon.
        machine.wait_until_succeeds(
            "journalctl -u ttlock.service | grep -q 'connected to MQTT broker'", timeout=60
        )

    with subtest("Home Assistant discovery is published and retained"):
        config = json.loads(read_retained(LOCK_DISCOVERY))
        assert config["unique_id"] == NODE, config
        assert config["command_topic"] == f"{BASE}/set", config
        assert config["state_topic"] == f"{BASE}/state", config
        assert config["availability_topic"] == f"{BASE}/availability", config
        # `optimistic` is deliberately true, and it is not a retreat from
        # evidence-based reporting.
        #
        # It is the only lever the MQTT lock platform gives for `assumed_state`,
        # and without it the dashboard card offers only the action that
        # contradicts our reported state — so a lock opened by hand while we
        # believe it locked cannot be locked again. Since this firmware cannot
        # sense a manual unlock at all (section 7a of the design notes), the
        # state topic is always "last known" rather than ground truth, and
        # saying so is the honest setting.
        #
        # Setting it does not stop Home Assistant subscribing to `state_topic`;
        # that subscription is unconditional. The invariant this test exists to
        # protect — never publishing a bolt position or availability that was
        # not observed — is enforced by the daemon and checked by the subtests
        # below, not by this flag.
        assert config["optimistic"] is True, config
        assert config["state_locking"] == "LOCKING", config
        assert config["state_unlocking"] == "UNLOCKING", config

        battery = json.loads(read_retained(BATTERY_DISCOVERY))
        assert battery["device_class"] == "battery", battery
        assert battery["state_topic"] == f"{BASE}/battery", battery
        # Both entities must land on one HA device.
        assert battery["device"]["identifiers"] == config["device"]["identifiers"]

    with subtest("availability is never claimed without evidence"):
        # This guest has no Bluetooth adapter, so the lock has never once been
        # heard from. The only honest thing to publish is `offline`.
        #
        # The daemon used to publish a retained `online` on every broker
        # connection, which is a guess dressed up as a fact — and because the
        # worker then suppressed its own correction as a no-change, that guess
        # became permanent. An earlier version of this test waited for `online`
        # here and so asserted the bug. Wait for `offline` and forbid `online`.
        machine.wait_until_succeeds(
            "journalctl -u availability-log | grep -qw offline", timeout=60
        )
        machine.fail("journalctl -u availability-log | grep -qw online")
        assert read_retained(f"{BASE}/availability") == "offline"

    with subtest("a command from MQTT reaches the Bluetooth worker"):
        publish(f"{BASE}/set", "LOCK")
        # Only the in-progress state may be published: the lock has not
        # acknowledged anything, and with no adapter it never will.
        machine.wait_until_succeeds(
            f"test \"$(timeout 10 mosquitto_sub {AUTH} -t '{BASE}/state' -C 1)\" = LOCKING",
            timeout=60,
        )
        assert read_retained(f"{BASE}/state") == "LOCKING"

    with subtest("a missing Bluetooth adapter is survivable, not fatal"):
        # A scan that cannot start must not stop the daemon doing the things
        # that need no radio: serving MQTT and expiring availability. It also
        # must not wedge — the LOCK above was accepted while scans were failing.
        machine.wait_until_succeeds(
            "journalctl -u ttlock.service | grep -q 'BLE scan failed'", timeout=60
        )
        machine.require_unit_state("ttlock.service", "active")

    with subtest("a broker reconnect republishes the truth, not an assumption"):
        # Regression test. `announce()` used to publish a retained "online" on
        # every ConnAck while the worker suppressed its own republish because
        # its cached value had not changed — so after any broker blip while the
        # lock was silent, MQTT retained "online" forever and nothing corrected
        # it. Availability is already "offline" here from the subtest above.
        assert read_retained(f"{BASE}/availability") == "offline"

        # Count first: the daemon already republished once on its initial
        # connect, so a bare "did it republish" check would pass without the
        # reconnect happening at all.
        republishes = int(
            machine.succeed(
                "journalctl -u ttlock.service"
                " | grep -c 'republishing current state'"
            ).strip()
        )

        machine.systemctl("restart mosquitto.service")
        machine.wait_for_unit("mosquitto.service")
        machine.wait_for_open_port(1883)
        # The daemon reconnects on its own; wait for it rather than for a fixed
        # delay, so a slow VM does not make this flaky.
        machine.wait_until_succeeds(
            "test \"$(journalctl -u ttlock.service"
            f" | grep -c 'republishing current state')\" -ge {republishes + 1}",
            timeout=90,
        )

        # The lock is still silent, so the reconnect must not have invented an
        # `online`. This is the assertion the bug would fail.
        machine.fail("journalctl -u availability-log | grep -qw online")
        assert read_retained(f"{BASE}/availability") == "offline"

    with subtest("the broker password stays out of the store and off the command line"):
        machine.fail("systemctl cat ttlock.service | grep -q ${mqttPassword}")
        machine.fail("grep -Rq ${mqttPassword} /etc/systemd/system/ 2>/dev/null")
        pid = machine.succeed("systemctl show ttlock.service -p MainPID --value").strip()
        machine.fail(f"tr '\\0' '\\n' < /proc/{pid}/cmdline | grep -q ${mqttPassword}")
        # ...while the lockData path is passed by reference, as intended.
        machine.succeed(
            f"tr '\\0' '\\n' < /proc/{pid}/cmdline | grep -qx -- ${lockDataFile}"
        )

    with subtest("the systemd hardening survived contact with reality"):
        for prop, want in [
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("ProtectKernelModules", "yes"),
            ("LockPersonality", "yes"),
            ("MemoryDenyWriteExecute", "yes"),
            ("RestrictRealtime", "yes"),
        ]:
            got = machine.succeed(
                f"systemctl show ttlock.service -p {prop} --value"
            ).strip()
            assert got == want, f"{prop}: expected {want}, got {got}"

    with subtest("a daemon restart re-announces discovery"):
        # Count first: the broker restart above already produced a reconnect, so
        # a fixed threshold here would pass without the daemon restarting at all.
        before = int(
            machine.succeed(
                "journalctl -u ttlock.service | grep -c 'connected to MQTT broker'"
            ).strip()
        )
        machine.systemctl("restart ttlock.service")
        machine.wait_for_unit("ttlock.service")
        machine.wait_until_succeeds(
            "test \"$(journalctl -u ttlock.service"
            f" | grep -c 'connected to MQTT broker')\" -ge {before + 1}",
            timeout=60,
        )
        json.loads(read_retained(LOCK_DISCOVERY))
  '';
}
