{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  dbus,
  version,
}:
rustPlatform.buildRustPackage {
  pname = "ttlock";
  inherit version;
  src = lib.cleanSource ../.;
  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "--package"
    "ttlock"
  ];

  nativeBuildInputs = [ pkg-config ];
  # BlueZ (and so D-Bus) is the Linux BLE backend; macOS uses CoreBluetooth.
  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [ dbus ];

  meta = {
    description = "Command-line control for TTLock Bluetooth locks";
    homepage = "https://github.com/n8henrie/ttlock-rs";
    license = lib.licenses.mit;
    mainProgram = "ttlock";
    platforms = lib.platforms.unix;
  };
}
