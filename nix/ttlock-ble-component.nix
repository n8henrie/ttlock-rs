{
  lib,
  buildHomeAssistantComponent,
  ttlock-python,
  version,
}:
buildHomeAssistantComponent {
  owner = "n8henrie";
  domain = "ttlock_ble";
  inherit version;

  # The workspace root holds custom_components/ttlock_ble; the builder copies
  # the whole custom_components/ tree into the component output.
  src = lib.cleanSource ../.;

  # Satisfies the manifest's `ttlock` requirement. Must be built
  # against home-assistant's Python (see flake.nix).
  dependencies = [ ttlock-python ];

  meta = {
    description = "Home Assistant integration for TTLock BLE locks (local, via the ttlock Python bindings)";
    license = lib.licenses.mit;
  };
}
