{
  lib,
  buildPythonPackage,
  rustPlatform,
  version,
}:
buildPythonPackage {
  pname = "ttlock";
  inherit version;
  pyproject = true;

  # The wheel is built from the workspace member, but maturin/cargo need the
  # whole workspace (root manifest + Cargo.lock + ttlock-core) in scope.
  src = lib.cleanSource ../.;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../Cargo.lock;
  };

  # Point maturin at the pyo3 crate's manifest rather than the virtual
  # workspace root.
  maturinBuildFlags = [
    "--manifest-path"
    "crates/ttlock-py/Cargo.toml"
  ];

  nativeBuildInputs = [
    rustPlatform.cargoSetupHook
    rustPlatform.maturinBuildHook
  ];

  pythonImportsCheck = [ "ttlock" ];

  meta = {
    description = "Python bindings for the sans-IO ttlock-core protocol engine";
    license = lib.licenses.mit;
  };
}
