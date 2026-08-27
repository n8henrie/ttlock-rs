# Security

This project handles the credentials that open a physical door.
The most likely bad day here is not a parser bug — it is a lock's AES key ending up somewhere readable.

## Reporting

Open a [public issue](https://github.com/n8henrie/ttlock-rs/issues).
Most findings here are better in the open, where people running this software can see them.

If disclosing in the clear would put someone's door at risk before a fix exists, reach me privately at <https://n8henrie.com/contact/> instead.
Either way, don't include real credentials — a synthetic key demonstrates anything in this codebase just as well.

This is a hobby project maintained by one person, so please allow reasonable time for a reply.
Fixes land in a new release; nothing is backported.

## Handling `lockData.json`

**It is a key to your door.**
It holds the lock's AES key and admin passcode in plaintext, because the protocol needs them in plaintext to build a frame.
Anyone who can read the file can open the lock, and this project offers no way to rotate either value — see the protocol's [security properties](docs/protocol-and-design.md#4-security-properties) for why.

- `chmod 600`, owned by the account that runs the daemon. World-readable is the same as leaving the key under the mat.
- Never commit it. `.gitignore` covers it and the Sciener app database; `scripts/check-secrets.sh` scans tracked files for credential-shaped content and runs in CI and before every release.
- Never put it in the Nix store, which is world-readable on the machine. The NixOS module takes `lockDataFile` and `mqtt.credentialsFile` as *paths* read at runtime, and both accept a [sops-nix](https://github.com/Mic92/sops-nix) secret path directly.
- Prefer `TTLOCK_MQTT_PASSWORD` over `--mqtt-password`. Anything on the command line is visible to every local user in `ps`; the NixOS module passes broker credentials through a systemd `EnvironmentFile` for exactly this reason, and `nix/checks/module-eval.nix` asserts it stays that way.

Delete the copy of the app database once you have imported from it.
It contains the same credentials for every lock your phone has ever been given a key to, not just the one you care about.

## Diagnostic captures

Two kinds of file produced while debugging are more sensitive than they look.

**An advertisement or packet capture names your lock and your home.**
It carries the MAC address, once per radio report, plus everything the lock broadcasts.
It never carries the AES key — that only ever encrypts, it is never transmitted — so a capture is safe to share when a bug report needs one, but it does not belong in git.

**A dump of the operate log (`0x25`) contains working door codes.**
The lock's audit trail stores keypad passcodes as plaintext ASCII inside the record body, so anything that reads the log obtains them, including codes issued to other people.
Reading it requires only the AES key, which means a saved log file is as dangerous as `lockData.json` itself and is much easier to forget about.
Treat one as a credential, do not paste it into an issue, and delete it when you are done.

`ttlock logs` reads `0x25` and prints passcodes in the clear, after a warning and a five-second pause.
That is deliberate — it is a local tool for your own door — but it means the output is a credential: do not paste it into an issue, and delete it when you are done.
`.gitignore` covers `/tmp/` and top-level `*.log` for this reason, and `scripts/check-secrets.sh` is the backstop.

## Test data

The only real-looking credential in the test suite is an `adminPs` value that was already published on the Home Assistant forum, cited at its use site in `crates/ttlock-core/src/credential.rs`.
Everything else is synthetic.
Please keep it that way in any contribution.
