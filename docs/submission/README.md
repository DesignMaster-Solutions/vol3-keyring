# Submission package: Volatility Plugin Contest 2026

Status: READY, NOT SENT. Sending is for the author (Alan De Bortolo), through the Impressora, with his OK.

Rules: https://volatilityfoundation.org/volatility-plugin-contest/ (deadline 31 December 2026; earlier submissions
are preferred when entries are similar). Several submissions by the same author are accepted as separate entries;
`email.txt` says this one is separate from vol3-io-uring and vol3-cbpf.

## Checklist before sending

- [ ] `git pull`; `.venv/bin/pytest tests` green on both samples (commands in README "Validation")
- [ ] `tests/sabotage.py` 15/15 and `tests/run_mutmut.sh` all killed
- [ ] Release v1.0.0 assets download and match `SHA256SUMS`
- [ ] The ICLA is already on file with the Foundation (sent 2026-11-05 with the first two entries); nothing to attach
      unless the Foundation asks again
- [ ] Send `email.txt` to contest@volatilityfoundation.org (if the sending account adds a signature, drop the
      closing lines of the txt)

## What goes in (contest requirements -> where)

| Requirement | Where |
|---|---|
| Source code | https://github.com/DesignMaster-Solutions/vol3-keyring (`plugins/linux/keyring.py`, `keyring_lib.py`), tag v1.0.0 |
| Memory samples | Release v1.0.0: `keyring-6.1.0-54-cloud-amd64.elf.zst`, `keyring-6.12.115.deb13.1-cloud-amd64.elf.zst`, the two ISFs `*.json.xz`, `SHA256SUMS`; rebuildable with `sample/build_sample.sh` |
| How to use | README.md ("Install and run") and docs/usage.md (real output on the three kernels and the live LUKS dump) |
| Write-up | docs/writeup.md |
| ICLA | on file since 2026-11-05 |
