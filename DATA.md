# Where the data lives

This repository is **code only**. The large data files are not tracked in git because they exceed GitHub's per-file size limit (100 MB).

They are archived **unencrypted** in the **repository owner's (creator/admin) Google Drive**, folder `steamdeck-1`:

| | |
|---|---|
| File | `stopped-projects-data-2026-11-26.tar` |
| Size | 399,738,880 bytes (~382 MB) |
| MD5 | `fa8963620140f755b891a616678b2195` |

From this repository the archive contains:

- `trawl-data/trawl.db` — the main SQLite database (~133 MB)
- `trawl-data/snapshots/` — per-cycle JSONL snapshots
- `trawl-data/archive-prerelease-r1/` and `archive-stopped-capped-plan/` — older database snapshots

Restore with:

```bash
tar xf stopped-projects-data-2026-11-26.tar trawl-data
```

Note (2026-11-26): the local deployment of this project was decommissioned on the machine that produced it. GitHub Actions are disabled account-wide. The code in this repository is the complete current copy.
