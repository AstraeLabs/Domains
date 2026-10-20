# Domains

Domain list used by **ViewDB** and **VibraVid**.

## Files

| File | Purpose |
|------|---------|
| `domains_s.json` | **Edit this file.** Simple list: `name -> { "full_url": "..." }`. |
| `domains.json` | **Generated file.** Contains status, history, latency and SSL data. Do not edit. |
| `check_domains.py` | Checks every domain and updates both JSON files. |
| `.github/workflows/update_domains.yml` | Runs every 15 minutes (06:00-23:00 UTC) and manually. |

## Add a domain

Add an entry to `domains_s.json`:

```json
"example": { "full_url": "https://example.com/" }
```

Then commit and push to `main`. The Action updates `domains.json` automatically.
To run it immediately: **Actions -> Update Domains -> Run workflow**.

## Remove a domain

Delete its entry from `domains_s.json`, then commit and push.

## Change a domain URL

Edit `full_url` in `domains_s.json` and push. History is kept and the status is
checked again on the next run.

## How it works

- `domains_s.json` defines which domains exist.
- `domains.json` keeps the previous status and history.
- Domains missing from `domains_s.json` are removed from `domains.json`.
- URLs without a scheme get `https://`; only scheme + host are kept.
- If `domains_s.json` is empty or invalid, the script stops without changing files.