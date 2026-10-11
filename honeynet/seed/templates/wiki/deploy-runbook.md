# Deploy runbook - Helio Tracker

1. SSH to `fake-jump-01` and check `/opt/app/.env` is up to date.
2. From the jump host, connect to `fake-db-01` with the **deploy** account
   (password in the ops notes on the jump host).
3. Run migrations, then restart `helio-tracker`.
4. Backups: `/home/deploy/backup.sh` on fake-db-01 runs nightly.
