#!/bin/bash
# nightly dump, run by cron at 02:00
mysqldump -u dbadmin -p'{{canary:db_1}}' helio > /var/backups/helio-$(date +%F).sql
gzip /var/backups/helio-$(date +%F).sql
