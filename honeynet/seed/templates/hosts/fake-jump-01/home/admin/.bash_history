cd /opt/app
cat .env
ssh deploy@fake-db-01
sudo systemctl restart helio-tracker
