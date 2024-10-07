git add -A
git stash
git pull
go build .
sudo systemctl daemon-reload && sudo systemctl enable goweb.service&& sudo systemctl start goweb.service
sudo journalctl -u goweb.service -f