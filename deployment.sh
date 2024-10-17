git add -A
git stash
git pull
go build .
echo "Waiting for 10 seconds for the app to build. ."
sleep 10
sudo systemctl daemon-reload && sudo systemctl enable goweb.service&& sudo systemctl stop goweb.service && sudo systemctl start goweb.service
echo "Waiting for 5 seconds for the app to build. ."
sleep 5
sudo journalctl -u goweb.service -f