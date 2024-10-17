git add -A
git stash
git pull
go build .
echo "Waiting for 5 seconds for the app to start. ."
sleep 5
echo "reload the service"
sudo systemctl daemon-reload 
echo "enable the service"
sudo systemctl enable goweb.service
echo "stop the service"
 sudo systemctl stop goweb.service
 echo "start the service"
  sudo systemctl start goweb.service
echo "Waiting for 5 seconds for the app to start. ."
sleep 5
sudo journalctl -u goweb.service -f