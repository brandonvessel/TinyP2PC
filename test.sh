origin_ip='161.35.97.247' # change this. this is the ip of your first peer

clear

# install dependencies
./apt-get.sh
clear

# build
./make.sh

# run
./master_peer $origin_ip