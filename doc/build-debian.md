## Build and install Goldcash on Debian 8.x

```sh
apt-get update && apt-get -y upgrade
apt-get -y install git build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-all-dev libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev
git clone https://github.com/goldcash/goldcash.git
cd goldcash
./contrib/instal_db5.sh `pwd`
```
copy the last two instructions after running the install_db5.sh script for later

```sh
./autogen.sh
```
run the export variable and configure script
```sh
make
make install
```
