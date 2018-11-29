_____________________________________________________________________________________________
# Install Java
Install oracle java by following 
https://www.digitalocean.com/community/tutorials/how-to-install-java-with-apt-on-ubuntu-18-04
_____________________________________________________________________________________________
# Redis Installation

- wget http://download.redis.io/releases/redis-4.0.10.tar.gz
- tar xzf redis-4.0.10.tar.gz
- cd redis-4.0.10
- make
- make install
_____________________________________________________________________________________________
# Install go

Install golang from this site.

https://golang.org/doc/install

The version used in development was go1.10.3 linux/amd64

add export PATH=$PATH:/usr/local/go/bin to .bashrc   
then do  
source .bashrc  
mkdir go  

_____________________________________________________________________________________________
then install go dep (golang package manager)  

go get -u github.com/golang/dep/cmd/dep

_____________________________________________________________________________________________
Then checkout our project in to go path  
it will be   
~/go/src/  

make sure the resulting directory structure is like this  
~/go/src/

_____________________________________________________________________________________________
# Install MYSQL

We are using "mysql  Ver 8.0.12 for Linux on x86_64 (MySQL Community Server - GPL)"  

Goto https://dev.mysql.com/downloads/repo/apt/ and download  

mysql-apt-config_0.8.10-1_all.deb  
md5:5b36dd754e7752162f890206fae50931  

sudo dpkg -i mysql-apt-config_0.8.10-1_all.deb  
sudo apt-get update  
sudo apt-get install mysql-server  

It should ask to set mysql password automatically just after installiing, if not:  

sudo mysql_secure_installation  

and answer the questions.  