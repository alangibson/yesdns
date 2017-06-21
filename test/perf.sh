# https://github.com/nominum/dnsperf
# https://gist.github.com/i0rek/369a6bcd172e214fd791
# https://github.com/nominum/dnsperf/pull/1

sudo apt-get install -y bind9utils libbind-dev libkrb5-dev libssl-dev libcap-dev libxml2-dev libgeoip-dev
curl ftp://ftp.nominum.com/pub/nominum/dnsperf/2.0.0.0/dnsperf-src-2.0.0.0-1.tar.gz -O
tar xfvz dnsperf-src-2.0.0.0-1.tar.gz
cd dnsperf-src-2.0.0.0-1
./configure --prefix=$(pwd)
make
make install

./bin/dnsperf -v -f inet -s 127.0.0.1 -p 5350 -c 100 -n 10000 -d ~/dev/gopath/src/github.com/alangibson/yesdns/test/dnsperf.in
