#! /bin/sh

[ ! -f build ] && mkdir build

cd build
cmake ..
make
mv my_dbg ..
