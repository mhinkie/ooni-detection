#!/bin/sh

git pull
cd build

cmake ../
make
