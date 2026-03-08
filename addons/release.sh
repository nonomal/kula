#!/usr/bin/env bash

set -e

cd "$(dirname "$0")"

./build.sh cross

cd "../dist"

for f in kula-linux-* ; do
    mkdir -p kula
    cp "$f" kula/kula
    cp ../VERSION kula/
    cp ../LICENSE kula/
    cp ../README.md kula/
    cp ../config.example.yaml kula/
    cp -r ../addons/bash-completion kula/
    cp -r ../addons/init kula/
    cp -r ../addons/man kula/
    g="$(echo "$f" | sed 's/-linux//g;')"
    tar -czf "${g}.tar.gz" kula
    rm -rf kula
done

cd ..
# building deb packages for all archs
for arch in amd64 arm64 riscv64; do
    ./addons/build_deb.sh "$arch"
done
cd -

echo "Release done!"
pwd
ls -1 $(pwd)/*.tar.gz
ls -1 $(pwd)/*.deb
