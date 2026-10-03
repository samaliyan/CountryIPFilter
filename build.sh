#!/bin/sh
# usage: ./build.sh 4.0.3
# Builds dist/CountryIPFilter-Setup-<version>.exe: one file, the guides are
# built in. Run from anywhere it installs itself to Program Files.
set -e
V=${1:-$(cat VERSION 2>/dev/null || echo dev)}
go vet ./...
GOOS=windows GOARCH=amd64 go vet ./...
go test ./...
python3 tools/mksyso.py --arch amd64 --ico assets/app.ico --manifest assets/app.manifest \
  --version "$V" --desc "Country IP Filter" --product "Country IP Filter" \
  --name CountryIPFilter.exe --company "Country IP Filter (open source, github.com/samaliyan/CountryIPFilter)" --out rsrc_windows_amd64.syso
rm -rf dist
mkdir -p dist
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -H windowsgui -X main.Version=$V" -o "dist/CountryIPFilter-Setup-$V.exe" .
echo "dist/CountryIPFilter-Setup-$V.exe"
