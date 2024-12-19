#!/bin/bash
# quick script to get the hashes of the opa versions in the list
opa_versions=('0.42.2' '0.43.1' '0.44.0'
'0.45.0' '0.46.3' '0.47.4'
'0.48.0' '0.49.2' '0.50.2'
'0.51.0' '0.52.0' '0.53.1'
'0.54.0' '0.55.0' '0.56.0'
'0.57.1' '0.58.0')

for version in "${opa_versions[@]}"
do
  echo \'"$version"\': {

  curl -s -L -o opa_windows_amd64.exe https://openpolicyagent.org/downloads/v$version/opa_windows_amd64.exe
  win=$(sha256sum opa_windows_amd64.exe)
  read -ra winArr <<< "$win"
  windowsHash="${winArr[0]}"
  echo "'windows': '$windowsHash',"

  curl -s -L -o opa_darwin_amd64.sha256 https://openpolicyagent.org/downloads/v$version/opa_darwin_amd64.sha256
  mac=$(cat opa_darwin_amd64.sha256)
  read -ra macArr <<< "$mac"
  macHash="${macArr[0]}"
  echo "'macos': '$macHash',"

  curl -s -L -o opa_linux_amd64_static https://openpolicyagent.org/downloads/v$version/opa_linux_amd64_static
  linux=$(sha256sum opa_linux_amd64_static)
  read -ra linuxArr <<< "$linux"
  linuxHash="${linuxArr[0]}"
  echo "'linux': '$linuxHash'"
  echo "},"
done
