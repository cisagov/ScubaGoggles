#!/usr/bin/env bash

opa_versions=('0.42.2' '0.43.1' '0.44.0'
'0.45.0' '0.46.3' '0.47.4'
'0.48.0' '0.49.2' '0.50.2'
'0.51.0' '0.52.0' '0.53.1'
'0.54.0' '0.55.0' '0.56.0'
'0.57.1' '0.58.0')

if [ $# -lt 1 ]
then
  echo "Usage: $0 <OS>"
  echo "Possible OS choices are: windows, macos, linux"
  exit
fi

for version in ${opa_versions[@]}
do
    python3 ./download_opa.py -v "$version" -os "$1"
    chmod +x ./opa*
    python3 ./Testing/run_unit_tests.py
    rm ./opa*
done

