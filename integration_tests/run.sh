#!/bin/bash

echo "::group::Build httpx"
rm integration-test httpx 2>/dev/null
cd ../cmd/httpx
go build
mv httpx ../../integration_tests/httpx
echo "::endgroup::"
echo "::group::Build httpx integration-test"
cd ../integration-test
go build
mv integration-test ../../integration_tests/integration-test 
cd ../../integration_tests
echo "::endgroup::"
./integration-test
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
