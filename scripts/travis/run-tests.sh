#!/bin/bash

cd $(dirname "$0")
cd ../..

if [ -n "$COVERAGE" ]
then
	phpunit --coverage-clover /tmp/clover.xml
else
	phpunit
fi