#!/bin/bash

if [ -n "$COVERAGE" ]
then
	phpunit --coverage-clover /tmp/clover.xml
else
	phpunit
fi