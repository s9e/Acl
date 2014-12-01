#!/bin/bash

cd $(dirname "$0")
cd ../..

composer install --dev -q --no-interaction

if [ -n "$COVERAGE" ]
then
	composer require --dev -q --no-interaction "satooshi/php-coveralls:*"
fi