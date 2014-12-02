#!/bin/bash

cd $(dirname "$0")

echo "Installing Composer"
./installComposer.sh

if [ -n "$COVERAGE" ]
then
	echo "Installing Scrutinizer"
	./installScrutinizer.sh
elif [ "$TRAVIS_PHP_VERSION" != "hhvm" ]
then
	echo "Removing XDebug"
	phpenv config-rm xdebug.ini
fi