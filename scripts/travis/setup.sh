#!/bin/bash

cd $(dirname "$0")

# Install Coveralls and XSLCache if we're saving code coverage and disable XDebug otherwise
if [ -n "$COVERAGE" ]
then
	# We run this script detached in the background. It'll finish while tests are running
	echo "Installing Composer dependencies"
	sh -c "./installComposer.sh 2>&1 &" >/dev/null 2>&1 &

	# Install Scrutinizer's external code coverage tool
	echo "Installing Scrutinizer"
	./installScrutinizer.sh >/dev/null 2>&1 &
else
	echo "Removing XDebug"
	phpenv config-rm xdebug.ini
fi

wait