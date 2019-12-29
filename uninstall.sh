#!/bin/sh

if [ $(id -u) -ne 0 ]
    then echo "You need to run this script as root."
    exit
fi

INSTALL_PATH="/usr/local/bin"

echo "Uninstalling BetterBlih from $INSTALL_PATH ..."
rm "$INSTALL_PATH/betterblih"

echo "BetterBlih was uninstalled."
