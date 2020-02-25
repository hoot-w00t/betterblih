#!/bin/sh

if [ $(id -u) -ne 0 ]
    then echo "You need to run this script as root."
    exit
fi

INSTALL_PATH="/usr/local/bin"

echo "Installing BetterBlih on $INSTALL_PATH ..."
cp betterblih.py "$INSTALL_PATH/betterblih"
chmod 755 "$INSTALL_PATH/betterblih"

echo "BetterBlih is now installed!"
