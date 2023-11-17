#!/bin/bash

_OSTYPE="$(uname -s)"
CPUTYPE="$(uname -m)"

check_brew_installed() {
    brew --version > /dev/null
    return $?
}

if [ $# != 1 ]; then
    echo "Bad arguments. Use install or uninstall."
    exit 1
fi

echo "Make sure you ran this script with sudo."

if [ $1 != "install" ] && [ $1 != "uninstall" ]; then
    echo "Invalid command"
    exit 1
fi

if [ $_OSTYPE = "Darwin" ] && [ $1 = "install" ]; then
    echo "Installing aft for macOS"

    # TODO
    #if [ $_OSTYPE = "Darwin" ] && check_brew_installed; then
    #	echo "Installing via brew"
    #	exit 0
    #fi
    if [ $CPUTYPE = "arm64" ]; then
        URL="https://github.com/dd-dreams/aft/releases/latest/download/aft-macos-aarch64.gz"
    else
        URL="https://github.com/dd-dreams/aft/releases/latest/download/aft-macos-x86_64.gz"
    fi
# Other Unix types might work, but this script currently doesn't support them.
elif [ $_OSTYPE = "Linux" ] || [ "$(echo $_OSTYPE | grep '.*BSD')" ] && [ $1 = "install" ]; then
    if [ $CPUTYPE = "arm64" ]; then
        echo "Incompatible architecture"
        exit 1
    fi
    echo "Installing aft for Linux/BSD"
    URL="https://github.com/dd-dreams/aft/releases/latest/download/aft-linux-x86_64.gz"
elif [ $1 = "install" ]; then
    echo "Incompatible OS"
    exit 1
elif [ $1 = "uninstall" ]; then
    rm /usr/local/bin/aft > /dev/null 2>&1 && echo "aft uninstalled" || echo "aft not installed"
    rm /etc/systemd/system/aft-relay.service > /dev/null 2>&1
    exit 0
fi

curl -L $URL > /tmp/aft.gz
gzip -dcN /tmp/aft.gz > /usr/local/bin/aft
chmod +x /usr/local/bin/aft

if [ $_OSTYPE = "Linux" ] && [ "$(ps 1 | grep 'systemd')" ]; then
    curl https://raw.githubusercontent.com/dd-dreams/aft/master/aft-relay.service > /etc/systemd/system/aft-relay.service
    systemctl daemon-reload
fi
