#!/bin/sh

# Verify OS
OS="$(uname)"
if [ "$OS" = "Darwin" ]; then
    OS="osx"
elif [ "$OS" = "Linux" ]; then
    OS="linux"
else
    echo "blimp can only be installed on either MacOS or Linux."
    exit 1
fi

RELEASE="0.15.1"

# Download the latest Blimp release into a temporary directory
# Try cURL, then wget, otherwise fail
ENDPOINT="https://github.com/kelda/blimp/releases/download/${RELEASE}/blimp-${OS}-${RELEASE}"
if which curl > /dev/null; then
    if ! curl -#fSLo blimp "$ENDPOINT"; then
        echo "Failed to download Blimp...exiting"
        exit 1
    fi
elif which wget > /dev/null; then
    if ! wget -O blimp"$ENDPOINT" ; then
        echo "Failed to download Blimp...exiting"
        exit 1
    fi
else
    echo "Installing blimp requires either cURL or wget to be installed."
fi

chmod +x "./blimp"

echo
echo "The latest Blimp release has been downloaded to the current working directory."
echo

read -p "Copy the binary into /usr/local/bin? (Y/n) " choice < /dev/tty
case "$choice" in
    n|N ) echo "You will have to move the binary into your PATH in order to invoke blimp globally.";;
    * ) echo "You may be prompted for your sudo password in order to write to /usr/local/bin."
        if [ -d "/usr/local/bin" ]; then
            sudo -p 'Sudo password: ' -- mv ./blimp /usr/local/bin
        else
            sudo -p 'Sudo password: ' -- mkdir -p /usr/local/bin && sudo mv ./blimp /usr/local/bin
        fi

        echo
        echo "Successfully installed blimp!"
        ;;
esac
