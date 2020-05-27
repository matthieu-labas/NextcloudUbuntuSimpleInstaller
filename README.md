# A Simple installer for Nextcloud on Ubuntu Server

This work was heavily inspired/copied from https://github.com/nextcloud/vm so it inherits its GPL v3 licence.

It's a simplification over it on several points:
* it does *not* create a filesystem for the data directory or configure the disks: as there are about as many different configurations as there are users, we consider that directory already created and configured
* it does *not* create system users: for the same reasong. Instead, it relies on the default, existing system user to perform the `sudo`s
* it does *not* configure the network, for the same reason
* it does *not* pre-install some Nextcloud apps: they can be installed simply when the server is up
* it does *not* pre-install Webmin: though a must-have, this script is focused on Nextcloud only
* it does *not* require a reboot, though it is recommended after upgrading all packages at the end of the installation
* it is *idempotent*: you should be able to run it several times and it should not mess up the system. If you can't, it should be considered as a bug.

A simple script to install the latest Nextcloud version, with PostgreSQL, Apache, Redis and APCU.

## Installing Webmin
```
if curl -fsSL http://www.webmin.com/jcameron-key.asc | sudo apt-key add - ; then
    echo "deb https://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list
    apt update -q4
    apt install -qy webmin
fi
```

