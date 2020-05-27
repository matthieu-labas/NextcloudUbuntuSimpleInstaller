# A Simple installer for Nextcloud on Ubuntu Server

This work was heavily inspired/copied from https://github.com/nextcloud/vm so it inherits its GPL v3 licence.

It's a simplification over it on several points:
* it does *not* create a filesystem for the data directory or configure the disks: as there are about as many different configurations as there are users, we consider that directory already created and configured
* it does *not* create system users: for the same reasong. Instead, it relies on the default, existing system user to perform the `sudo`s
* it does *not* configure the network, for the same reason
* it does *not* pre-install some Nextcloud apps: they can be installed simply when the server is up
* it does *not* pre-install Webmin: though a must-have, this script is focused on Nextcloud only
* it does *not* require a reboot, though it is recommended after upgrading all packages at the end of the installation
* it does *not* install a Let's Encrypt certificate (in the TODO list)
* it is *idempotent*: you should be able to run it several times and it should not mess up the system. If you can't, it should be considered as a bug.

## Installation

1. Copy the `vars.template` to `vars` and edit the parameters:
    * `NCBASE` (default: `/var/www`) is where the Nextcloud archive will be extracted (i.e. `$NCBASE/nexcloud` usually)
    * `NCDATA` (default: none) is the Nextcloud data directory. Whether a simple folder, a simple disk, LLVM or RAID mount is up to the System Administrator. **It is the only mandatory parameter**.
    * `NCUSER` (default: `ncadmin`) is the Nextcloud Administrator. It is *not* a system account, but the login you should use when logging in the Nextcloud instance
    * `NCPASS` (default: auto-generated) is the Nextcloud Administrator password
    * `PGDB_PASS` (default: auto-generated) is the PostgreSQL administrator password
    * `DBNAME` (default: `nextcloud`) is the Nextcloud database name
    * `PHPVER` is the PHP version that should be installed. If not defined, the default PHP will be installed (`apt install php`) and its version will be read (`PHP_VERSION` constant)
2. As a sudoer, run `sudo ./nextcloud_install.sh`
    * A log file will be created detailing the main steps
3. Recommended: upgrade the whole system
    * `apt update -q4 && apt dist-upgrade -y && apt autoremove --purge -y && apt autoclean`

## Bonus: installing Webmin

Because Webmin is such a cool tool, you can use the following snipet to install it (run as root):
```
if curl -fsSL http://www.webmin.com/jcameron-key.asc | sudo apt-key add - ; then
    echo "deb https://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list
    apt update -q4
    apt install -qy webmin
fi
```
