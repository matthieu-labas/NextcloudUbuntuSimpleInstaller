#!/bin/bash
echo "Thank you https://github.com/nextcloud/vm"

# System is supposed to be almost blank, with the following:
# - locale and timezone already set
# - Server FQDN available (through `hostname --fqdn`)
# - Nextcloud data directory $NCDATA must exist

# Check root
uid=$(id | cut -f1 -d' ' | awk -F = '{split($2,a,"("); print a[1]}')
if [ $uid -ne 0 ] ; then
	echo "Run with sudo"
	exit 1
fi

gen_passwd() {
    local length=$1
    local charset="$2"
    local password=""
    while [ ${#password} -lt "$length" ] ; do
        password=$(echo "$password""$(head -c 100 /dev/urandom | LC_ALL=C tr -dc "$charset")" | fold -w "$length" | head -n 1)
    done
    echo "$password"
}
SHUF=$(shuf -i 25-29 -n 1)


# Get configuration
if [ -f ./vars ] ; then
	. ./vars
else
	echo "Cannot find variables file ./vars"
	exit 1
fi

# Check configuration
if [ ! -d "$NCDATA" ] ; then
	echo "$NCDATA does not exist. Exiting..."
	exit 1
fi

NCBASE=${NCBASE:-/var/www}
NCUSER=${NCUSER:-ncadmin}
if [ -z "$DBPASS" ] ; then
	NCPASS=$(gen_passwd "$SHUF" "a-zA-Z0-9@#*=")
	log "[NEXTCLOUD] Generated password for user \"$NCUSER\" is \"$NCPASS\""
fi
DBNAME=${DBNAME:-nextcloud}
if [ -z "$DBPASS" ] ; then
	DBPASS=$(gen_passwd "$SHUF" "a-zA-Z0-9@#*=")
	log "[DB] Generated password is \"$DBPASS\""
fi

NCPATH=$NCBASE/nextcloud

LOGFILE="$PWD/nextcloud_install-$(date +%Y-%m-%d-%H-%M).log"
log() {
	echo -e "$(date +"%Y-%m-%d %H-%M-%S") $1" | tee -a $LOGFILE
}

check_network() {
	if ! ping -c1 www.github.com > /dev/null 2>&1 ; then
		log "No network connectivity. Exiting..."
		exit 2
	fi
}

restart_webserver() {
	systemctl restart apache2.service
	systemctl restart php"$PHPVER"-fpm.service
}

occ_command() {
	sudo -u www-data php "$NCPATH"/occ "$@";
}

calculate_php_fpm() {
	# Minimum amount of max children (lower than this won't work with 2 GB RAM)
	min_max_children=8
	# If start servers are lower than this then it's likely that there are room for max_spare_servers
	min_start_servers=20
	# Maximum amount of children is only set if the min_start_servers value are met
	min_max_spare_servers=35

	# Calculate the sum of the current values
	CURRENT_START="$(grep pm.start_servers "$PHP_POOL_DIR"/nextcloud.conf | awk '{ print $3}')"
	CURRENT_MAX="$(grep pm.max_spare_servers "$PHP_POOL_DIR"/nextcloud.conf | awk '{ print $3}')"
	CURRENT_MIN="$(grep pm.min_spare_servers "$PHP_POOL_DIR"/nextcloud.conf | awk '{ print $3}')"
	CURRENT_SUM="$((CURRENT_START + CURRENT_MAX + CURRENT_MIN))"

	# Calculate max_children depending on RAM
	# Tends to be between 30-50MB per children
	average_php_memory_requirement=50
	available_memory=$(awk '/MemAvailable/ {printf "%d", $2/1024}' /proc/meminfo)
	PHP_FPM_MAX_CHILDREN=$((available_memory/average_php_memory_requirement))

	# Lowest possible value is 8
	if [ $PHP_FPM_MAX_CHILDREN -lt $min_max_children ] ; then
		log "The current max_children value available to set is $PHP_FPM_MAX_CHILDREN, and with that value PHP-FPM won't function properly.
	The minimum value is 8, and the value is calculated depening on how much RAM you have left to use in the system.
	The absolute minimum amount of RAM required to run the VM is 2 GB, but we recomend 4 GB.
	You now have two choices:
	1. Import this VM again, raise the amount of RAM with at least 1 GB, and then run this script again,
	   installing it in the same way as you did before.
	2. Import this VM again without raising the RAM, but don't install any of the following apps:
	   1) Collabora
	   2) OnlyOffice
	   3) Full Text Search
	This script will now exit.
	The installation was not successful, sorry for the inconvenience.
	If you think this is a bug, please report it to $ISSUES"
		exit 1
	else
		sed -i "s|pm.max_children.*|pm.max_children = $PHP_FPM_MAX_CHILDREN|g" "$PHP_POOL_DIR"/nextcloud.conf
		# Check if the sum of all the current values are more than $PHP_FPM_MAX_CHILDREN and only continue it is
		if [ $PHP_FPM_MAX_CHILDREN -gt $CURRENT_SUM ] ; then
		    # Set pm.max_spare_servers
		    if [ $PHP_FPM_MAX_CHILDREN -ge $min_max_spare_servers ] ; then
		        if [ "$(grep pm.start_servers "$PHP_POOL_DIR"/nextcloud.conf | awk '{ print $3}')" -lt $min_start_servers ] ; then
		            sed -i "s|pm.max_spare_servers.*|pm.max_spare_servers = $((PHP_FPM_MAX_CHILDREN - 30))|g" "$PHP_POOL_DIR"/nextcloud.conf
		        fi
		    fi
		fi
	fi

	# If $PHP_FPM_MAX_CHILDREN is lower than the current sum of all values, revert to default settings
	if [ $PHP_FPM_MAX_CHILDREN -lt $CURRENT_SUM ] ; then
		sed -i "s|pm.max_children.*|pm.max_children = $PHP_FPM_MAX_CHILDREN|g" "$PHP_POOL_DIR"/nextcloud.conf
		sed -i "s|pm.start_servers.*|pm.start_servers = 3|g" "$PHP_POOL_DIR"/nextcloud.conf
		sed -i "s|pm.min_spare_servers.*|pm.min_spare_servers = 2|g" "$PHP_POOL_DIR"/nextcloud.conf
		sed -i "s|pm.max_spare_servers.*|pm.max_spare_servers = 3|g" "$PHP_POOL_DIR"/nextcloud.conf
	fi
	restart_webserver
}

log "[SYSTEM] Installing tools..."
apt install -qy curl lshw net-tools netplan.io build-essential
add-apt-repository universe
add-apt-repository multiverse
apt update -q4

# Install Postgres
log "[DB] Installing PostgreSQL..."
apt install -qy postgresql
if ! sudo -u postgres psql -l | grep "$DBNAME" > /dev/null ; then
	log "[DB] Create database $DBNAME and user $NCUSER..."
	sudo -u postgres psql <<END
	CREATE USER $NCUSER WITH PASSWORD '$PGDB_PASS';
	CREATE DATABASE "$DBNAME" WITH OWNER $NCUSER TEMPLATE template0 ENCODING 'UTF8';
END
else
	log "[DB] Database $DBNAME already exists"
fi

# Install Apache
log "[HTTP] Installing Apache..."
apt install -qy apache2
log "[HTTP] Enabling Apache modules..."
a2enmod rewrite headers proxy proxy_fcgi setenvif env mime dir authz_core alias ssl
a2dismod mpm_prefork
if ! grep -q 'ServerSignature' /etc/apache2/apache2.conf ; then
	log "[HTTP] Disable server tokens in Apache..."
	{
	echo "# Turn off ServerTokens for both Apache and PHP"
	echo "ServerSignature Off"
	echo "ServerTokens Prod"
	} >> /etc/apache2/apache2.conf
else
	log "[HTTP] Server tokens in Apache already disabled"
fi
if ! grep -q 'IfModule http2_module' /etc/apache2/mods-available/http2.conf ; then
	log "[HTTP] Enabling HTTP2..."
	cat << HTTP2_ENABLE > /etc/apache2/mods-available/http2.conf
	<IfModule http2_module>
		Protocols h2 http/1.1
		H2Direct on
	</IfModule>
HTTP2_ENABLE
	a2enmod http2
else
	log "[HTTP] HTTP2 already enabled"
fi

# Install PHP
# If PHPVER is undefined, install latest php and retrieve version
if [ -z "$PHPVER" ] ; then
	log "[PHP] Retrieving latest version..."
	apt install -qy php
	PHPVER=$(php -r "echo PHP_VERSION;" | cut -f1,2 -d.)
	log "[PHP] Latest version is $PHPVER"
fi

PHP_FPM_DIR=/etc/php/$PHPVER/fpm
PHP_INI=$PHP_FPM_DIR/php.ini
PHP_POOL_DIR=$PHP_FPM_DIR/pool.d
log "[PHP] Installing PHP$PHPVER..."
apt install -qy php"$PHPVER"-fpm php"$PHPVER"-intl php"$PHPVER"-ldap php"$PHPVER"-imap php"$PHPVER"-gd php"$PHPVER"-pgsql php"$PHPVER"-curl php"$PHPVER"-xml php"$PHPVER"-zip php"$PHPVER"-mbstring php"$PHPVER"-soap php"$PHPVER"-json php"$PHPVER"-gmp php"$PHPVER"-bz2 php-pear php"$PHPVER"-dev php-imagick
a2enconf php"$PHPVER"-fpm

if [ ! -f "$PHP_POOL_DIR"/nextcloud.conf ] ; then
	log "[PHP] Configuring Nextcloud..."
	cat << POOL_CONF > "$PHP_POOL_DIR"/nextcloud.conf
[Nextcloud]
user = www-data
group = www-data
listen = /run/php/php"$PHPVER"-fpm.nextcloud.sock
listen.owner = www-data
listen.group = www-data
pm = dynamic
; max_children is set dynamically with calculate_php_fpm()
pm.max_children = 8
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 3
env[HOSTNAME] = $(hostname -f)
env[PATH] = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp
security.limit_extensions = .php
php_admin_value [cgi.fix_pathinfo] = 1
; Optional
; pm.max_requests = 2000
POOL_CONF

	mv "$PHP_POOL_DIR"/www.conf "$PHP_POOL_DIR"/www.conf.backup
else
	log "[PHP] Nextcloud already configured"
fi

calculate_php_fpm

cd $NCBASE
if [ ! -d "$NCPATH" ] ; then
	log "[NEXTCLOUD] Checking latest version..."
	VER=$(curl -s -m 900 https://download.nextcloud.com/server/releases/ | sed --silent 's/.*href="nextcloud-\([^"]\+\).zip.asc".*/\1/p' | sort --version-sort | tail -1)
	log "[NEXTCLOUD] Downloading version $VER..."
	curl -fSLO --retry 3 https://download.nextcloud.com/server/releases/nextcloud-$VER.tar.bz2
	log "[NEXTCLOUD] Unpacking version $VER..."
	tar -xjf nextcloud-$VER.tar.bz2 && rm -f nextcloud-$VER.tar.bz2
else
	log "[NEXTCLOUD] Already installed"
fi

log "[NEXTCLOUD] Setting up file permissions..."
find "${NCPATH}"/ -type f -print0 | xargs -0 chmod 0640
find "${NCPATH}"/ -type d -print0 | xargs -0 chmod 0750
chown -R root:www-data "${NCPATH}"/
chown -R www-data:www-data "${NCPATH}"/apps/
chown -R www-data:www-data "${NCPATH}"/config/
chown -R www-data:www-data "${NCPATH}"/themes/
chown -R www-data:www-data "${NCPATH}"/updater/
chown -R www-data:www-data "${NCDATA}"/
if [ -f "${NCPATH}"/.htaccess ] ; then
    chmod 0644 "${NCPATH}"/.htaccess
    chown root:www-data "${NCPATH}"/.htaccess
fi
if [ -f "${NCDATA}"/.htaccess ] ; then
    chmod 0644 "${NCDATA}"/.htaccess
    chown root:www-data "${NCDATA}"/.htaccess
fi

cd $NCPATH
if [ ! -d "$NCPATH" ] ; then
	log "[NEXTCLOUD] Installing Nexcloud..."
	occ_command maintenance:install \
		--data-dir="$NCDATA" \
		--database=pgsql \
		--database-name="$DBNAME" \
		--database-user="$NCUSER" \
		--database-pass="$PGDB_PASS" \
		--admin-user="$NCUSER" \
		--admin-pass="$NCPASS"
else
	log "[NEXTCLOUD] Nexcloud already installed"
fi

log "[NEXTCLOUD] Configuring retention..."
occ_command config:system:set trashbin_retention_obligation --value="auto, 180"
occ_command config:system:set versions_retention_obligation --value="auto, 365"

if ! crontab -lu www-data | grep -q "$NCPATH/cron.php" > /dev/null ; then
	log "[NEXTCLOUD] Configuring cron..."
	crontab -u www-data -l | { cat; echo "*/5  *  *  *  * php -f \"$NCPATH/cron.php\" > /dev/null 2>&1"; } | crontab -u www-data -
else
	log "[NEXTCLOUD] Cron already configured"
fi

log "[PHP] Configuring $PHP_INI..."
sed -i "s|max_execution_time =.*|max_execution_time = 3500|g" "$PHP_INI"
sed -i "s|max_input_time =.*|max_input_time = 3600|g" "$PHP_INI"
sed -i "s|memory_limit =.*|memory_limit = 512M|g" "$PHP_INI"
sed -i "s|post_max_size =.*|post_max_size = 1100M|g" "$PHP_INI"
sed -i "s|upload_max_filesize =.*|upload_max_filesize = 1000M|g" "$PHP_INI"

if ! grep -q "OPcache settings for Nextcloud" "$PHP_INI" ; then
	log "[PHP] Configuring OPcache..."
	phpenmod opcache
	{
	echo "# OPcache settings for Nextcloud"
	echo "opcache.enable=1"
	echo "opcache.enable_cli=1"
	echo "opcache.interned_strings_buffer=8"
	echo "opcache.max_accelerated_files=10000"
	echo "opcache.memory_consumption=256"
	echo "opcache.save_comments=1"
	echo "opcache.revalidate_freq=1"
	echo "opcache.validate_timestamps=1"
	} >> "$PHP_INI"
else
	log "[PHP] OPcache already configured"
fi

sed -i "s|;emergency_restart_threshold.*|emergency_restart_threshold = 10|g" /etc/php/"$PHPVER"/fpm/php-fpm.conf
sed -i "s|;emergency_restart_interval.*|emergency_restart_interval = 1m|g" /etc/php/"$PHPVER"/fpm/php-fpm.conf
sed -i "s|;process_control_timeout.*|process_control_timeout = 10|g" /etc/php/"$PHPVER"/fpm/php-fpm.conf

if [ ! -f "$PHP_FPM_DIR"/conf.d/20-pdo_pgsql.ini ] || ! grep -q "^[PostgresSQL]" "$PHP_FPM_DIR"/conf.d/20-pdo_pgsql.ini ; then
	log "[PHP] Configuring Postgres..."
	{
	echo ""
	echo "[PostgresSQL]"
	echo "pgsql.allow_persistent = On"
	echo "pgsql.auto_reset_persistent = Off"
	echo "pgsql.max_persistent = -1"
	echo "pgsql.max_links = -1"
	echo "pgsql.ignore_notice = 0"
	echo "pgsql.log_notice = 0"
	} >> "$PHP_FPM_DIR"/conf.d/20-pdo_pgsql.ini
else
	log "[PHP] Postgres already configured"
fi

log "[REDIS] Installing Redis..."
pecl channel-update pecl.php.net
yes no | pecl install -Z redis
apt install -qy redis-server

REDIS_CONF=/etc/redis/redis.conf
REDIS_SOCK=/var/run/redis/redis-server.sock
REDIS_PASS=$(gen_passwd "$SHUF" "a-zA-Z0-9@#*=")
if ! grep -q "extension=redis.so" "$PHP_INI" ; then
	log "[REDIS] Configuring PHP..."
	echo 'extension=redis.so' >> "$PHP_INI"
else
	log "[REDIS] PHP already configured"
fi
if ! grep -q "'\\\\OC\\\\Memcache\\\\APCu'" $NCPATH/config/config.php ; then
	log "[REDIS] Configuring Nextcloud..."
	sed -i "s|);||g" $NCPATH/config/config.php
	cat <<ADD_TO_CONFIG >> $NCPATH/config/config.php
  'memcache.local' => '\\OC\\Memcache\\APCu',
  'filelocking.enabled' => true,
  'memcache.distributed' => '\\OC\\Memcache\\Redis',
  'memcache.locking' => '\\OC\\Memcache\\Redis',
  'redis' =>
  array (
	'host' => '$REDIS_SOCK',
	'port' => 0,
	'timeout' => 0.5,
	'dbindex' => 0,
	'password' => '$REDIS_PASS',
  ),
);
ADD_TO_CONFIG
else
	log "[REDIS] Nextcloud already configured"
fi

log "[REDIS] Configuring System..."
sed -i "s|# unixsocket .*|unixsocket $REDIS_SOCK|g" $REDIS_CONF
sed -i "s|# unixsocketperm .*|unixsocketperm 777|g" $REDIS_CONF
sed -i "s|^port.*|port 0|" $REDIS_CONF
sed -i "s|# requirepass .*|requirepass $REDIS_PASS|g" $REDIS_CONF
sed -i 's|# rename-command CONFIG ""|rename-command CONFIG ""|' $REDIS_CONF
redis-cli SHUTDOWN
chown redis:root $REDIS_CONF
chmod 600 $REDIS_CONF


log "[KERNEL] Configuring memory..."
if ! grep -Fxq "vm.overcommit_memory = 1" /etc/sysctl.conf ; then
    echo 'vm.overcommit_memory = 1' >> /etc/sysctl.conf
fi
if ! grep -Fxq "never" /sys/kernel/mm/transparent_hugepage/enabled ; then
    echo "never" > /sys/kernel/mm/transparent_hugepage/enabled
fi

log "[PHP] Configuring SMB..."
apt install -qy libsmbclient-dev
pecl install smbclient
if ! grep -qFx extension=smbclient.so "$PHP_INI" ; then
    echo "# PECL smbclient" >> "$PHP_INI"
    echo "extension=smbclient.so" >> "$PHP_INI"
fi
yes no | pecl install -Z igbinary
if ! grep -q "extension=igbinary.so" "$PHP_INI" ; then
	{
	echo "# igbinary for PHP"
	echo "extension=igbinary.so"
	echo "session.serialize_handler=igbinary"
	echo "igbinary.compact_strings=On"
	} >> "$PHP_INI"
fi

log "[APCU] Installing APCU..."
yes no | pecl install -Z apcu
if ! grep -q "APCu settings for Nextcloud" "$PHP_INI" ; then
	log "[PHP] Configuring APCU..."
	{
	echo "# APCu settings for Nextcloud"
	echo "extension=apcu.so"
	echo "apc.enabled=1"
	echo "apc.max_file_size=5M"
	echo "apc.shm_segments=1"
	echo "apc.shm_size=128M"
	echo "apc.entries_hint=4096"
	echo "apc.ttl=3600"
	echo "apc.gc_ttl=7200"
	echo "apc.mmap_file_mask=NULL"
	echo "apc.slam_defense=1"
	echo "apc.enable_cli=1"
	echo "apc.use_request_time=1"
	echo "apc.serializer=igbinary"
	echo "apc.coredump_unmap=0"
	echo "apc.preload_path"
	} >> "$PHP_INI"
	sed -i "s|;date.timezone.*|date.timezone = $(cat /etc/timezone)|g" "$PHP_INI"
	restart_webserver
else
	log "[PHP] APCU already configured"
fi

log "[NEXTCLOUD] Configuring cache..."
yes | occ_command db:convert-filecache-bigint

log "[NEXTCLOUD] Configuring database..."
occ_command db:add-missing-indices

log "[SYSTEM] Installing other tools..."
apt install -qy ssl-cert p7zip p7zip-full git

log "[WEB] Configuring access..."
SITES_AVAILABLE="/etc/apache2/sites-available"
TLS_CONF="nextcloud_tls_domain_self_signed.conf"
HTTP_CONF="nextcloud_http_domain_self_signed.conf"
if [ ! -f $SITES_AVAILABLE/$HTTP_CONF ] ; then
    cat << HTTP_CREATE > "$SITES_AVAILABLE/$HTTP_CONF"
<VirtualHost *:80>
### YOUR SERVER ADDRESS ###
#    ServerAdmin admin@example.com
#    ServerName example.com
#    ServerAlias subdomain.example.com
### SETTINGS ###
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:/run/php/php$PHPVER-fpm.nextcloud.sock|fcgi://localhost"
    </FilesMatch>
    DocumentRoot $NCPATH
    <Directory $NCPATH>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
    Satisfy Any
    </Directory>
    <IfModule mod_dav.c>
    Dav off
    </IfModule>
    <Directory "$NCDATA">
    # just in case if .htaccess gets disabled
    Require all denied
    </Directory>
    # The following lines prevent .htaccess and .htpasswd files from being
    # viewed by Web clients.
    <Files ".ht*">
    Require all denied
    </Files>
    # Disable HTTP TRACE method.
    TraceEnable off
    # Disable HTTP TRACK method.
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} ^TRACK
    RewriteRule .* - [R=405,L]
    SetEnv HOME $NCPATH
    SetEnv HTTP_HOME $NCPATH
    # Avoid "Sabre\DAV\Exception\BadRequest: expected filesize XXXX got XXXX"
    <IfModule mod_reqtimeout.c>
    RequestReadTimeout body=0
    </IfModule>
</VirtualHost>
HTTP_CREATE
fi
if [ ! -f $SITES_AVAILABLE/$TLS_CONF ] ; then
    cat << TLS_CREATE > "$SITES_AVAILABLE/$TLS_CONF"
<VirtualHost *:443>
    Header add Strict-Transport-Security: "max-age=15768000;includeSubdomains"
    SSLEngine on
### YOUR SERVER ADDRESS ###
#    ServerAdmin admin@example.com
#    ServerName example.com
#    ServerAlias subdomain.example.com
### SETTINGS ###
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:/run/php/php$PHPVER-fpm.nextcloud.sock|fcgi://localhost"
    </FilesMatch>
    DocumentRoot $NCPATH
    <Directory $NCPATH>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
    Satisfy Any
    </Directory>
    <IfModule mod_dav.c>
    Dav off
    </IfModule>
    <Directory "$NCDATA">
    # just in case if .htaccess gets disabled
    Require all denied
    </Directory>
    
    # The following lines prevent .htaccess and .htpasswd files from being
    # viewed by Web clients.
    <Files ".ht*">
    Require all denied
    </Files>
    
    # Disable HTTP TRACE method.
    TraceEnable off
    # Disable HTTP TRACK method.
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} ^TRACK
    RewriteRule .* - [R=405,L]
    SetEnv HOME $NCPATH
    SetEnv HTTP_HOME $NCPATH
    # Avoid "Sabre\DAV\Exception\BadRequest: expected filesize XXXX got XXXX"
    <IfModule mod_reqtimeout.c>
    RequestReadTimeout body=0
    </IfModule>
### LOCATION OF CERT FILES ###
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
</VirtualHost>
TLS_CREATE
fi
a2ensite "$TLS_CONF"
a2ensite "$HTTP_CONF"
a2dissite default-ssl
if ! grep -q "http://lost.l-w.ca/0x05/apache-mod_proxy_fcgi-and-php-fpm" /etc/apache2/sites-available/000-default.conf ; then
	#sed -i "s|DocumentRoot /var/www/html|DocumentRoot $NCBASE|g" /etc/apache2/sites-available/000-default.conf
	sed -i '14i\    # http://lost.l-w.ca/0x05/apache-mod_proxy_fcgi-and-php-fpm/' /etc/apache2/sites-available/000-default.conf
	sed -i '15i\    <FilesMatch "\.php$">' /etc/apache2/sites-available/000-default.conf
	sed -i '16i\        <If "-f %{SCRIPT_FILENAME}">' /etc/apache2/sites-available/000-default.conf
	sed -i '17i\          SetHandler "proxy:unix:/run/php/php'$PHPVER'-fpm.nextcloud.sock|fcgi://localhost"' /etc/apache2/sites-available/000-default.conf
	sed -i '18i\        </If>' /etc/apache2/sites-available/000-default.conf
	sed -i '19i\    </FilesMatch>' /etc/apache2/sites-available/000-default.conf
	sed -i '20i\    ' /etc/apache2/sites-available/000-default.conf
	restart_webserver
fi


apt remove --purge -y lxd

log "[NEXTCLOUD] Configuring access..."
occ_command config:system:set logtimezone --value="$(cat /etc/timezone)"
chown -R www-data:www-data $NCPATH
occ_command config:system:set overwrite.cli.url --value="http://localhost/"
occ_command config:system:set htaccess.RewriteBase --value="/"
occ_command maintenance:update:htaccess

#log "[SSH] Recreating keys..."
#rm -v /etc/ssh/ssh_host_*
#dpkg-reconfigure openssh-server

a2dismod status
calculate_php_fpm
# Run again if values are reset on last run
calculate_php_fpm

log "[NEXTCLOUD] Patching SMB..."
# Fix SMB issues (https://github.com/nextcloud/server/issues/20622)
# git_apply_patch 20941 server 18.0.4
NC_APPS_PATH=$NCPATH/apps
rm -Rf "$NC_APPS_PATH"/files_external/3rdparty/icewind/smb
cd "$NC_APPS_PATH"/files_external/3rdparty/icewind/
git clone https://github.com/icewind1991/SMB.git smb

# TODO: SMTP configuration?

log "[NEXTCLOUD] Sanitizing..."
occ_command maintenance:repair
log "[NEXTCLOUD] Adding trusted domain $(hostname --fqdn)..."
occ_command config:system:set trusted_domains 1 --value=$(hostname --fqdn)
sed -i "s|'overwrite.cli.url' => .*|'overwrite.cli.url' => '$(hostname --fqdn)',|g" $NCPATH/config/config.php
sed -i "s|RewriteBase /nextcloud|RewriteBase /|g" $NCPATH/.htaccess

log "Installation complete. To add trusted domains, type \"sudo -u www-data php \"$NCPATH/occ\" config:system:set trusted_domains <index> --value=[domain]\""
# TODO: Reboot?

