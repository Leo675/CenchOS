CenchOS 7 Alpha 0.3
=======

CenchOS is a free open source Web Server Framework in Alpha stages of development. This differs from a web application framework greatly as the focus of this tool is to build out custom functions and configurations for CentOS server administration and engineering, rather than the websites hosted on it.
<br>
Disclamer: Security, availability, and quality of service are all in mind when developing CenchOS, but use at your own risk.
No code is obfuscated and most external resources are widely considered as trusted like EPEL, RepoForge, Wordpress.org etc. 
<br>
Usage: in the top 50 lines of the script there are server specific variables that should to be filled out like usernames, passwords, domain names, and optional services. If they are not filled out, the required ones will be prompted on execution. After inputs are received, the installation will continue unattended.

After completing the variables (or not), run it with any of the following as root:<br>
\# source setup.sh<br>
\# bash setup.sh<br>
\# ./setup.sh<br>
\# . ./setup.sh<br>
 
The script will reboot at the end if selinux is enabled. Custom functions will be in root's .bashrc file<br>

Depending on how much source is compiled, the install can take between 5-30 minutes. Most of this time is spent compiling PHP and Python.<br>

###Features<br>
####Automagically installed and configured:<br>
  * NGINX
  * PHP-FPM
  * BIND9 (named)
  * MySQL (MariaDB)
  * yum
  * SSH
  * selinux
  * Firewalld
  * clamd
  * Python

####Custom bash functions added to root's .bashrc for easy server administration:<br>
  * Adds a new site to NGINX and PHP-FPM. the -nophp flag will prevent an FPM site from being made.<br>
<code>add\_site \<domain name\> -nophp</code><br>
  * Removes a site from NGINX and PHP-FPM<br>
<code>remove\_site \<domain_name\></code><br>
  * Creates a zone pointer and zone file for the domain<br>
 <code>add_dns \<domain name\></code><br>
  * Removes a zone pointer and zone file for the domain<br>
<code>remove_dns \<domain name\></code><br>
  * Installs WordPress to the domain specified. The domain must already be installed to the server.<br>
<code>install_wp \<domain name\></code><br>
  * Reloads or starts a process with systemctl depending on if it is running already.<br>
<code>rezload \<process name\></code><br>

####Fully featured latest stable PHP configuration, including imap
  * A seperate CGI pool ran by seperate users for each site

<code>./configure --enable-fpm --disable-cgi --enable-opcache \\</code><br>
<code>--without-apache \\</code><br>
<code>--enable-mbstring  --enable-sockets --enable-calendar --enable-inline-optimization --enable-exif --enable-gd-native-ttf enable-zip --enable-bcmath \\</code><br>
<code>--with-curl --with-gd  --with-zlib  --with-mcrypt --with-mysql --with-mysqli --with-pdo-mysql --with-mhash \\</code><br> 
<code>--with-imap=/usr/local/php-imap --with-imap-ssl --with-kerberos --with-xsl --with-iconv --with-pspell \\</code><br>
<code>--with-xmlrpc --with-openssl --with-jpeg-dir=/usr/include/libpng10/png.h</code>

