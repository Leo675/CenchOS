#!/bin/bash
#CenchOS Alpha 0.3
#For CentOS 7+ 64 bit (There is no official 32 bit version)
#Author: Leo675
#------------------------------------------------------------------------------------#
############# Fill out variables with your server specific information #############

#Alpha: Does not work with multiple external interfaces yet. Find your interface and IP with 'ip addr'
interface='eth0'
#External IP address to make sites, DNS records, and firewall rules for	
ipAddress='127.0.0.1'

#NGINX is the only supported web server for now, change to "no" for none
webServer='nginx'
	webRoot='/opt/html'
	#Comma seperated, www sub-domain will be added automatically, IP address is ok too
	siteList='yoursitegoeshere.com'

#Configures DNS server for all sites with working name servers
installBind='yes'

#SSH user credentials, root will not be allowed to log in
sshUser=''
sshUserPass=''
sshPort=''
hostName=''


#Only mariadb supported currently, 'no' for nothing
sqlServer='mariadb'
	#blank is ok if no mysql server is selected
	mysqlRootPW=''

#Alpha: Only American offsets supported, and region may be the wrong state in the same zone. It will use UTC otherwise.
timezoneGMToffset='-7'
DSTenabled='false'

#Installs the latest stable version of PHP (might add older version support later)
phpVersion='latest'
phpHandler='phpfpm'
#Sets selinux to Enforcing and fixes it for nginx/php-fpm sockets
enableSElinux='yes'
#The latest stable version of Python 2 will be altinstalled to /usr/local to prevent breaking the system
installPython2="no"
#Installs the latest stable version of Python3, change to "no" for none.
installPython3="no"
#Set this to yes to update virus definitions at the end of the script. Run freshclam manually otherwise.
freshclam='no'
#Alpha: Auto detection of CPU cores will improve
cpuCores=1

############# Modifications not recommended below this line #############
#------------------------------------------------------------------------------------#

#Makes swap file for extra memory to prevent OOM during compiling etc.
dd if=/dev/zero of=/swapfile bs=1024 count=262144
mkswap /swapfile
chmod 0600 /swapfile
swapon /swapfile

## Function initialization (functions are at the bottom of the script) ##
#Alpha: better checks for functions will be added later
if [ -z "$(grep -F 'FUNCTION STORAGE' /root/.bashrc)" ]
then
	#root will have the functions by default
	echo "${DGREEN}Installing CenchOS functions to /root/.bashrc$NORMAL"
	fStart="$(grep -nE '^#+(END |)FUNCTION STORAGE' "$BASH_SOURCE" | cut -d':' -f1)"
	fEnd="$(echo "$fStart" | tail -1)"
	fStart="$(echo "$fStart" | head -1)"
	sed -n "$fStart,${fEnd}p" "$BASH_SOURCE" >> /root/.bashrc
	source /root/.bashrc
else
	echo "${DYELLOW}Functions already installed to /root/.bashrc$NORMAL"
	source /root/.bashrc
fi
#################### End function initialization #######################

## initial clean up of environment

#dotglob makes it so * in a directory with hidden files will get the hidden files too
shopt -s dotglob

######################User input parameter checking ######################

req_param sshUser "$sshUser" username
req_param sshUserPass "$sshUserPass" password
req_param sshPort "$sshPort" port
req_param hostName "$hostName" domain
req_param ipAddress "$ipAddress" ipv4

[ "$sqlServer" = 'mariadb' ] &&	req_param mysqlRootPW "$mysqlRootPW" password

###################### End of parameter checking ######################



# get cpu architecture and number of cores
if [ -z "$cpuCores" -o "$cpuCores" == "auto" ]
then
	#This is one style of multicore processors listing them, there will be another pattern of detection to be added later
	cpuCores="$(grep -Fm 1 'cpu cores' /proc/cpuinfo | grep -Eom 1 '[0-9]{1,2}')"
	if [ -z "$cpuCores" ]
	then
		#Basic user interaction to input number of cores
		until [ "$cpuCores" ]
		do
			echo -e "${DYELLOW}Automatic detection of CPU cores has failed.\n$CYAN""Input the number of CPU cores$WHITE:$NORMAL"
			read coreInput
            
			if [ -n "$(echo "$coreInput" | grep -Em1 "[0-9]{1,2}")" ]
			then
				cpuCores="$coreInput"
			fi
		done
	fi
fi

########################

## time zone settigs. Only does american time zones currently, otherwise will set to UTC
americaCheck=$(( -5 >= $timezoneGMToffset >= -8 ))

#Disabled/Incomplete: not fully working European time zone detection
#grep -lEr '(CET|EET|BST|GMT)0.*M3.5.0/{0,1}[1-4]{0,1},M10.5.0/{0,1}[1-4]{0,1}' /usr/share/zoneinfo/Europe

if [ "$americaCheck" -eq 1 ]
then
	echo "${DGREEN}American time zone detected$NORMAL"
	ameriZone="$(echo $timezoneGMToffset | grep -Eom 1 '[5-8]')"
	if [ "$DSTenabled" = 'true' ]
	then
		echo "$CYAN""DST enabled$NORMAL"
		\rm /etc/localtime
		\cp -f "$(grep -lEr '(GMT|PST|EST|EDT|MST|MDT|CST|CDT)'"$ameriZone"'.*M3.2.0,M11.1.0' /usr/share/zoneinfo/America | head -1)" /etc/localtime
	elif [ "$DSTenabled" = 'false' ]
	then
		echo "$CYAN""DST disabled$NORMAL"
		\rm /etc/localtime
		ln -s "$(grep -lEr '(GMT|PST|EST|MST|CST)'"$ameriZone"'$' /usr/share/zoneinfo/America | tail -1)" /etc/localtime
	fi
else 
	echo "${DYELLOW}non-American time zone detected, selecting$CYAN UTC$DYELLOW time zone$NORMAL"
	\rm /etc/localtime
	ln -s /usr/share/zoneinfo/UTC /etc/localtime
fi

## sets hostame and maps hosts to /etc/hosts
hostname "$hostName"
echo "$siteList" | sed -e 's% %%g' -e 's%,%\n%g' | sed -r '/[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}/d' | while read hostMap
	do if [ -z "$(grep -m 1 "$ipAddress $hostMap www.$hostMap" /etc/hosts)" ]
		then
			echo "$ipAddress $hostMap www.$hostMap" >> /etc/hosts
			echo -e "${DGREEN}adding$WHITE:\n$CYAN$ipAddress $hostMap www.$hostMap$DGREEN\nto /etc/hosts$NORMAL"
		else
			echo "${DYELLOW}host $CYAN$hostMap$DYELLOW is already mapped in /etc/hosts$NORMAL"
	fi
done

##Security and optimization of /etc/sysctl.conf
#Make sure ASLR is enabled at highest level
conf_set 'kernel.randomize_va_space = 2' 'kernel.randomize_va_space\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Increase system file descriptor limit
conf_set 'fs.file-max = 65535' 'fs.file-max\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Increase system IP port limits
conf_set 'net.ipv4.ip_local_port_range = 2000 65000' 'net.ipv4.ip_local_port_range\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Controls the System Request debugging functionality of the kernel
conf_set 'kernel.sysrq = 0' 'kernel.sysrq\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Controls whether core dumps will append the PID to the core filename
conf_set 'kernel.core_uses_pid = 1' 'kernel.core_uses_pid\s*=.*' 'LASTLINE' /etc/sysctl.conf
#Allow for more PIDs
conf_set 'kernel.pid_max = 65536' 'kernel.pid_max\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Turn on syncookies for SYN flood attack protection
conf_set 'net.ipv4.tcp_syncookies = 1' 'net.ipv4.tcp_syncookies\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'net.ipv4.tcp_synack_retries = 2' 'net.ipv4.tcp_synack_retries\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Ignore all ICMP ECHO and TIMESTAMP requests sent to it via broadcast/multicast
conf_set 'net.ipv4.icmp_echo_ignore_broadcasts = 1' 'net.ipv4.icmp_echo_ignore_broadcasts\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Turn on and log spoofed, source routed, and redirect packets
conf_set 'net.ipv4.conf.all.log_martians = 1' 'net.ipv4.conf.all.log_martians\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Accept packets with SRR option? No
conf_set 'net.ipv4.conf.all.accept_source_route = 0' 'net.ipv4.conf.all.accept_source_route\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'net.ipv4.conf.default.accept_source_route = 0' 'net.ipv4.conf.default.accept_source_route\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Turn on protection for bad icmp error messages
conf_set 'net.ipv4.icmp_ignore_bogus_error_responses = 1' 'net.ipv4.icmp_ignore_bogus_error_responses\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Accept Redirects? No, this is not router
conf_set 'net.ipv4.conf.all.accept_redirects = 0' 'net.ipv4.conf.all.accept_redirects\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'net.ipv4.conf.all.secure_redirects = 0' 'net.ipv4.conf.all.secure_redirects\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'net.ipv4.conf.default.accept_redirects = 0' 'net.ipv4.conf.default.accept_redirects\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'net.ipv4.conf.default.secure_redirects = 0' 'net.ipv4.conf.default.secure_redirects\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Don't act as a router
conf_set 'net.ipv4.ip_forward = 0' 'net.ipv4.ip_forward\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'net.ipv4.conf.all.send_redirects = 0' 'net.ipv4.conf.all.send_redirects\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'net.ipv4.conf.default.send_redirects = 0' 'net.ipv4.conf.default.send_redirects\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Enable source validation by reversed path, as specified in RFC1812
conf_set 'net.ipv4.conf.all.rp_filter = 1' 'net.ipv4.conf.all.rp_filter\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'net.ipv4.conf.default.rp_filter = 1' 'net.ipv4.conf.default.rp_filter\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Number of Router Solicitations to send until assuming no routers are present.
conf_set 'net.ipv6.conf.default.router_solicitations = 0' 'net.ipv6.conf.default.router_solicitations\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Accept Router Preference in RA?
conf_set 'net.ipv6.conf.default.accept_ra_rtr_pref = 0' 'net.ipv6.conf.default.accept_ra_rtr_pref\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Learn Prefix Information in Router Advertisement
conf_set 'net.ipv6.conf.default.accept_ra_pinfo = 0' 'net.ipv6.conf.default.accept_ra_pinfo\s*=.*' 'LASTLINE' /etc/sysctl.conf
# Setting controls whether the system will accept Hop Limit settings from a router advertisement
conf_set 'net.ipv6.conf.default.accept_ra_defrtr = 0' 'net.ipv6.conf.default.accept_ra_defrtr\s*=.*' 'LASTLINE' /etc/sysctl.conf
#router advertisements can cause the system to assign a global unicast address to an interface
conf_set 'net.ipv6.conf.default.autoconf = 0' 'net.ipv6.conf.default.autoconf\s*=.*' 'LASTLINE' /etc/sysctl.conf
#how many neighbor solicitations to send out per address?
conf_set 'net.ipv6.conf.default.dad_transmits = 0' 'net.ipv6.conf.default.dad_transmits\s*=.*' 'LASTLINE' /etc/sysctl.conf
# How many global unicast IPv6 addresses can be assigned to each interface?
conf_set 'net.ipv6.conf.default.max_addresses = 1' 'net.ipv6.conf.default.max_addresses\s*=.*' 'LASTLINE' /etc/sysctl.conf
conf_set 'root soft nofile 65535' '^\#*\s*root soft nofile.*' 'LASTLINE' /etc/security/limits.conf
conf_set 'root hard nofile 65535' '^\#*\s*root hard nofile.*' 'LASTLINE' /etc/security/limits.conf


if [ "$webServer" = 'nginx' ]
then
	#Soft and hard file descriptor limits for root and nginx
	conf_set 'nginx soft nofile 20480' '^\#*\s*httpd soft nofile.*' 'LASTLINE' /etc/security/limits.conf
	conf_set 'nginx hard nofile 30720' '^\#*\s*httpd hard nofile.*' 'LASTLINE' /etc/security/limits.conf
fi

##yum configuration
echo "${DGREEN}Enabling Plus in Base repo$NORMAL"
sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/CentOS-Base.repo
#The yum plugin fastestmirror tends to cause problems.
echo "${DGREEN}Disabling yum plugin$WHITE:$DGREEN fastestmirror$NORMAL"
sed -i 's/enabled=1/enabled=0/g' /etc/yum/pluginconf.d/fastestmirror.conf

#Presto doesn't usually come default any more, but just in case.
if [ -f "/etc/yum/pluginconf.d/presto.conf" ]
then
	echo "${DGREEN}Disabling yum plugin$WHITE:$DGREEN presto$NORMAL"
	sed -i 's/enabled=1/enabled=0/g' /etc/yum/pluginconf.d/presto.conf
fi

#Installs latest EPEL yum repo
echo "${DGREEN}Installing/Updating latest EPEL repo and setting priority$NORMAL"
yum -y install wget
epelVer="$(wget -O - http://dl.fedoraproject.org/pub/epel/7/x86_64/e/ 2>/dev/null | grep -m 1 -oE  '"epel-release-[0-9]-[0-9]\.noarch\.rpm"' | tail -1 | sed 's,",,g')"
rpm -Uvh "http://dl.fedoraproject.org/pub/epel/7/x86_64/e/$epelVer" 
rpm --import http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7

#Installs latest RepoForge yum repo
# echo "${DGREEN}Installing/Updating latest RepoForge repo and setting priority$NORMAL"
# rpmforgeVer="$(wget -O - http://pkgs.repoforge.org/rpmforge-release/ 2>/dev/null | grep -Eo 'rpmforge-release-[0-9]\.[0-9]\.[0-9]-[0-9]\.el7\.rf\.x86_64\.rpm' | tail -1)"
# rpm -Uvh "http://pkgs.repoforge.org/rpmforge-release/$rpmforgeVer"


#Setting priorities
set_priority CentOS-Base.repo 10 'releasever/os/$basearch'
set_priority CentOS-Base.repo 10 'updates/$basearch'
set_priority CentOS-Base.repo 10 'extras/$basearch'
set_priority CentOS-Base.repo 10 'centosplus/$basearch'
set_priority epel.repo 30 'epel/7/$basearch'
set_priority rpmforge.repo 20 'en/$basearch/rpmforge'

yum -y install yum-priorities
#This removes a line from yum.conf that usually is not there to begin with, but I have seen it on some VPS images. It will prevent kernel headers from being downloaded.
sed -ri 's%^exclude=kernel%#exclude=kernel%g' /etc/yum.conf
yum -y update

[ "$antiVirus" = 'clamd' ] && toInstall='clamd'
[ "$antiVirus" = 'clamav' ] && toInstall='clamav'


yum install -y bind-utils jwhois wget openssl-devel git subversion make bzip2-devel which gcc gcc-c++ zip libtool make automake screen perl pcre-devel bison flex yum-utils iptables-devel libnet10-devel "$toInstall"

useradd "$sshUser" -d "/home/$sshUser" -m
echo -e "$sshUserPass\n$sshUserPass" | passwd "$sshUser"

#adds user to sudoers
echo "$sshUser ALL=(ALL)   ALL" >> /etc/sudoers

echo "${DGREEN}Configuring SSH$NORMAL"
sed -i "s/#Port 22/Port $sshPort/" /etc/ssh/sshd_config
sed -i "s/#PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
sed -i "s/#X11Forwarding yes/X11Forwarding no/" /etc/ssh/sshd_config
sed -i "s/#UseDNS yes/UseDNS no/g" /etc/ssh/sshd_config
sed -i "s/#Port 22/Port $sshPort/" /etc/ssh/sshd_config
conf_set 'PasswordAuthentication yes' '#?PasswordAuthentication no' 'NOADD' /etc/ssh/sshd_config

if [ -z "$(grep -m 1 "AllowUsers $sshUser" /etc/ssh/sshd_config)" ]
then
	echo "AllowUsers $sshUser" >> /etc/ssh/sshd_config
else
	echo "${DYELLOW}user $CYAN$sshUser$DYELLOW already allowed to ssh$NORMAL"
fi

systemctl restart sshd

#Start and wait for firewalld to start
echo "${DGREEN}Starting firewalld$NORMAL"
firewalld
until [ "$(firewall-cmd --query-panic | sed -r 's/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g')" != 'FirewallD is not running' ]
do 
	echo "${DYELLOW}Waiting for firewalld to start...$NORMAL"
	sleep 1
done


echo "${DGREEN}Opening ports for required services on interface $CYAN$interface$NORMAL"
firewall-cmd --zone=public --change-interface="$interface"
firewall-cmd --permanent --zone=public --change-interface="$interface"

echo "1 -i lo -j ACCEPT
10 ! -i lo -d 127.0.0.0/8 -j DROP
1 -m state --state ESTABLISHED,RELATED -j ACCEPT
3 -p icmp -m icmp --icmp-type 8 -j ACCEPT
4 -p tcp ! --syn -m state --state NEW -j DROP" | while read x
do
firewall-cmd --permanent --direct --add-rule ipv4 filter public $x
done

#ssh
echo "${DGREEN}SSH$CYAN TCP$WHITE:$CYAN $sshPort$NORMAL"
firewall-cmd --permanent --zone=public --add-port="$sshPort"/tcp

#dns
echo "${DGREEN}DNS$CYAN IP$WHITE:$CYAN 53$NORMAL"
firewall-cmd --permanent --zone=public --add-service=dns

#Web Server
if [ "$webServer" = 'nginx' ]
then
	echo "${DGREEN}NGINX$CYAN TCP$WHITE:$CYAN 80 443$NORMAL"
	firewall-cmd --permanent --zone=public --add-service=http --add-service=https
fi
#Mail server (unused yet)
#firewall-cmd --zone=external --add-port=25/tcp --add-port=465/tcp --add-port=143/tcp --add-port=993/tcp --add-port=110/tcp --add-port=995/tcp

#minor DOS protection
firewall-cmd --permanent --direct --add-rule ipv4 filter public 0 -m limit --limit 5/m --limit-burst 14 -j LOG --log-prefix 'iptables denied: ' --log-level 7

firewall-cmd --permanent --direct --add-rule ipv4 filter public 99 -j DROP
firewall-cmd --reload
systemctl enable firewalld.service

[ "$freshclam" = 'yes' ] && freshclam

## install latest Python 2 to /usr/local
if [ "$installPython2" = 'yes' ]
then
	cd /usr/local/src/
	py2Ver="$(wget -O - https://www.python.org/ftp/python/ 2>/dev/null | grep -Eo '2\.[0-9]{1,2}\.[0-9]{1,2}' | tail -4 | sort | uniq)"
	echo "$py2Ver" | while read pSearch
	do
		echo "pSearch is $pSearch"
		releaseVer="$(wget -O - "https://www.python.org/ftp/python/$pSearch" 2>/dev/null | grep -Eo 'Python-2\.[0-9]{1,2}\.[0-9]{1,2}\.tgz' | head -1)"
		echo "releaseVer is $releaseVer"
		if [ -n "$releaseVer" -a -z "$pyFound" ]
		then
			wget "https://www.python.org/ftp/python/$pSearch/$releaseVer"
			pyFound=1
		fi
	done
	tar xzf Python-2.7*.tgz
	cd Python-2.7*
	cd Modules/zlib
	./configure 
	make
	make install
	cd ../..
	./configure --prefix=/usr/local
	make
	make altinstall
	cd ~
	\rm -rf /usr/local/src/Python-2.7*
fi

## install latest Python 3
if [ "$installPython3" = 'yes' ]
then
	cd /usr/local/src/
	py3Ver="$(wget -O - https://www.python.org/ftp/python/ 2>/dev/null | grep -Eo '3\.[0-9]{1,2}\.[0-9]{1,2}' | tail -1)"
	wget "https://www.python.org/ftp/python/$py3Ver/Python-$py3Ver.tgz"
	tar xzf Python-3*.tgz
	cd Python-3*
	cd Modules/zlib
	./configure
	make
	make install
	cd ../..
	./configure # --bindir=/usr/bin --sbindir=/usr/sbin  --sysconfdir=/etc --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --datarootdir=/usr/share --includedir=/usr/include
	make
	make install
	cd ~
	\rm -rf /usr/local/src/Python-3.4*
fi

#Install python pip (package manager)
if [ "$updatePython2" = 'yes' -o "$installPython3" = 'yes' ]
then
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
\rm get-pip.py
fi

##Install web server
if [ "$webServer" = 'nginx' ]
then
	#Installs official NGINX repo
	if [ ! -f /etc/yum.repos.d/nginx.repo ]
	then
		echo "${DGREEN}Installing official NGINX repo$NORMAL"
		nginxURI="$(wget -O - http://nginx.org/packages/centos/7/noarch/RPMS/ 2>/dev/null | grep -Eo 'nginx-release-centos-7-[0-9]{1,2}\.el7\.ngx.noarch.rpm' | tail -1)"
		rpm -Uvh "http://nginx.org/packages/centos/7/noarch/RPMS/$nginxURI"
		set_priority nginx.repo 50 'http://nginx.org/packages/centos/7/$basearch/'
		yum update
	else
		echo "${DYELLOW}NGINX repo already installed$NORMAL" 
	fi
	if [ ! -f '/etc/nginx/nginx.conf' ]
	then
		echo "${DGREEN}Installing NGINX$NORMAL"
		yum -y install nginx
		mkdir -p "$webRoot"
		#chcon -R -u system_u -r object_r -t httpd_sys_rw_content_t "$webRoot"
		
		sed -i '/keepalive_timeout  65;/d' /etc/nginx/nginx.conf
	else
		echo '${DYELLOW}nginx is already installed$NORMAL'
	fi
	
	#########bashrc conf########
	conf_set "webRoot=$webRoot" "webRoot\s*=.*" 'LASTLINE' /root/.bashrc
	conf_set "webServer=nginx" "webServer\s*=.*" 'LASTLINE' /root/.bashrc
	############################
	
	conf_set "worker_processes  $cpuCores;" 'worker_processes\s+.*' 'NOADD' /etc/nginx/nginx.conf
	#leaving this error report on for now
	conf_set 'open_file_cache_errors on;' '#?open_file_cache_errors\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'open_file_cache max=10000 inactive=20s;' '#?open_file_cache\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'open_file_cache_valid 30s;' '#?open_file_cache_valid\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'open_file_cache_min_uses 2;' '#?open_file_cache_min_uses\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'gzip_proxied any;' '#?gzip_proxied\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'gzip_comp_level 4;' '#?gzip_comp_level\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;' '#?gzip_types\s+.*'  'http {' /etc/nginx/nginx.conf
	conf_set 'gzip  on;' '#?gzip\s+(on|off)\s*;' 'http {' /etc/nginx/nginx.conf
	conf_set 'reset_timedout_connection on;' '#?reset_timedout_connection\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'send_timeout 30;' '#?send_timeout\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'client_header_timeout 30;' '#?client_header_timeout\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'client_body_timeout 30;' 'client_body_timeout\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'keepalive_timeout 30;' '#?keepalive_timeout\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'tcp_nodelay on;'  '#?tcp_nodelay\s+.*' 'http {' /etc/nginx/nginx.conf		
	conf_set 'tcp_nopush     on;' '#?tcp_nopush\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'client_max_body_size 20m;' '#?client_max_body_size\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'server_tokens off;' '#?server_tokens\s+.*' 'http {' /etc/nginx/nginx.conf
	conf_set 'client_body_buffer_size 128k;' '#?client_body_buffer_size\s+.*' 'http {' '/etc/nginx/nginx.conf'
	conf_set 'sendfile on;' '#?sendfile\s+.*;' 'http {' /etc/nginx/nginx.conf
    # Temp fix
	mkdir -p "/var/log/nginx/log/"
	
	#Removes defaul nginx site
	remove_conf 'server\s+\{' '^    \}$' /etc/nginx/nginx.conf
    echo '}' >> /etc/nginx/nginx.conf
	#deprecated
	# if [ -f "/etc/nginx/conf.d/default.conf" ]
	# then
		# \rm -v "/etc/nginx/conf.d/default.conf"
	# else
		# echo "${DYELLOW}default nginx site already removed$NORMAL"
	# fi	
fi

#Checks for all supported php handlers, but only phpfpm is currently supported
if [ "$phpHandler" = 'phpfpm' ]
then

	#.bashrc setting
	conf_set "phpHandler=$phpHandler" "phpHandler\s*=.*" 'LASTLINE' /root/.bashrc	

	#installing php-imap from source
	cd /usr/local/src/
	if [ -f '/usr/local/src/imap-2007f.tar.gz' ]
	then
		echo 'php-imap already downloaded, skipping download'
	else
		wget ftp://ftp.cac.washington.edu/imap/imap-2007f.tar.gz
	fi

	tar zxf imap-2007f.tar.gz
	cd imap-2007f/
	#configuring PHP-IMAP Makefile for this CentOS environment
	perl -pi -e 's#SSLDIR=/usr/local/ssl#SSLDIR=/etc/pki/tls#' src/osdep/unix/Makefile
	perl -pi -e 's#SSLINCLUDE=\$\(SSLDIR\)/include#SSLINCLUDE=/usr/include/openssl#' src/osdep/unix/Makefile
	perl -pi -e 's#SSLLIB=\$\(SSLDIR\)/lib#SSLLIB=/usr/lib/openssl#' src/osdep/unix/Makefile
	if [ "$architecture" = 'x86_64' ]
	then
		make slx EXTRAAUTHENTICATORS=gss
	else
		make slx EXTRACFLAGS=-fPIC EXTRAAUTHENTICATORS=gss
	fi
	#copying made files to installation directory
	mkdir -p /usr/local/php-imap/include
	mkdir -p /usr/local/php-imap/lib
	\cp -f c-client/*.h /usr/local/php-imap/include/
	\cp -f c-client/*.c /usr/local/php-imap/lib/
	\cp -f c-client/*.h /usr/local/php-imap/
	\cp -f c-client/*.c /usr/local/php-imap/
	\cp -f c-client/c-client.a /usr/local/php-imap/lib/libc-client.a
	#PHP-IMAP cleanup
	\rm -rf /usr/local/src/imap*


	#making PHP from source
	cd /usr/local/src
	#finds latest version of php
	phpVersion="$(wget -O - http://php.net/downloads.php 2>/dev/null | grep -Eo "php-[0-9]\.[0-9]\.[0-9]{1,2}\.tar\.gz" | head -1)"
	wget "http://www.php.net/get/$phpVersion/from/us1.php.net/mirror"
	tar -xzf mirror
	cd php-*
	#Redundant check, because this is where different PHP handlers can be inserted or maybe the configure command will become dynamic
	if [ "$phpHandler" = "phpfpm" ]
	then
		yum -y install libcurl-devel libxml2-devel libjpeg-devel libpng-devel libc-client-devel aspell-devel libmcrypt-devel libxslt-devel

		#libtiff-devel
        ./configure --enable-fpm --disable-cgi --enable-opcache \
        --without-apache \
        --enable-mbstring  --enable-sockets --enable-calendar --enable-inline-optimization --enable-exif --enable-gd-native-ttf --enable-zip --enable-bcmath \
        --with-curl --with-gd  --with-zlib  --with-mcrypt --with-mysql --with-mysqli --with-pdo-mysql --with-mhash --with-pspell --with-imap=/usr/local/php-imap --with-imap-ssl --with-kerberos --with-xsl --with-iconv --with-xmlrpc --with-openssl \
        --with-jpeg-dir=/usr/include/libpng10/png.h
		make
		make install
		#cp ./modules/opcache.so /usr/local/lib/php/extensions/no-debug-non-zts-20121212/
		\cp -f sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm
		chmod 755 /etc/init.d/php-fpm
		mkdir /etc/fpm.d
		\cp -f /usr/local/etc/php-fpm.conf.default /usr/local/etc/php-fpm.conf
		sed -i ':a;N;$!ba;s/Pool Definitions.*//g' /usr/local/etc/php-fpm.conf
		conf_set 'include=/etc/fpm.d/\*.conf' ';?include=.*' '\[global\]' /usr/local/etc/php-fpm.conf
		#conf_set 'emergency_restart_threshold = 10' ';?emergency_restart_threshold\s*=.*' 'NOADD' /usr/local/etc/php-fpm.conf
		#conf_set 'emergency_restart_interval = 1m' ';?emergency_restart_interval\s*=.*' 'NOADD' /usr/local/etc/php-fpm.conf
		#conf_set 'process_control_timeout = 10s' ';?process_control_timeout\s*=.*' 'NOADD' /usr/local/etc/php-fpm.conf
		\cp -f php.ini-production /usr/local/lib/php.ini
		sed -i '/user_ini.filename/d' /usr/local/lib/php.ini
		
		conf_set 'mysql.default_socket = /var/lib/mysql/mysql.sock' 'mysql.default_socket\s*=.*' '; http://php.net/mysql.default-socket' /usr/local/lib/php.ini
        conf_set 'mysqli.default_socket = /var/lib/mysql/mysql.sock' 'mysqli.default_socket =.*' '\[MySQLi\]'  /usr/local/lib/php.ini
        conf_set 'pdo_mysql.default_socket = /var/lib/mysql/mysql.sock' 'pdo_mysql.default_socket =.*' '\[Pdo_mysql\]' /usr/local/lib/php.ini
		conf_set 'opcache.enable_cli=1' ';?opcache.enable_cli\s*=.*' '; End:' /usr/local/lib/php.ini
		conf_set 'opcache.fast_shutdown=1' ';?opcache.fast_shutdown\s*=.*' '; End:' /usr/local/lib/php.ini
		conf_set 'opcache.revalidate_freq=60' ';?opcache.revalidate_freq\s*=.*' '; End:' /usr/local/lib/php.ini
		conf_set 'opcache.max_accelerated_files=4000' ';?opcache.max_accelerated_files\s*=.*' '; End:' /usr/local/lib/php.ini
		conf_set 'opcache.memory_consumption=128' ';?opcache.memory_consumption\s*=.*' '; End:' /usr/local/lib/php.ini
		conf_set 'zend_extension=opcache.so' ';?zend_extension\s*=.*' '; End:' /usr/local/lib/php.ini
		conf_set 'opcache.enable=On' ';?opcache.enable\s*=.*' 'NOADD' /usr/local/lib/php.ini
		conf_set 'opcache.interned_strings_buffer=8' ';?opcache.interned_strings_buffer\s*=.*' '; End:' /usr/local/lib/php.ini

	fi
fi

#start web services
if [ "$phpHandler" = "phpfpm" ]
then
	rezload php-fpm
	systemctl enable php-fpm
fi

if [ "$webServer" = "nginx" ]
then
	rezload nginx
	systemctl enable nginx
fi

#Installs MariaDB server
if [ "$sqlServer" = 'mariadb' ]
then
	echo "${DGREEN}Installing MySQL Server$WHITE:$CYAN MariaDB$NORMAL"
	yum -y install mariadb-server mariadb-devel
	
	systemctl start mariadb
	systemctl enable mariadb
	
	#Automated version of mysql_secure_installation
	mysql -e "DELETE FROM mysql.user WHERE User='';"
	mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
	mysql -e "DROP DATABASE test;"
	mysql -e "UPDATE mysql.user SET Password=PASSWORD('$mysqlRootPW') WHERE User='root';"
	mysql -e 'FLUSH PRIVILEGES;'
	
	#my.cnf configurations
	conf_set 'user=mysql' 'user\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'thread_cache_size=16K' 'thread_cache_size\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'low_priority_updates=1' 'low_priority_updates\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'concurrent_insert=2' 'concurrent_insert\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'tmp_table_size=64M' 'tmp_table_size\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'max_heap_table_size=64M' 'max_heap_table_size\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'query_cache_limit=128M' 'query_cache_limit\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'table_cache=2K' 'table_cache\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'table_definition_cache=5K' 'table_definition_cache\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'open_files_limit=4K' 'open_files_limit\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'key_buffer=64M' 'key_buffer\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'long_query_time=5' 'long_query_time\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'local-infile=0' 'local-infile\s*=.*' '\[mysqld\]' /etc/my.cnf
	conf_set 'innodb_file_per_table' 'innodb_file_per_table\s*' '\[mysqld\]' /etc/my.cnf
	conf_set 'bind-address=127.0.0.1' 'bind-address\s*=.*' '\[mysqld\]' /etc/my.cnf
	systemctl restart mariadb
fi

if [ "$installBind" = 'yes' ]
then
	yum -y install bind bind-chroot
	systemctl stop named
	conf_set 'listen-on port 53  { any; };' 'listen-on\s+port\s+53\s+\{.*' 'options {' /etc/named.conf
	conf_set 'listen-on-v6 port 53  { any; };' 'listen-on-v6\s+port\s+53\s+\{.*' 'options {' /etc/named.conf
	conf_set 'allow-query     { any; };' 'allow-query\s+\{.*' 'options {' /etc/named.conf
	#Alpha: will add a better way of detecting options here
	if [ -z "$(grep -Em1 "^OPTIONS=" /etc/sysconfig/named)" ]
	then
		echo "OPTIONS=\"-n $cpuCores\"" >> /etc/sysconfig/named
	fi

	
	#Loop to create zone files and pointers
	echo "$siteList" | sed -e 's% %%g' -e 's%,%\n%g' | sed -r '/[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}\.[1-2]{0,1}[0-9]{0,1}[0-9]{1}/d' | grep -Eo "^[a-zA-Z0-9\-]{1,255}\.[a-zA-Z0-9\-]{1,255}$" | uniq | while read zoneList
	do
		add_dns "$zoneList"
	done
	systemctl enable named
fi

if [ "$enableSElinux" = 'yes' ]
then
	yum -y install selinux-policy-targeted selinux-policy libselinux libselinux-python libselinux-utils policycoreutils setroubleshoot setroubleshoot-server setroubleshoot-plugin
	if [ "$phpHandler" = 'phpfpm' -o "$webServer" = 'nginx' ]
	then
	#grep nginx /var/log/audit/audit.log | audit2allow -M nginx
#############SELINUX POLICY###############
echo -e 'module nginx 1.0;\n
require {
        type var_run_t;
        type httpd_t;
        type usr_t;
        type initrc_t;
        class sock_file write;
        class unix_stream_socket connectto;
        class file append;
}\n
#============= httpd_t ==============
allow httpd_t initrc_t:unix_stream_socket connectto;
allow httpd_t var_run_t:sock_file write;
allow httpd_t usr_t:file append;' > nginx.te
##############SELINUX POLICY##################
checkmodule -M -m -o nginx.mod nginx.te
semodule_package -o nginx.pp -m nginx.mod
semodule -i nginx.pp
\rm -f nginx.pp nginx.te nginx.mod
	fi
	conf_set 'SELINUX=Enforcing' '^\s*SELINUX\s*=.*' 'LASTLINE' /etc/selinux/config
fi
#Loop to create websites with self signed certs
if [ "$webServer" = 'nginx' ]
then
	echo "$siteList" | sed -e 's% %%g' -e 's%,%\n%g' | while read siteToAdd
	do
		add_site "$siteToAdd"
	done
fi
exit 0

#############FUNCTION STORAGE#################

##Colors for custom output
#Fatal errors
RED="$(echo -en '\e[0;31m')"
#Fatal error description
LRED="$(echo -en '\e[1;31m')"
#Success
DGREEN="$(echo -en '\e[0;32m')"
#Warnings/Notifications
DYELLOW="$(echo -en '\e[0;33m')"
#Variables
CYAN="$(echo -en '\e[0;36m')"

#Other
YELLOW="$(echo -en '\e[1;33m')"
GREEN="$(echo -en '\e[1;32m')"
NORMAL="$(echo -en '\e[00m')"
BLUE="$(echo -e '\e[1;34m')"
DBLUE="$(echo -en '\e[0;34m')"
LCYAN="$(echo -en '\e[1;36m')"
WHITE="$(echo -en '\e[1;37m')"
PURP="$(echo -en '\e[0;35m')"

##############DEPENDABLE FUNCTIONS#################
#Function for changing or adding new configurations to files
conf_set()
{
	toAdd="$1"
	checkFor="$2"
	whereToAdd="$3"
	filePath="$4"
	oldValue="$(grep -Eom1 "$checkFor" "$filePath")"
	if [ -z "$oldValue" ]
	then
		if [ "$whereToAdd" = 'LASTLINE' ]
		then
			echo "${DGREEN}Adding $CYAN$toAdd$DGREEN to the last line of $CYAN$filePath$NORMAL"
			echo "$toAdd" >> "$filePath"
		else
			echo "${DGREEN}Adding $CYAN$toAdd$DGREEN to $whereToAdd in $CYAN$filePath$NORMAL"

			sed -ir "s%$whereToAdd%$whereToAdd\n$toAdd%" "$filePath"
            return
		fi
	elif [ "$oldValue" != "$toAdd" ]
	then
		echo "${DGREEN}Changing $CYAN$oldValue$DGREEN to $CYAN$toAdd$DGREEN in $CYAN$filePath$NORMAL"
		sed -ri "s%$checkFor%$toAdd%" "$filePath"
	else
		echo "${DYELLOW}$CYAN$toAdd$DYELLOW already exists in $CYAN$filePath$NORMAL"
	fi
}

#Removes multiple lines of configurations based on start and finish point
remove_conf() {
	startConf="$1"
	endConf="$2"
	filePath="$3"

	conf="$(perl -ne "print if /$startConf/ .. /$endConf/" "$filePath")"
	[ -n "$conf" ] && echo -e "${DGREEN}Removing configurations in$WHITE:$CYAN $filePath\n$conf$NORMAL" &&
		perl -i -ne "print unless /$startConf/ .. /$endConf/" "$filePath"
	#Remove triple spaces and replace with double
	sed -i ':a;N;$!ba;s%\n\n\n%\n\n%g' "$filePath"
}

#Simple funtion to start or reload a process depending on if its running already
rezload() {
	procName="$1"
	if [ -z "$procName" ]
	then
		echo "${RED}No process name given to rezload$NORMAL"
		return
	fi
	if [ -n "$(ps -ef | grep -F "$procName" | grep -vF 'grep ')" ]
	then
		systemctl reload "$procName"
	else
		systemctl start "$procName"
	fi
}

##############END DEPENDABLE FUNCTIONS#################
#adds pointer to rfc1912.zones and zone file to /var/named with a default template (including name servers)
add_dns() {

	#Input assignment, clear errors
	domainName="$1"
	error=''
	#Input validation
	[ -z "$domainName" ] && error='Usage: add_dns <FQDN>\n'
	rPattern='(?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63}(?<!-))|((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})$)'
	[ -z "$(echo "$domainName" | grep -P "$rPattern")" ] && error="${error}${RED}Invalid domain name$WHITE:$CYAN $domainName $DYELLOW(did not pass regex check)$NORMAL"
	[ -n "$error" ] && echo -e "$error" && return

	if [ -z "$(grep "$domainName" /etc/named.rfc1912.zones)" ]
	then
		echo "${DGREEN}Creating zone pointer for $CYAN$domainName$DGREEN in /etc/named.rfc1912.zones$NORMAL"
		echo -e "zone \"$domainName\" in {\n  type master;\n  file \"$domainName\";\n};\n" >> /etc/named.rfc1912.zones
	else
		echo "${DYELLOW}Zone pointer for $CYAN$domainName$DYELLOW already exists in /etc/named.rfc1912.zones$NORMAL"
	fi
	if [ ! -f "/var/named/$domainName" ]
	then
		echo "${DGREEN}Creating zone file for $CYAN$domainName$DGREEN at $CYAN/var/named/$domainName$NORMAL"
		echo -e "\$ttl 38400\\n$domainName.        IN      SOA     $domainName. thebesttechever.gmail.com. (\\n         1326543200\\n         10800\\n         3600\\n         604800\\n         38400\\n )\\n$domainName.    IN    NS    ns1.$domainName.\\n$domainName.    IN    NS    ns2.$domainName.\\n$domainName.    IN    A    $ipAddress\\n*.$domainName.    IN    A    $ipAddress\\n*.$domainName.    IN    MX    20 mx.$domainName.\\n$domainName.    IN    MX    10 mx.$domainName." > "/var/named/$domainName"
		chown root:named "/var/named/$domainName"
		chmod 640 "/var/named/$domainName"
	else
		echo "${DYELLOW}Zone file for $CYAN$domainName$DYELLOW already exits at$CYAN /var/named/$domainName$NORMAL"
	fi
}
on_startup() {
	
	[ ! -d "/etc/rc.startup" ] && { mkdir '/etc/rc.startup'; chmod -R 700 '/etc/rc.startup'; chmod 700 '/etc/rc.local'; }
	conf_set 'find /etc/rc.startup -name "*.start" -exec {} \;' 'find /etc/rc.startup -name "\*.start" -exec \{\} \\;' 'LASTLINE' /etc/rc.local
	cmds="$2"
	name="$1.start"
	error=''
	[ -z "$cmds" ] && error="No command provided \$2\n"
	[ -z "$name" ] && error="${error}Provide script name \$1\n"

	[ -n "$error" ] && { echo -en "$error"; return; }
	
	pFlags="$(echo "$*" | grep -Eo "\-p\s+[^\s]+" | sed -r 's,-p\s+,,g')"
	echo "$flags" | {
		while read flag
		do
			case "$flag" in
				n) cmds="$cmds\n\\\\rm -f /etc/rc.startup/$name"
				;;
				*)
				;;
			esac
		done
		echo -e "$cmds" > "/etc/rc.startup/$name"
		chmod 700 "/etc/rc.startup/$name"
	}
}

#Function for adding new sites to nginx and php-fpm
add_site() {
	flags="$(echo "$2" | grep -Eo "\-[a-z]+" | sed 's,-,,g')"
	echo "flags are $flags"
	echo "$flags" | {
		while read flag
		do
			case "$flag" in
				nophp) nophp=1
				;;
			esac
		done

		vHost="$1"
		error=''
		[ -z "$vHost" ] && error="No site provided\n"

		[ -z "$webRoot" ] && error="${error}No \$webRoot found\n"
		
		[ -n "$error" ] && { echo -en "$error"; return; }
		
		echo "${DGREEN}Creating directories for $vHost$NORMAL"
		mkdir -p "$webRoot/$vHost/certs" "$webRoot/$vHost/tmp" "$webRoot/$vHost/Sessions" "$webRoot/$vHost/public_html" "$webRoot/$vHost/logs"
		#echo -e '#!/usr/bin/perl -w\nprint "Content-type: text/html\\n\\n";print "<html><head><title>Hello World!! </title></head>\\n";print "<body><h1>Hello world</h1></body></html>\\n";' > "$webRoot/$vHost/index.cgi"
		#chmod +x "$webRoot/$vHost/index.cgi"
		#echo '<?php phpinfo(); ?>' > "$webRoot/$vHost/public_html/index.php"
		useradd "$vHost"
		chown -R "$vHost:nginx" "$webRoot/$vHost"
		if [ "$(getenforce)" = 'Disabled' ]
		then
			on_startup "one_time_semod_$vHost" "semanage fcontext -a -t httpd_sys_rw_content_t \"$webRoot/$vHost(/.*)?\";restorecon -RF \"$webRoot/$vHost\"" -n
			touch /.autorelabel
		else
			semanage fcontext -a -t httpd_sys_rw_content_t "$webRoot/$vHost(/.*)?"	
			restorecon -RF "$webRoot/$vHost"
		fi
		openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=/L=/O=/CN=*.$vHost" -keyout "$webRoot/$vHost/certs/$vHost.key"  -out "$webRoot/$vHost/certs/$vHost.crt"
		################ NGINX SITE CREATION #######################
		if [ "$webServer" = 'nginx' ]
		then
			if [ -f "/etc/nginx/conf.d/$vHost.conf" ]
			then
				echo "vHost configuration for $vHost already exists in /etc/nginx/conf.d/$vHost.conf"
			else
				echo "creating vHost config file /etc/nginx/conf.d/$vHost.conf"	
				socketName='fpm'
################################ NGINX CONFIG FILE ############################
if [ "$phpHandler" != 'phpfpm' -o -n "$nophp" ]
then
	echo "${DYELLOW}PHP disabled for new site $CYAN$vHost$NORMAL"
	siteIndexes='index index.html index.htm index.shtml'
	cgiPass=''
else
	echo "${DGREEN}PHP enabled for new site $CYAN$vHost$NORMAL"
	siteIndexes='index index.php index.html index.htm index.shtml'
#########NGINX TO FPM FCGI PASS#################	
cgiPass='location ~ \.php$ {
root           '"$webRoot"'/'"$vHost"'/public_html;
fastcgi_pass   unix:'"/var/run/$vHost-$socketName.socket"'; 
fastcgi_index  index.php;
fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
include        fastcgi_params;'
#########END NGINX TO FPM FCGI PASS##############
fi
echo -e 'server {\n\nlisten 80;\nlisten 443 ssl;\nssl off;\nssl_certificate '"$webRoot/$vHost/certs/$vHost.crt"';
ssl_certificate_key '"$webRoot/$vHost/certs/$vHost.key"';\nserver_name  '"$vHost"' www.'"$vHost"';
access_log  '"$webRoot/$vHost/logs/$vHost.access.log"'  main;
location / {\n
root   '"$webRoot/$vHost/public_html"';
'"$siteIndexes"';\n 
}\n
error_page   500 502 503 504  /50x.html;\nlocation = /50x.html {\nroot   '"$webRoot"';\n 
}\n 
'"$cgiPass"'
}\n}' > "/etc/nginx/conf.d/$vHost.conf"
################################ END NGINX CONFIG FILE ########################

				touch "$webRoot/$vHost/logs/$vHost.access.log"
				chown nginx:nginx "$webRoot/$vHost/logs/$vHost.access.log"
				rezload nginx
			fi
		fi	
		############### END NGINX SITE CREATION #######################
		
		################ START PHPFPM SITE CREATION ##################
		#Creates separate pools for each site
		if [ "$phpHandler" = "phpfpm" ]
		then
			if [ -f "/etc/php-fpm.d/$vHost.conf" ]
			then
				echo "configuration file for $vHost already exists at /etc/php-fpm.d/$vHost.conf"
			else
				echo "making php-fpm pool for $vHost at /etc/php-fpm.d/$vHost.conf"
############################ PHPFPM CONFIG FILE ###########################
echo -e '['"$vHost"']\n\nlisten = '"/var/run/$vHost-fpm.socket"'
listen.allowed_clients = 127.0.0.1\n\nlisten.owner = '"$webServer"'
listen.group = '"$webServer"'\nlisten.mode = 0600\n
user = '"$vHost"'\ngroup = '"$vHost"'\npm = dynamic\npm.max_children = 4\npm.start_servers = 2
pm.min_spare_servers = 2\npm.max_spare_servers = 4\npm.max_requests = 400
request_terminate_timeout = 120s\nrlimit_files = 131072\nrlimit_core = unlimited
catch_workers_output = yes\nsecurity.limit_extensions =\n
env[HOSTNAME] = $HOSTNAME\nenv[PATH] = /usr/local/bin:/usr/bin:/bin\nenv[TMP] = /tmp
env[TMPDIR] = /tmp\nenv[TEMP] = /tmp\n\nslowlog = '"$webRoot/$vHost/logs/$vHost-php-slow.log"'
php_admin_value[error_log] = '"$webRoot/$vHost/logs/$vHost-php-error.log"'\n
php_admin_flag[log_errors] = on\nphp_value[session.save_handler] = files
php_value[session.save_path] = '"$webRoot/$vHost/Sessions"'' > "/etc/fpm.d/$vHost.conf"
########################## END PHPFPM CONFIG FILE ###########################
				rezload php-fpm
			fi
		fi
		############### END PHPFPM SITE CREATION
	}
}

install_wp() {
	siteName="$1"
	if [ -d "$webRoot/$siteName/public_html/" ]
	then
		## WORDPRESS
		wpdbName="$(randpass 15 0)"
		wpdbUser="$(randpass 15 0)"
		wpdbPW="$(randpass 30 0)"
		done=0
		
		until [ "$done" = 1 ]
		do
			echo "${DYELLOW}Input MySQL root user password to create new database$NORMAL"
			read -s mysqlRootPW
			if [ -n "$mysqlRootPW" ]
			then
				if [ -n "$(mysql -uroot -p"$mysqlRootPW" -e "SELECT USER(),CURRENT_USER();" | grep -F 'CURRENT_USER()')" ]
				then
					echo "password correct"
					done=1
				else
					echo "${DYELLOW}Incorrect mysql root password$NORMAL"
				fi
			fi
		done	
		
		mysqladmin -uroot -p"$mysqlRootPW" create "$wpdbName"
		query="GRANT ALL PRIVILEGES ON $wpdbName.* TO $wpdbUser@'localhost' IDENTIFIED BY \"$wpdbPW\";"
		mysql -uroot -p"$mysqlRootPW" -e "$query"
		cd /usr/local/src
		wget http://wordpress.org/latest.tar.gz
		tar xzf latest.tar.gz
		\cp -arf wordpress/* "$webRoot/$siteName/public_html"
		chown -R $siteName:nginx "$webRoot/$siteName/public_html"
		\mv "$webRoot/$siteName/public_html/wp-config-sample.php" "$webRoot/$siteName/public_html/wp-config.php"
		conf_set "define('DB_NAME', '$wpdbName');" "define\(\s*'DB_NAME'\s*,.*" 'MySQL settings -' "$webRoot/$siteName/public_html/wp-config.php"
		conf_set "define('DB_USER', '$wpdbUser');" "define\(\s*'DB_USER'\s*,.*" 'MySQL settings -' "$webRoot/$siteName/public_html/wp-config.php"
		conf_set "define('DB_PASSWORD', '$wpdbPW');" "define\(\s*'DB_PASSWORD'\s*,.*" 'MySQL settings -' "$webRoot/$siteName/public_html/wp-config.php"
		conf_set "define('DB_HOST', 'localhost');" "define\(\s*'DB_HOST'\s*,.*" 'MySQL settings -' "$webRoot/$siteName/public_html/wp-config.php"
	else
		echo "${CYAN}$siteName$RED web directory not found:$CYAN $webRoot/$siteName/public_html$RED aborting...$NORMAL"
	fi
}

#Credit to legroom.net for this generator!
#http://www.legroom.net/2010/05/06/bash-random-password-generator
randpass() {
	[ "$2" == "0" ] && CHAR="[:alnum:]" || CHAR="[:graph:]"
		cat /dev/urandom | tr -cd "$CHAR" | head -c ${1:-32}
		echo
}

#Removes zone pointer and zone file
remove_dns() {
#Input assignment, clear errors
	domainName="$1"
	error=''
	#Input validation
	[ -z "$domainName" ] && error='Usage: add_dns <FQDN>\n'
	[ -n "$error" ] && echo -e "$error" && return
	[ -n "$(grep -Pm 1 "zone\s+[\\"\']$domainName[\\"\']\s+in" /etc/named.rfc1912.zones)" ] &&
		remove_conf "^\s*zone \"$domainName\" in \{" "\};" /etc/named.rfc1912.zones ||
		error="${error}${DYELLOW}Domain name not found in /etc/named.rfc1912.zones$WHITE:$CYAN $domainName$NORMAL\n"
	[ -f "/var/named/$domainName" ] &&
		echo "${DGREEN}Removing DNS zone file $WHITE:$CYAN /var/named$domainName$NORMAL" &&
		\rm -f "/var/named/$domainName" ||
		error="${error}${DYELLOW}Zone file not found at$WHITE:$CYAN /var/named/$domainName$NORMAL\n"
	systemctl reload named
	[ -n "$error" ] && echo -en "$error" && return
}

remove_site() {
	vHost="$1"
	[ -z "$vHost" ] && error="No site provided\n"
	[ -z "$webRoot" ] && error="${error}No \$webRoot found\n"	
	[ -n "$error" ] && echo -en "$error" && return

	rm -rf "$webRoot/$vHost" "/etc/php-fpm.d/$vHost.conf"
	rm -f "/etc/nginx/conf.d/$vHost.conf"

	systemctl reload php-fpm
	systemctl reload nginx
}

req_param() {

	req_var="$1"
	varValue="$2"
	type="$3"
	req_length="$4"


	if [ -n "$varValue" ]
	then
		echo "$CYAN$req_var$DGREEN is already set$NORMAL"
	else
		case $type in
			password)
			req_pattern='^.+$'
			req_length=8
			;;
			username)
			req_pattern='^\w+'
			req_length=2
			;;
			numeric)
			req_pattern='^[0-9]+$'
			req_length=1
			;;
			##Credit for port number regex pattern http://utilitymill.com/utility/Regex_For_Range and http://stackoverflow.com/questions/12968093/regex-to-validate-port-number
			port)
			req_pattern='^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'
			req_length=2
			;;
			##Credit for domain regex pattern (allows dot-less domains) http://stackoverflow.com/questions/11809631/fully-qualified-domain-name-validation
			domain)
			req_pattern='(?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63}(?<!-))|((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63})$)'
			req_length=1
			;;
			##Credit for ipv4 regex pattern http://stackoverflow.com/questions/10006459/regular-expression-for-ip-address-validation
			ipv4)
			req_pattern='^(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))$'
			req_length=7
			;;
		esac
		
		until [ "$varValue" ]
		do
			echo "${DYELLOW}Input $CYAN$type for $CYAN$req_var$DYELLOW (requires $CYAN$req_length+$DYELLOW characters)$NORMAL"
			read userInput
			if [ -n "$(echo "$userInput" | grep -P "$req_pattern")" -a "$(echo "$userInput" | wc -c)" -gt $req_length ]
			then
				varValue="$userInput"
				eval "$req_var"="$userInput"
				echo "$CYAN$type$DGREEN set successfully for $CYAN$req_var$NORMAL"
			fi
		done
	fi
}

#Old function to set priorities. It should be replaced by conf_set in the future
set_priority()
{
	repoName="$1"
	priority="$2"
	baseurl="$3"
	insertLine="$(grep -nFm 1 "$baseurl" /etc/yum.repos.d/$repoName | cut -d: -f1)"
	let insertLine+=1
	if [ -z "$(sed -n "${insertLine}p" /etc/yum.repos.d/$repoName | grep -Fm 1 "priority=$priority")" ]
	then
		echo "${DGREEN}Setting priority of $repoName $baseurl to $priority$NORMAL"
		sed -i "${insertLine}i priority=$priority" "/etc/yum.repos.d/$repoName"
	else
		echo "${DYELLOW}Priority already set for $repoName$NORMAL"
	fi
}
######################END FUNCTION STORAGE ######################
