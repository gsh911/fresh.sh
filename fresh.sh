# VARS
_serverName=""
_domainName=""
_primaryDNS=""
_secondaryDNS=""
_ntpServer=""
_ipAddress=""
_ipNetmask=""
_ipGateway=""
_adminUser=""
_adminPassword=""

# PARTITIONING

#/boot=100M
#vg_${_serverName}_lv-home=1G
#vg_${_serverName}_lv-tmp=1G
#vg_${_serverName}_lv-root=2G
#vg_${_serverName}_lv-usr=2G
#vg_${_serverName}_lv-var=1G
#vg_${_serverName}_lv-swap=RAM + 2G

# MOUNT
cat << EOF > /etc/fstab
/dev/sda1                       /boot                   ext4    defaults,nosuid,nodev,noexec            1       2
/dev/mapper/vg_${_serverName}-lv_root     /                       ext4    defaults                                1       1
/dev/mapper/vg_${_serverName}-lv_home     /home                   ext4    defaults,nosuid,nodev,noexec            1       2
/dev/mapper/vg_${_serverName}-lv_tmp      /tmp                    ext4    defaults,nosuid,nodev,noexec            1       2
/dev/mapper/vg_${_serverName}-lv_usr      /usr                    ext4    defaults,nodev                          1       2
/dev/mapper/vg_${_serverName}-lv_var      /var                    ext4    defaults,nosuid,nodev,noexec            1       2
/dev/mapper/vg_${_serverName}-lv_swap     swap                    swap    defaults                                0       0
/tmp                            /var/tmp                none    defaults,nosuid,nodev,noexec,bind       0       0
tmpfs                           /dev/shm                tmpfs   defaults,nosuid,nodev,noexec            0       0
devpts                          /dev/pts                devpts  gid=5,mode=620                          0       0
sysfs                           /sys                    sysfs   defaults                                0       0
proc                            /proc                   proc    defaults                                0       0
EOF

# DNS
cat << EOF > /etc/resolv.conf
domain ${_domainName}
search ${_domainName}
nameserver ${_primaryDNS}
nameserver ${_secondaryDNS}
EOF

# NETWORK
sed -i 's/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf

echo "127.0.0.1 localhost" > /etc/hosts

sed -i 's/localhost.localdomain/'${_serverName}.${_domainName}'/g' /etc/sysconfig/network
echo "NOZEROCONF=true" >> /etc/sysconfig/network

hostname ${_serverName}

cat << EOF > /etc/sysconfig/network-scripts/ifcfg-eth0
DEVICE=eth0
NAME=${_serverName}_eth0
TYPE=Ethernet
ONBOOT=yes
NM_CONTROLLED=no
BOOTPROTO=none
IPADDR=${_ipAddress}
NETMASK=${_ipNetmask}
GATEWAY=${_ipGateway}
EOF

cat << EOF > /etc/sysconfig/network-scripts/ifcfg-virbr0
DEVICE=virbr0
NAME=${_serverName}_virbr0
TYPE=Bridge
ONBOOT=yes
NM_CONTROLLED=no
BOOTPROTO=none
IPADDR=192.168.1.254
NETMASK=255.255.0.0
DELAY=0
EOF

# IPTABLES
cat << EOF > /etc/sysconfig/iptables
*filter

:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# DEFAULT HYPERVISOR INPUT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i virbr0 -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT

# DEFAULT HYPERVISOR OUTPUT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT

# DEFAULT CONTAINERS OUTPUT
-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -p icmp -j ACCEPT

# SSH HYPERVISOR INPUT
-A INPUT -m state --state NEW -m tcp -p tcp -i eth0 --dport 22 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp -o eth0 --sport 22 -j ACCEPT

# DNS CONTAINERS OUTPUT
-A FORWARD -m state --state NEW -m udp -p udp -i virbr0 -o eth0 --dport 53 -j ACCEPT

# HTTP CONTAINERS OUTPUT
-A FORWARD -m state --state NEW -m tcp -p tcp -i virbr0 -o eth0 --dport 80 -j ACCEPT

# HTTPS CONTAINERS OUTPUT
-A FORWARD -m state --state NEW -m tcp -p tcp -i virbr0 -o eth0 --dport 443 -j ACCEPT

# SMTP CONTAINERS OUTPUT
-A FORWARD -m state --state NEW -m tcp -p tcp -i virbr0 --dport 25 -j ACCEPT

# SMTP HYPERVISOR OUTPUT
-A OUTPUT -m state --state NEW -m tcp -p tcp -o eth0 --dport 25 -j ACCEPT

# DNS HYPERVISOR OUTPUT
-A OUTPUT -m state --state NEW -m udp -p udp -o eth0 --dport 53 -j ACCEPT

# HTTP HYPERVISOR OUTPUT
-A OUTPUT -m state --state NEW -m tcp -p tcp -o eth0 --dport 80 -j ACCEPT

# HTTPS HYPERVISOR OUTPUT
-A OUTPUT -m state --state NEW -m tcp -p tcp -o eth0 --dport 443 -j ACCEPT

# NTP HYPERVISOR OUTPUT
-A OUTPUT -m state --state NEW -m udp -p udp -o eth0 --dport 123 -j ACCEPT

# REJECT RULES
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
-A INPUT -j DROP
-A OUTPUT -j REJECT --reject-with icmp-host-prohibited

COMMIT

*nat

:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

-A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE

COMMIT
EOF

# MOTD
cat << EOF > /etc/motd

WARNING
=======
YOU MUST HAVE PRIOR AUTHORIZATION TO ACCESS THIS SYSTEM.
ALL CONNECTIONS ARE LOGGED AND MONITORED.
BY CONNECTING TO THIS SYSTEM YOU FULLY CONSENT TO ALL MONITORING.
UN-AUTHORIZED ACCESS OR USE WILL BE PROSECUTED TO THE FULL EXTENT OF LAW.

EOF

# PROFILE
cat << EOF > /etc/profile.d/custom.sh 
# History params

readonly HISTFILE
export HISTTIMEFORMAT="%h/%d - %H:%M:%S "
export HISTCONTROL=ignoredups
export HISTSIZE=5000
export HISTFILESIZE=20000

# Console params
shopt -s checkwinsize
shopt -s cdspell
shopt -s autocd

# Grep Options

export GREP_OPTIONS='--color=auto'

# Timeout

export TMOUT=300
readonly TMOUT

# Default editor

export EDITOR=vim

# Login mail alert
echo 'Shell access '\`date\` \`who | tail -1 \`| mail -s "Access on \`hostname\`" monitoring@${_domainName}

# Prompt

PS1="\[\e[01;41m\]\t\[\e[00m\] \[\e[01;32m\]\u@\h\[\e[00m\]:\[\e[01;34m\]\w\[\e[00m\] "
EOF

# VIM
cat << EOF > /etc/skel/.vimrc 
set number
colorscheme slate
filetype plugin indent on
syntax on
set showcmd
set history=100
set showmatch
set hlsearch
set incsearch
set shiftround
set ignorecase
filetype on
EOF

mkdir -p /etc/skel/.vim/ftdetect
echo "autocmd BufNewFile,BufReadPost messages* :se filetype=messages" > /etc/skel/.vim/ftdetect/messages.vim
echo "autocmd BufNewFile,BufReadPost secure* :se filetype=messages" >> /etc/skel/.vim/ftdetect/messages.vim
echo "autocmd BufNewFile,BufReadPost maillog* :se filetype=messages" >> /etc/skel/.vim/ftdetect/messages.vim
echo "autocmd BufNewFile,BufReadPost cron* :se filetype=messages" >> /etc/skel/.vim/ftdetect/messages.vim
/bin/cp -a /etc/skel/. /root

# DISABLE ROOT
> /etc/securetty
sed -i 's/\/bin\/bash/\/nologin/g' /etc/passwd
passwd --delete root

# SUDO
adduser $_adminUser
echo "${_adminUser}:${_adminPassword}" | chpasswd
echo "${_adminUser}     ALL=(ALL)       ALL" > /etc/sudoers.d/custom
chmod 400 /etc/sudoers.d/custom

# KERNEL TUNING
cat << EOF >> /etc/sysctl.conf

# Drop icmp redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Double the syn backlog size
net.ipv4.tcp_max_syn_backlog = 2048

# Ignore ping broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log packets destinated to impossible addresses
net.ipv4.conf.all.log_martians = 1

# Ignore bogus icmp error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Don't send timestamps
net.ipv4.tcp_timestamps = 0
EOF

echo "blacklist usb-storage" > /etc/modprobe.d/blacklist-usbstorage.conf
for i in $(find /lib/modules/`uname -r`/kernel/drivers/net/wireless -name "*.ko" -type f) ; do echo blacklist $i >> /etc/modprobe.d/blacklist-wireless.conf ; done
for i in $(find /lib/modules/`uname -r`/kernel/drivers/scsi/fcoe -name "*.ko" -type f) ; do echo blacklist $i >> /etc/modprobe.d/blacklist-fcoe.conf ; done
echo "install ipv6 /bin/true" > /etc/modprobe.d/blacklist-ipv6.conf

# POLICIES
sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 60' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 1' /etc/login.defs
sed -i '/^PASS_MIN_LEN/c\PASS_MIN_LEN 9' /etc/login.defs
sed -i '/^PASS_WARN_AGE/c\PASS_WARN_AGE 15' /etc/login.defs

# SSH
cat << EOF > /etc/ssh/sshd_config
Port 22
AddressFamily inet
ListenAddress ${_ipAddress}
Protocol 2

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
ServerKeyBits 2048

SyslogFacility AUTHPRIV
LogLevel INFO

LoginGraceTime 15s
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 1

RSAAuthentication no
PubkeyAuthentication no
RhostsRSAAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreUserKnownHosts no
IgnoreRhosts yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
KerberosAuthentication no
UsePAM yes

AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
X11DisplayOffset 10
X11UseLocalhost yes
PrintMotd yes
PrintLastLog yes
TCPKeepAlive yes
UseLogin no
UsePrivilegeSeparation yes
PermitUserEnvironment no
Compression delayed
ClientAliveInterval 60
ClientAliveCountMax 3
ShowPatchLevel no
UseDNS no
PidFile /var/run/sshd.pid
MaxStartups 10
PermitTunnel no

Subsystem       sftp    /usr/libexec/openssh/sftp-server

AllowUsers ${_adminUser}
EOF

echo "ALL:ALL" >> /etc/hosts.deny
echo "sshd:ALL" >> /etc/hosts.allow

# TIME
ln -fs /usr/share/zoneinfo/Europe/Paris /etc/localtime

# MAIL
sed -i 's/#root:\t\tmarc/root:\t\tmonitoring@'$_domainName'/g' /etc/aliases

# REPOSITORY
rm -rf /etc/yum.repos.d/*

cat << EOF > /etc/yum.conf
[main]
cachedir=/var/cache/yum/\$basearch/\$releasever
keepcache=0
debuglevel=2
logfile=/dev/null
exactarch=1
obsoletes=1
gpgcheck=1
plugins=1
bugtracker_url=http://bugs.centos.org/set_project.php?project_id=16&ref=http://bugs.centos.org/bug_report_page.php?category=yum
distroverpkg=centos-release
EOF

cat << EOF > /etc/yum.repos.d/Centos.repo
[CentOS-Base]
name=CentOS-\$releasever - Base
mirrorlist=http://mirrorlist.centos.org/?release=\$releasever&arch=\$basearch&repo=os
[CentOS-Updates]
name=CentOS-\$releasever - Updates
mirrorlist=http://mirrorlist.centos.org/?release=\$releasever&arch=\$basearch&repo=updates
EOF

rm -rf /etc/pki/rpm-gpg/
rpm --import http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-6

# PACKETS CLEANUP
yum -y install yum-plugin-remove-with-leaves yum-utils
yum -y remove --remove-leaves fuse mdadm efibootmgr iptables-ipv6 iscsi* dhcp-common device-mapper-multipath* xfsprogs

# PACKETS UPDATE
yum -y update

# OS TUNING
sed -i 's/1-6/1/g' /etc/sysconfig/init
sed -i 's/1-6/1/g' /etc/init/start-ttys.conf
sed -i 's/sushell/sulogin/' /etc/sysconfig/init
sed -i 's/PROMPT=yes/PROMPT=no/' /etc/sysconfig/init
sed -i 's/exec.*/exec \/bin\/echo "Control-Alt-Delete pressed, but no action will be taken"/' /etc/init/control-alt-delete.conf

touch /var/log/tallylog
sed -i '0,/^auth/s//auth        required      pam_tally2.so deny=3 audit onerr=fail unlock_time=900\n&/' /etc/pam.d/system-auth
sed -i '0,/^auth/s//auth        required      pam_tally2.so deny=3 audit onerr=fail unlock_time=900\n&/' /etc/pam.d/password-auth
sed -i '0,/^account/s//account     required      pam_tally2.so\n&/' /etc/pam.d/system-auth
sed -i '0,/^account/s//account     required      pam_tally2.so\n&/' /etc/pam.d/password-auth

chmod 400 /etc/hosts.allow
chmod 400 /etc/hosts.deny
chmod 700 /var/log/audit
chmod 740 /etc/rc.d/init.d/iptables
chmod 740 /sbin/iptables
chmod 600 /etc/rsyslog.conf
chmod 640 /etc/security/access.conf
chmod 600 /etc/sysctl.conf

# PACKETS INSTALLATION
yum -y install logwatch vim-enhanced mlocate aide libcgroup ntpdate

# SERVICES CONFIGURATION
chkconfig --del ntpdate
chkconfig --del rdisc
chkconfig --del netconsole
chkconfig --del netfs
chkconfig --del restorecond
chkconfig --del blk-availability
chkconfig --del saslauthd

chkconfig cgconfig on
chkconfig cgred on

# NTP
echo "${_ntpServer}"> /etc/ntp/step-tickers
cat << EOF > /etc/cron.daily/ntpdate
#!/bin/sh

/etc/init.d/ntpdate start >/dev/null 2>&1
EXITVALUE=\$?
if [ \$EXITVALUE != 0 ]; then
    /usr/bin/logger -t ntpdate "ALERT exited abnormally with [\$EXITVALUE]"
fi
exit 0
EOF
chmod +x /etc/cron.daily/ntpdate

# POSTFIX
sed -i 's/inet_protocols = all/inet_protocols = ipv4/g' /etc/postfix/main.cf

# AUDIT
/bin/cp -a /usr/share/doc/audit-*/stig.rules /etc/audit/audit.rules
sed -i '/b32/d' /etc/audit/audit.rules

# LOGWATCH
cat << EOF > /usr/share/logwatch/default.conf/logwatch.conf
LogDir = /var/log
TmpDir = /var/cache/logwatch
MailTo = monitoring@${_domainName}
MailFrom = Logwatch <monitoring@${_domainName}>
Print =
Range = yesterday
Detail = Low
Service = All
Service = "-zz-network"     # Prevents execution of zz-network service, which
Service = "-zz-sys"         # Prevents execution of zz-sys service, which
Service = "-eximstats"      # Prevents execution of eximstats service, which
mailer = "sendmail -t"
EOF

# LOGROTATE
mkdir /var/log/archives
cat << EOF > /etc/logrotate.conf
# see "man logrotate" for details
# rotate log files weekly
weekly

# keep 12 weeks worth of backlogs
rotate 12

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# uncomment this if you want your log files compressed
compress

# archives will be rotated to archives directory
olddir /var/log/archives

# RPM packages drop log rotation information into this directory
include /etc/logrotate.d

# no packages own wtmp and btmp -- we'll rotate them here
/var/log/wtmp {
    monthly
    create 0664 root utmp
        minsize 1M
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    rotate 1
}

# system-specific logs may be also be configured here.
EOF

# OS CLEANUP
cat << EOF > /etc/cron.d/cleanKernel
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/
@reboot   root    package-cleanup --oldkernels --count=1 -y >/dev/null 2>&1
EOF

rm -rf /etc/ssh/ssh_host*
rm -rf ~/anaconda-ks.cfg ~/install.log ~/install.log.syslog
rm -rf /var/log/anaconda.*
rm -rf /var/log/dmesg.*
rm -rf /var/log/dracut.log
rm -f /etc/sysconfig/ip6tables*
rm -f /etc/sysconfig/iptables.old
rm -f /etc/sysconfig/system-config-firewall*
rm -rf /tmp/*
rm -rf /etc/issue*
rm -rf /lost+found/
rm -rf /var/lost+found/
rm -rf /usr/lost+found/
rm -rf /home/lost+found/
rm -rf /var/log/yum.log
rm -rf /boot/lost+found/
rm -rf /mnt/
rm -rf /media/

/usr/sbin/userdel shutdown
/usr/sbin/userdel halt
/usr/sbin/userdel games
/usr/sbin/userdel operator
/usr/sbin/userdel ftp
/usr/sbin/userdel gopher
/usr/sbin/userdel lp

history -c

# SERVICES RESTART
/etc/init.d/network restart >/dev/null 2>&1
/etc/init.d/sshd restart >/dev/null 2>&1
/etc/init.d/iptables restart >/dev/null 2>&1
/etc/init.d/ntpdate restart >/dev/null 2>&1
/etc/init.d/postfix restart >/dev/null 2>&1
/etc/init.d/auditd restart >/dev/null 2>&1
sysctl -q -p

# LXC INSTALLATION
yum -y install gcc libcap-devel rsync make

curl -L http://downloads.sourceforge.net/project/lxc/lxc/lxc-0.9.0/lxc-0.9.0.tar.gz > lxc-0.9.0.tar.gz
curl -L https://gist.github.com/hagix9/3514296/download > lxc-centos.tar.gz

tar xf lxc-0.9.0.tar.gz
tar xf lxc-centos.tar.gz
cd lxc-0.9.0

mkdir /opt/lxc-0.9.0
./configure --prefix=/opt/lxc-0.9.0
make
make install
ln -s /opt/lxc-0.9.0 /opt/lxc
cd .. 
cp gist*/lxc-centos /opt/lxc/share/lxc/templates/
chmod +x /opt/lxc/share/lxc/templates/lxc-centos
rm -rf lxc-*
rm -rf gist*
/opt/lxc/bin/lxc-checkconfig

cat << EOF > /opt/lxc-0.9.0/etc/lxc/default.conf
lxc.network.type = veth
lxc.network.link = virbr0
lxc.network.flags = up
lxc.tty = 1
EOF

# COMMAND EXAMPLES

#/opt/lxc/bin/lxc-create -n centos -t centos -B lvm --lvname lv_lxc_centos --vgname vg_${_serverName} --fstype ext4 --fssize 5GO
#rm -rf /opt/lxc/var/lib/lxc/centos/rootfs
#/opt/lxc/bin/lxc-start --name centos -d -c /opt/lxc/var/lib/lxc/centos/console -o /opt/lxc/var/lib/lxc/centos/log -p /opt/lxc/var/lib/lxc/centos/pid
#/opt/lxc/bin/lxc-console -n centos
