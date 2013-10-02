# VARS
_serverName="lxc1"
_primaryDNS="8.8.8.8"
_secondaryDNS="8.8.4.4"
_domainName="cecurity.com"
_ipAddress="192.168.155.129"
_ipNetmask="255.255.255.0"
_ipGateway="192.168.155.2"
_adminUser="anthony.cabero"
_adminPassword="12341234"

# MOUNT
echo "/dev/sda1                       /boot                   ext4    defaults,nosuid,nodev,noexec            1       2
/dev/mapper/vg_$_serverName-lv_root     /                       ext4    defaults                                1       1
/dev/mapper/vg_$_serverName-lv_home     /home                   ext4    defaults,nosuid,nodev,noexec            1       2
/dev/mapper/vg_$_serverName-lv_tmp      /tmp                    ext4    defaults,nosuid,nodev,noexec            1       2
/dev/mapper/vg_$_serverName-lv_usr      /usr                    ext4    defaults,nodev                          1       2
/dev/mapper/vg_$_serverName-lv_var      /var                    ext4    defaults,nosuid,nodev,noexec            1       2
/dev/mapper/vg_$_serverName-lv_swap     swap                    swap    defaults                                0       0
/tmp                            /var/tmp                none    defaults,nosuid,nodev,noexec,bind       0       0
tmpfs                           /dev/shm                tmpfs   defaults,nosuid,nodev,noexec            0       0
devpts                          /dev/pts                devpts  gid=5,mode=620                          0       0
sysfs                           /sys                    sysfs   defaults                                0       0
proc                            /proc                   proc    defaults                                0       0" > /etc/fstab

# DNS
echo "domain $_domainName
search $_domainName
nameserver $_primaryDNS
nameserver $_secondaryDNS" > /etc/resolv.conf

# NETWORK
echo "DEVICE=eth0
NAME=$_serverName_eth0
TYPE=Ethernet
ONBOOT=yes
NM_CONTROLLED=yes
BOOTPROTO=none
IPADDR=$_ipAddress
NETMASK=$_ipNetmask
GATEWAY=$_ipGateway" > /etc/sysconfig/network-scripts/ifcfg-eth0

# MOTD
echo "
WARNING
=======
YOU MUST HAVE PRIOR AUTHORIZATION TO ACCESS THIS SYSTEM. ALL CONNECTIONS ARE LOGGED AND MONITORED. BY CONNECTING TO THIS SYSTEM YOU FULLY CONSENT TO ALL MONITORING. UN-AUTHORIZED ACCESS OR USE WILL BE PROSECUTED TO THE FULL EXTENT OF LAW.
" > /etc/motd

# PROFILE
echo "# History params

readonly HISTFILE
export HISTTIMEFORMAT=\"%h/%d - %H:%M:%S \"
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
echo 'Shell access '\`date\` \`who | tail -1 \`| mail -s \"Access on \`hostname\`\" monitoring@$_domainName

# Prompt

PS1=\"\[\e[01;41m\]\t\[\e[00m\] \[\e[01;32m\]\u@\h\[\e[00m\]:\[\e[01;34m\]\w\[\e[00m\] \"" > /etc/profile.d/custom.sh

# VIM
echo "set number
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
filetype on" > /etc/skel/.vimrc 
mkdir -p /etc/skel/.vim/ftdetect
echo "autocmd BufNewFile,BufReadPost messages* :se filetype=messages" > /etc/skel/.vim/ftdetect/messages.vim
echo "autocmd BufNewFile,BufReadPost secure* :se filetype=messages" >> /etc/skel/.vim/ftdetect/messages.vim
echo "autocmd BufNewFile,BufReadPost maillog* :se filetype=messages" >> /etc/skel/.vim/ftdetect/messages.vim
echo "autocmd BufNewFile,BufReadPost cron* :se filetype=messages" >> /etc/skel/.vim/ftdetect/messages.vim
cp -a /etc/skel/. /root

# DISABLE ROOT
> /etc/securetty
sed -i 's/\/bin\/bash/\/nologin/g' /etc/passwd
passwd --delete root

# SUDO
adduser $_adminUser
echo "$_adminUser:$_adminPassword" | chpasswd
echo "$_adminUser       ALL=(ALL)       ALL" > /etc/sudoers.d/custom

# KERNEL TUNING
echo "
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
net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf

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
sed -i '/^#PasswordAuthentication yes/d' /etc/ssh/sshd_config
sed -i 's/#UseDNS yes/UseDNS no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 60/g' /etc/ssh/sshd_config
sed -i '/UsePAM yes/d' /etc/ssh/sshd_config
sed -i 's/#UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 15s/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i '/GSSAPI/d' /etc/ssh/sshd_config
sed -i 's/#ListenAddress 0.0.0.0/ListenAddress '$_ipAddress'/g' /etc/ssh/sshd_config
sed -i 's/#RSAAuthentication yes/RSAAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication no/g' /etc/ssh/sshd_config
sed -i '/X11Forwarding yes/d' /etc/ssh/sshd_config
sed -i 's/^#ServerKeyBits 1024/ServerKeyBits 2048/g' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries 6/MaxAuthTries 3/g' /etc/ssh/sshd_config
sed -i 's/^#MaxSessions 10/MaxSessions 1/g' /etc/ssh/sshd_config
echo "AllowUsers $_adminUser" >> /etc/ssh/sshd_config

echo "ALL:ALL" >> /etc/hosts.deny
echo "sshd:ALL" >> /etc/hosts.allow

# TIME
ln -fs /usr/share/zoneinfo/Europe/Paris /etc/localtime

# MAIL
sed -i 's/#root:\t\tmarc/root:\t\tmonitoring@'$_domainName'/g' /etc/aliases
sed -i 's/root/monitoring@'$_domainName'/g' /etc/crontab

# NETWORK
echo "127.0.0.1 localhost" > /etc/hosts
sed -i 's/localhost.localdomain/'$_serverName.$_domainName'/g' /etc/sysconfig/network
echo "NOZEROCONF=true" >> /etc/sysconfig/network

# REPOSITORY
rm -rf /etc/yum.repos.d/*
echo "[main]
cachedir=/var/cache/yum/\$basearch/\$releasever
keepcache=0
debuglevel=2
logfile=/dev/null
exactarch=1
obsoletes=1
gpgcheck=1
plugins=1
bugtracker_url=http://bugs.centos.org/set_project.php?project_id=16&ref=http://bugs.centos.org/bug_report_page.php?category=yum
distroverpkg=centos-release" > /etc/yum.conf
echo "[CentOS-Base]
name=CentOS-\$releasever - Base
mirrorlist=http://mirrorlist.centos.org/?release=\$releasever&arch=\$basearch&repo=os
[CentOS-Updates]
name=CentOS-\$releasever - Updates
mirrorlist=http://mirrorlist.centos.org/?release=\$releasever&arch=\$basearch&repo=updates" > /etc/yum.repos.d/Centos.repo
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
echo "# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so
auth        required      pam_tally2.so deny=3 onerr=fail unlock_time=60

account     required      pam_unix.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so
account     required      pam_tally2.so per_user

password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=9 lcredit=-2 ucredit=-2 dcredit=-2 ocredit=-2
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=10
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so" > /etc/pam.d/system-auth

chmod 400 /etc/hosts.allow
chmod 400 /etc/hosts.deny
chmod 700 /var/log/audit
chmod 740 /etc/rc.d/init.d/iptables
chmod 740 /sbin/iptables
chmod 600 /etc/rsyslog.conf
chmod 640 /etc/security/access.conf
chmod 600 /etc/sysctl.conf

# PACKETS INSTALLATION
yum -y install logwatch vim-enhanced mlocate aide libcgroup
updatedb
chkconfig --del rdisc && chkconfig --del netconsole && chkconfig --del netfs && chkconfig --del restorecond && chkconfig --del blk-availability && chkconfig --del saslauthd
chkconfig cgconfig on && chkconfig cgred on

# NTPD
sed -i '/-6/d' /etc/ntp.conf

# SELINUX

# POSTFIX
sed -i 's/inet_protocols = all/inet_protocols = ipv4/g' /etc/postfix/main.cf

# AUDIT
/bin/cp -a /usr/share/doc/audit-*/stig.rules /etc/audit/audit.rules
sed -i '/b32/d' /etc/audit/audit.rules

# LOGWATCH
echo "LogDir = /var/log
TmpDir = /var/cache/logwatch
MailTo = monitoring@$_domainName
MailFrom = Logwatch <monitoring@$_domainName>
Print =
Range = yesterday
Detail = Low
Service = All
Service = \"-zz-network\"     # Prevents execution of zz-network service, which
Service = \"-zz-sys\"         # Prevents execution of zz-sys service, which
Service = \"-eximstats\"      # Prevents execution of eximstats service, which
mailer = \"sendmail -t\"" > /usr/share/logwatch/default.conf/logwatch.conf

# LOGROTATE
mkdir /var/log/archives
echo "# see \"man logrotate\" for details
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

# system-specific logs may be also be configured here." > /etc/logrotate.conf

reboot

# OS CLEANUP
echo "package-cleanup --oldkernels --count=1 -y
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
rm -rf /mnt/ && rm -rf /opt/ && rm -rf /media/
/usr/sbin/userdel shutdown
/usr/sbin/userdel halt
/usr/sbin/userdel games
/usr/sbin/userdel operator
/usr/sbin/userdel ftp
/usr/sbin/userdel gopher
/usr/sbin/userdel lp
history -c" > /tmp/clean
sudo bash /tmp/clean && rm -f /tmp/clean

reboot

#LXC
sudo yum -y install gcc libcap-devel rsync ntp
sudo chkconfig --del ntpdate
sudo chkconfig ntpd on
sed -i 's/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf
sudo sh -c "echo 'DEVICE=virbr0
IPADDR=192.168.1.254
TYPE=Bridge
ONBOOT=yes
BOOTPROTO=none
DELAY=5
STP=yes' > /etc/sysconfig/network-scripts/ifcfg-br0"
sudo /etc/init.d/network restart
sudo cat << EOF > /etc/sysconfig/iptables
*filter

:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# DEFAULT INPUT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT

# SSH INBOUND
-A INPUT -m state --state NEW -m tcp -p tcp -i eth0 --dport 22 -j ACCEPT
-A OUTPUT -m state --state NEW -m tcp -p tcp -o eth0 --sport 22 -j ACCEPT

# DEFAULT FORWARD
-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -p icmp -j ACCEPT

# DNS FORWARD
-A FORWARD -m state --state NEW -m udp -p udp -i br0 -o eth0 --dport 53 -j ACCEPT

# HTTP FORWARD
-A FORWARD -m state --state NEW -m tcp -p tcp -i br0 -o eth0 --dport 80 -j ACCEPT

# HTTPS FORWARD
-A FORWARD -m state --state NEW -m tcp -p tcp -i br0 -o eth0 --dport 443 -j ACCEPT

# DEFAULT OUTPUT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT

# DNS OUTPUT
-A OUTPUT -m state --state NEW -m udp -p udp -o eth0 --dport 53 -j ACCEPT

# HTTP OUTPUT
-A OUTPUT -m state --state NEW -m tcp -p tcp -o eth0 --dport 80 -j ACCEPT

# HTTPS OUTPUT
-A OUTPUT -m state --state NEW -m tcp -p tcp -o eth0 --dport 443 -j ACCEPT

# NTP HYPERVISOR OUTPUT
-A OUTPUT -m state --state NEW -m udp -p udp -o eth0 --dport 123 -j ACCEPT

# REJECT RULES
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A OUTPUT -j REJECT --reject-with icmp-host-prohibited

COMMIT

*nat

:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

-A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE

COMMIT
EOF
curl -L http://downloads.sourceforge.net/project/lxc/lxc/lxc-0.9.0/lxc-0.9.0.tar.gz > lxc-0.9.0.tar.gz
curl -L https://gist.github.com/hagix9/3514296/download > lxc-centos.tar.gz
tar xf lxc-0.9.0.tar.gz
tar xf lxc-centos.tar.gz
cd lxc-0.9.0
mkdir /opt/lxc-0.9.0
./configure --prefix=/opt/lxc-0.9.0
make
sudo make install
ln -s /opt/lxc-0.9.0 /opt/lxc
cd .. 
sudo cp gist*/lxc-centos /opt/lxc/share/lxc/templates/ #perms?
rm -rf lxc-*
rm -rf gist*
/opt/lxc/bin/lxc-checkconfig
sudo /opt/lxc/bin/lxc-create -n centos -t centos -B lvm --lvname lv_name --vgname vg_name --fstype ext4 --fssize 5GO
#echo "rootfs / rootfs rw 0 0" > /etc/mtab
#lxc.tty = 1
rm -rf /opt/lxc/var/lib/lxc/centos/rootfs
sudo /opt/lxc/bin/lxc-start --name centos -d -c /opt/lxc/var/lib/lxc/centos/console -o /opt/lxc/var/lib/lxc/centos/log -p /opt/lxc/var/lib/lxc/centos/pid
sudo ./lxc-console -n centos
