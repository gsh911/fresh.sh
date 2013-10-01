# Firewall configuration
firewall --enabled --ssh

# Install OS instead of upgrade
install

# Use network installation
url --url=ftp://ftp.free.fr/mirrors/ftp.centos.org/6/os/x86_64/

# Root password
rootpw --iscrypted $1$LBVx0jSD$tSEr7Hamy1CPBaWTuGfYz.

# System authorization information
auth  --useshadow  --passalgo=sha512

# Use graphical install
graphical
firstboot --disable

# System keyboard
keyboard fr-latin9

# System language
lang en_US

# SELinux configuration
selinux --disabled

# Do not configure the X Window System
skipx

# Installation logging level
logging --level=info

# System timezone
timezone --isUtc Europe/Paris

# Network information
network  --bootproto=static --noipv6 --device=eth0 --gateway=192.168.150.1 --ip=192.168.150.232 --nameserver=8.8.8.8,8.8.4.4 --netmask=255.255.255.0 --hostname lxc1.cecurity.com --onboot=on

# System bootloader configuration
bootloader --location=mbr

# Clear the Master Boot Record
zerombr

# Partition clearing information
clearpart --all --initlabel

# Disk partitioning information
part /boot --fstype=ext4 --size=100
part pv.01 --grow
volgroup vg_$_serverName pv.01
logvol swap --name=lv_swap --vgname=vg_$_serverName --size=2048
logvol / --fstype=ext4 --name=lv_root --vgname=vg_$_serverName --size=1024
logvol /home --fstype=ext4 --name=lv_home --vgname=vg_$_serverName --size=1024
logvol /tmp --fstype=ext4 --name=lv_tmp --vgname=vg_$_serverName --size=1024
logvol /usr --fstype=ext4 --name=lv_usr --vgname=vg_$_serverName --size=2048
logvol /var --fstype=ext4 --name=lv_var --vgname=vg_$_serverName --size=1024

%pre

%end
