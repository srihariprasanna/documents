#!/bin/bash
# Server Hardening Script by Srihari Prasanna J
echo "SERVER HARDENING"
echo
echo "###############################################################"
echo
echo "Check selinux enabled or disabled"
selinuxfile="/etc/selinux/config"
if [ -e $selinuxfile ]; then
        echo "File exists"
        echo "$selinuxfile changed from enabled to disabled"
        sed -i "s/enabled/disabled/g" $selinuxfile

elif [  `cat $selinuxfile | grep disabled` ]; then
        echo "Already disabled"
else
        echo "File does not exists"
fi
echo 
echo "###############################################################"
echo
echo "Checking Ipv6 enabled or not"
networkfile="/etc/sysconfig/network"
if [ -e $networkfile ]; then
        echo "File Exists"
        echo "Checking the ipv6 values"
        if [ "$(grep -E "NETWORKING_IPV6|IPV6INIT" $networkfile &>/dev/null; echo $?)" == 0 ]; then
                echo "Value Present,Attempting to change the values"
                sed -i "s/NETWORKING_IPV6=yes/NETWORKING_IPV6=no/g" $networkfile
                sed -i "s/IPV6INIT=yes/IPV6INIT=no/g" $networkfile
                echo "Value Changed and Current values are `cat $networkfile | grep -E "NETWORKING_IPV6|IPV6INIT"`"
        else
                echo "Values not present,appending the values to Networkfile"
                echo "NETWORKING_IPV6=no" >> $networkfile
                echo "IPV6INIT=no" >> $networkfile
                echo "Value added"
        fi
fi
echo 
echo "###############################################################"
echo
echo "Disabling Unwanted Services"
chkconfig autofs off
chkconfig avahi-daemon off
chkconfig avahi-dnsconfd off
chkconfig bluetooth off
chkconfig conman off
chkconfig cups off
chkconfig dhcdbd off
chkconfig firstboot off
chkconfig gpm off
chkconfig haldaemon off
chkconfig isdn off
chkconfig iptables off
chkconfig ip6tables off
chkconfig irda off
chkconfig irqbalance off
chkconfig kdump off
chkconfig kudzu off
chkconfig mcstrans off
chkconfig microcode_ctl off
chkconfig multipathd off
chkconfig netconsole off
chkconfig netfs off
chkconfig netplugd off
chkconfig nfs off
chkconfig nfslock off
chkconfig nscd off
chkconfig pcscd off
chkconfig portmap off
chkconfig rdisc off
chkconfig rhnsd off
chkconfig restorecond off
chkconfig rpcgssd off
chkconfig rpcidmapd off
chkconfig rpcsvcgssd off
chkconfig sendmail off
chkconfig smartd off
chkconfig winbind off
chkconfig wpa_supplicant off
chkconfig xfs off
chkconfig ypbind off
chkconfig yum-updatesd off
echo
echo "###############################################################"
echo
echo "SSH Hardening"
echo
echo "Setting Banner Message"
sed -i "s:#Banner none:Banner /etc/issue:g" /etc/ssh/sshd_config
echo "Setting SSH LogLevel is set to INFO"
sed -i "s:#LogLevel INFO:LogLevel INFO:g" /etc/ssh/sshd_config
echo "Setting X11 forwarding to no"
sed -i "s:X11Forwarding yes:X11Forwarding no:g" /etc/ssh/sshd_config
echo "Setting MaxAuthTries to 4"
sed -i "s:#MaxAuthTries 6:MaxAuthTries 4:g" /etc/ssh/sshd_config
echo "Setting SSH IgnoreRhosts"
sed -i "s:#IgnoreRhosts yes:IgnoreRhosts yes:g" /etc/ssh/sshd_config
echo "Setting SSH HostbasedAuthentication"
sed -i "s:#HostbasedAuthentication no:HostbasedAuthentication no:g" /etc/ssh/sshd_config
echo "Setting SSH PermitEmptyPasswords to disabled"
sed -i "s:#PermitEmptyPasswords no:PermitEmptyPasswords no:g" /etc/ssh/sshd_config
echo "Setting SSH PermitUserEnvironment is disabled"
sed -i "s:#PermitUserEnvironment no:PermitUserEnvironment no:g" /etc/ssh/sshd_config
echo "Setting SSH Idle Timeout Interval"
sed -i "s:#ClientAliveInterval 0:ClientAliveInterval 300:g" /etc/ssh/sshd_config
sed -i "s:#ClientAliveCountMax 3:ClientAliveCountMax 3:g" /etc/ssh/sshd_config
echo "Setting SSH LoginGraceTime"
sed -i "s:#LoginGraceTime 2m:LoginGraceTime 2m:g" /etc/ssh/sshd_config
cat > /etc/issue << EOF
|-----------------------------------------------------------------|
| This system is for the use of authorized users only.            |
| Individuals using this computer system without authority, or in |
| excess of their authority, are subject to having all of their   |
| activities on this system monitored and recorded by system      |
| personnel.                                                      |
|                                                                 |
| In the course of monitoring individuals improperly using this   |
| system, or in the course of system maintenance, the activities  |
| of authorized users may also be monitored.                      |
|                                                                 |
| Anyone using this system expressly consents to such monitoring  |
| and is advised that if such monitoring reveals possible         |
| evidence of criminal activity, system personnel may provide the |
| evidence of such monitoring to law enforcement officials.       |
|-----------------------------------------------------------------|
EOF
cat /etc/issue
service sshd restart
echo 
echo "###############################################################"
echo 
echo "Set Shadow Password Days to 90"
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\  90/g' /etc/login.defs
echo "Setting minimum days between password changes to 7"
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\  7/g' /etc/login.defs
echo "Setting  Minimum acceptable password length to 15"
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\  15/g' /etc/login.defs
echo "Setting Minimum acceptable password length to 7"
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\  7/g' /etc/login.defs
echo 
echo "###############################################################"
echo
echo "Setting Kernel Parameters"
sysctlfile="/etc/sysctl.conf"
if [ "$(grep "net.ipv4.icmp_echo_ignore_broadcasts" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1 already set"
else
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
echo net.ipv4.icmp_echo_ignore_broadcasts = 1 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.icmp_ignore_bogus_error_responses" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1 already set"
else
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1"
echo net.ipv4.icmp_ignore_bogus_error_responses = 1 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.tcp_syncookies" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.tcp_syncookies = 1 already set"
else
echo "net.ipv4.tcp_syncookies = 1"
echo net.ipv4.tcp_syncookies = 1 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.all.log_martians" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.all.log_martians = 1 already set"
else
echo "net.ipv4.conf.all.log_martians = 1"
echo net.ipv4.conf.all.log_martians = 1 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.default.log_martians" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.default.log_martians = 1 already set"
else
echo "net.ipv4.conf.default.log_martians = 1"
echo net.ipv4.conf.default.log_martians = 1 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.all.accept_source_route" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.all.accept_source_route = 0 already set"
else
echo "net.ipv4.conf.all.accept_source_route = 0"
echo net.ipv4.conf.all.accept_source_route = 0 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.default.accept_source_route" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.default.accept_source_route = 0 already set"
else
echo "net.ipv4.conf.default.accept_source_route = 0"
echo net.ipv4.conf.default.accept_source_route = 0 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.default.accept_source_route" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.all.rp_filter = 1 already set"
else
echo "net.ipv4.conf.all.rp_filter = 1"
echo net.ipv4.conf.all.rp_filter = 1 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.default.rp_filter" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.default.rp_filter = 1 already set"
else
echo "net.ipv4.conf.default.rp_filter = 1"
echo net.ipv4.conf.default.rp_filter = 1 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.all.accept_redirects" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.all.accept_redirects = 0 already set"
else
echo "net.ipv4.conf.all.accept_redirects = 0"
echo net.ipv4.conf.all.accept_redirects = 0 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.default.accept_redirects" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.default.accept_redirects = 0 already set"
else
echo "net.ipv4.conf.default.accept_redirects = 0"
echo net.ipv4.conf.default.accept_redirects = 0 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.all.secure_redirects" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.all.secure_redirects = 0 already set"
else
echo "net.ipv4.conf.all.secure_redirects = 0"
echo net.ipv4.conf.all.secure_redirects = 0 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.default.secure_redirects" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.default.secure_redirects = 0 already set"
else
echo "net.ipv4.conf.default.secure_redirects = 0"
echo net.ipv4.conf.default.secure_redirects = 0 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.ip_forward" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.ip_forward = 0 already set"
else
echo "net.ipv4.ip_forward = 0"
echo net.ipv4.ip_forward = 0 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.all.send_redirects" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.all.send_redirects = 0 already set"
else
echo "net.ipv4.conf.all.send_redirects = 0"
echo net.ipv4.conf.all.send_redirects = 0 >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.default.send_redirects" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.conf.default.send_redirects already set"
else
echo "net.ipv4.conf.default.send_redirects = 0"
echo "net.ipv4.conf.default.send_redirects = 0" >> $sysctlfile
fi

if [ "$(grep "net.ipv4.conf.default.send_redirects" $sysctlfile &>/dev/null; echo $?)" == 0 ]; then
echo "net.ipv4.route.flush already set"
else
echo "net.ipv4.route.flush = 1"
echo net.ipv4.route.flush = 1 >> $sysctlfile
fi
sysctl -p
echo 
echo "###############################################################"
echo
echo "Ensure AIDE is installed"
if [ "$(rpm -q aide &>/dev/null; echo $?)" == 0 ]; then
	echo "AIDE is already installed"
else
	echo "AIDE is not installed,Installing AIDE"
	yum install -y aide
	echo "Initialize Aide"
	aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
	echo "Adding Cron"
	if [ "$(grep "#Enabling Aide check" &>/dev/null; echo $?)" == 0 ]; then
	echo "Cron already enabled"
	else
	echo "#Enabling Aide check" >> /var/spool/cron/root
	echo '0 1 * * * /usr/sbin/aide --check >/dev/null 2>&1' >> /var/spool/cron/root
	fi
fi
echo
echo "###############################################################"
echo
echo "Ensure TCP Wrappers Installed or Not"
if [ "$(rpm -q tcp_wrappers &>/dev/null; echo $?)" == 0 ] && [ "$(rpm -q tcp_wrappers-libs &>/dev/null; echo $?)" == 0 ]; then
	echo "TCP Wrappers already Installed"
else
	echo "Installing TCP Wrappers"
	yum install -y tcp_wrappers 
	echo "TCP Wrappers Installed"
fi
echo
echo "###############################################################"
echo
echo "Audit for processes that start prior to auditd daemon" 
auditfile="/boot/grub/menu.lst"
if [ "$(grep "audit" $auditfile &>/dev/null; echo $?)" == 0 ]; then
	echo "Audit parameter is already added to the kernel line"
	echo `grep "audit" /boot/grub/menu.lst`
else
	echo "Add the Auditd line at the end of kernel line"
	sed -ie '/^kernel/s/$/ audit=1/' $auditfile
	echo `grep "audit" /boot/grub/menu.lst`
fi
echo
echo "###############################################################"
echo
echo "Compressing the LogRotate"
logrotatefile="/etc/logrotate.conf"
if [ "$(grep "#compress" $logrotatefile &>/dev/null; echo $?)" == 0 ]; then
	sed -i "s/^#compress/compress/g" $logrotatefile 
	echo `grep compress $logrotatefile`
else
	echo "Compress option already enabled."
fi
echo
echo "###############################################################"
echo
echo "Installing Postfix"
yum install -y postfix
chkconfig postfix on
cp /etc/postfix/main.cf /etc/postfix/main.cf.bak
service postfix start
echo
echo "Postfix Installed"
echo
echo "###############################################################"
