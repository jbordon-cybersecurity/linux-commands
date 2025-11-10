# 🧭 LinuxZoo + Napier Practical Command Handbook

_A curated list of essential Linux commands used across Napier’s Networking, Security, and SELinux practicals (LinuxZoo, pfSense, AWS, etc.)._

---

## ⚙️ 1️⃣ Basic System Commands
| **Command**                 | **Description**                        |
| --------------------------- | -------------------------------------- |
| `pwd`                       | Show current working directory         |
| `ls -l` / `ls -a`           | List files (long format / show hidden) |
| `cd /path`                  | Change directory                       |
| `mkdir name` / `rmdir name` | Create or remove directory             |
| `cp src dest`               | Copy file(s)                           |
| `mv src dest`               | Move or rename file                    |
| `rm file` / `rm -r folder`  | Delete files or directories            |
| `cat file` / `less file`    | View file contents                     |
| `head -n` / `tail -n`       | Show first or last lines of a file     |
| `clear`                     | Clear the terminal screen              |
| `history`                   | Show recent commands                   |
| `!23`                       | Repeat command number 23 from history  |


---

## 🔐 2️⃣ File Permissions & Ownership
| **Command**        | **Description**                         |
| ------------------ | --------------------------------------- |
| `ls -l`            | View permissions                        |
| `chmod 755 file`   | Change file permissions (rwx for owner) |
| `chown user file`  | Change file owner                       |
| `chgrp group file` | Change group ownership                  |


---

## 🌐 3️⃣ Networking Basics
| **Command**                  | **Description**              |
| ---------------------------- | ---------------------------- |
| `ip addr show`               | Show all IP addresses        |
| `ifconfig`                   | Legacy network configuration |
| `ip route`                   | Show routing table           |
| `ping <ip>`                  | Test connectivity            |
| `traceroute -I <ip>`         | Trace path using ICMP        |
| `netstat -tuln` / `ss -tuln` | Show listening TCP/UDP ports |
| `hostname`                   | Display hostname             |
| `nslookup <domain>`          | DNS lookup                   |
| `curl <url>` / `wget <url>`  | Fetch a webpage              |
| `scp file user@host:/path`   | Secure copy to remote        |
| `ssh user@host`              | Secure remote login          |


---

## 🧩 4️⃣ LinuxZoo Networking Practical
| **Purpose**                   | **Command**                                                  |
| ----------------------------- | ------------------------------------------------------------ |
| Show interfaces               | `ip addr show`                                               |
| Find default gateway          | `ip route`                                                   |
| Add IP to interface           | `sudo ip addr add 192.168.X.X/24 dev eth2`                   |
| Add IP with broadcast         | `sudo ip addr add 192.168.3.62/28 brd 192.168.3.63 dev eth3` |
| Remove all IPs from interface | `sudo ip addr flush dev eth2`                                |
| Verify connectivity           | `ping 192.168.1.23`                                          |
| Check MAC of interface        | `ip link show eth3`                                          |
| Check ARP cache               | `cat /proc/net/arp`                                          |
| Add default route             | `ip route add default via 192.168.X.X dev eth0`              |

---

## 🧠 5️⃣ SELinux Administration Practical
| Purpose                        | Command                                                                   |
| ------------------------------ | ------------------------------------------------------------------------- |
| **Check enforcement mode**     | `getenforce`                                                              |
| **View full status**           | `sestatus`                                                                |
| **Check enforcement value**    | `cat /sys/fs/selinux/enforce`                                             |
| **Locate SELinux sys dir**     | `ls /sys/fs/selinux`                                                      |
| **Count items in dir**         | `ls /sys/fs/selinux \| wc -l`                                             |
| **Locate rsyslogd binary**     | `which rsyslogd`                                                          |
| **Get SELinux label (file)**   | `ls -Z /usr/sbin/rsyslogd`                                                |
| **Get SELinux label (config)** | `ls -Z /etc/rsyslog.conf`                                                 |
| **Get process label**          | `ps -eZ \| grep rsyslogd`                                                 |
| **Search allow rule (file)**   | `sesearch --allow -s syslogd_t -t syslog_conf_t -c file > /root/selinux1` |
| **Search allow rule (dir)**    | `sesearch --allow -s syslogd_t -t syslog_conf_t -c dir > /root/selinux2`  |
| **List dirs matching label**   | `ls -Zd /etc/* \| grep syslog_conf_t > /root/selinux3`                    |
| **Find all items by context**  | `find /etc -context '*:syslog_conf_t:*' > /root/selinux4`                 |


---

### 🔹 SELinux Port Rules
| **Purpose**                  | **Command**                                                                  |
| ---------------------------- | ---------------------------------------------------------------------------- |
| Show enabled name_bind rules | `sesearch -A -s syslogd_t -c tcp_socket -p name_bind -C \| grep -v '^D[TF]'` |
| Count enabled rules          | `... \| wc -l`                                                               |
| List port types              | `semanage port -l \| egrep 'syslogd_port_t\|syslog_tls_port_t\|rsh_port_t'`  |
| Find service name            | `grep 6514/tcp /etc/services`                                                |
| ✅ **Common answers**         | `3`, `514,601,6514`, `syslog-tls`                                            |

---

### 🔹 NetworkManager Process Transition
| **Purpose**               | **Command**                                                           |
| ------------------------- | --------------------------------------------------------------------- |
| Locate daemon             | `which NetworkManager`                                                |
| Process label             | `ps -eZ \| grep NetworkManager`                                       |
| Dispatcher.d exec label   | `ls -Z /etc/NetworkManager/dispatcher.d`                              |
| Find transition rule      | `sesearch -T -s NetworkManager_t -t NetworkManager_dispatcher_exec_t` |
| ✅ **Process type result** | `NetworkManager_dispatcher_t`                                         |

---

## 📊 6️⃣ Services, Ports & Monitoring
| **Command**                                | **Description**              |
| ------------------------------------------ | ---------------------------- |
| `systemctl status <service>`               | Check service status         |
| `systemctl restart <service>`              | Restart service              |
| `ss -tulpn`                                | Show active listening ports  |
| `netstat -ulnp \| grep 111`                | Find UDP port 111 PID        |
| `nmap 10.200.0.1 -p 50-80 --max-retries 3` | Port scan for open TCP ports |


---

## 🌩️ 7️⃣ Tcpdump & Packet Capture
| **Purpose**         | **Command**                             |
| ------------------- | --------------------------------------- |
| Start capture       | `tcpdump -vi ens3 port 80 > /tmp/log &` |
| Make web request    | `lwp-request http://linuxzoo.net`       |
| Stop capture        | `kill -1 %1`                            |
| View packets        | `cat /tmp/log \| less`                  |
| Find TCP flags      | `grep "Flags" /tmp/log`                 |
| Locate FIN sequence | `grep "Flags \[F" /tmp/log`             |


---

## 📦 8️⃣ Miscellaneous Useful Commands
| **Command**          | **Description**           |
| -------------------- | ------------------------- |
| `lsmod` / `modinfo`  | View kernel modules       |
| `df -h`              | Disk space summary        |
| `free -h`            | Memory usage              |
| `top`                | Live process monitor      |
| `date` / `cal`       | Display date and calendar |
| `yum list installed` | List installed packages   |
| `rpm -q <package>`   | Check package info        |
| `man <command>`      | View manual page          |


---

## 🧾 9️⃣ Logs & Diagnostics
| **Command**                 | **Description**      |
| --------------------------- | -------------------- |
| `dmesg \| tail`             | Show kernel messages |
| `journalctl -xe`            | View recent logs     |
| `tail -f /var/log/messages` | Monitor logs live    |


---

## 🧱 🔟 SELinux Usage Commands

| Purpose                                 | Command                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------ |
| **Create directories**                  | `mkdir /root/secure /root/protect`                                       |
| **Set SELinux type**                    | `chcon -t system_conf_t /root/secure` <br>`chcon -t etc_t /root/protect` |
| **Create test files**                   | `touch /root/secure/test1 /root/protect/test2`                           |
| **View contexts**                       | `ls -Z /root/secure /root/protect`                                       |
| **Copy file**                           | `cp /root/secure/test1 /root/protect/test3`                              |
| **Move file**                           | `mv /root/secure/test1 /root/protect/test4`                              |
| **Check copied/moved labels**           | `ls -Z /root/protect`                                                    |
| **Show default context (matchpathcon)** | `matchpathcon /root/protect/test2 > /root/match1`                        |
| **List file context rules**             | `semanage fcontext -l \| grep '^/root'`                                  |
| **Filter by type**                      | `semanage fcontext -l \| grep admin_home_t`                              |
| **Add .bin rule**                       | `semanage fcontext -a -t bin_t "/root/.*\.bin"`                          |
| **Apply new context**                   | `restorecon /root/test.bin`                                              |
| **Check boolean**                       | `getsebool httpd_tmp_exec`                                               |
| **Set boolean on**                      | `setsebool -P httpd_tmp_exec on`                                         |
| **List rules from boolean**             | `sesearch -A -b httpd_tmp_exec > /root/boolrule`                         |
| **Trigger error (manual in LinuxZoo)**  | *Click “cause error”*                                                    |
| **Start service**                       | `systemctl start httpd`                                                  |
| **Check service status**                | `systemctl status httpd`                                                 |
| **Search AVC events**                   | `ausearch -m avc -ts recent`                                             |
| **Save last AVC event line**            | `ausearch -m avc -ts recent \| tail -n 1 > /root/event`                  |
| **View saved AVC event**                | `cat /root/event`                                                        |
| **Find directory by inode**             | `find / -inum <inode> 2>/dev/null`                                       |
| **Fix context recursively**             | `restorecon -R /etc/httpd/conf.d`                                        |
| **Verify httpd active**                 | `systemctl start httpd` <br>`systemctl status httpd`                     |

       

🔥 1️⃣1️⃣ Firewall & iptables Configuration Commands

| Purpose                                              | Command                                                                                                                      |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Flush all existing rules**                         | `iptables -F INPUT; iptables -F OUTPUT; iptables -F FORWARD`                                                                 |
| **Set default policies (safe)**                      | `iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT; iptables -P FORWARD ACCEPT`                                            |
| **Set default policies (strict)**                    | `iptables -P INPUT DROP; iptables -P OUTPUT DROP; iptables -P FORWARD DROP`                                                  |
| **Save script as executable**                        | `chmod +x /root/firewall` <br>`chmod +x /root/firewall2`                                                                     |
| **Run custom firewall script**                       | `/root/firewall` or `/root/firewall2`                                                                                        |
| **Show current rules with line numbers**             | `iptables -L -n --line-numbers`                                                                                              |
| **Check specific chains**                            | `iptables -L INPUT -n --line-numbers` <br>`iptables -L OUTPUT -n --line-numbers` <br>`iptables -L FORWARD -n --line-numbers` |
| **Allow established & related incoming traffic**     | `iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`                                                     |
| **Allow established & related outgoing traffic**     | `iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`                                                    |
| **Insert Telnet allow rule (proxy 10.200.0.1)**      | `iptables -I INPUT 1 -m conntrack --ctstate NEW -p tcp --dport 23 -s 10.200.0.1 -j ACCEPT`                                   |
| **Reject Telnet from other IPs**                     | `iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 23 ! -s 10.200.0.1 -j REJECT`                                   |
| **Allow SSH from local subnet**                      | `iptables -A INPUT -m conntrack --ctstate NEW -p tcp --dport 22 ! -s 10.0.0.0/16 -j ACCEPT`                                  |
| **Allow outbound HTTP to proxy (LinuxZoo)**          | `iptables -A OUTPUT -m conntrack --ctstate NEW -p tcp -d 10.200.0.1 --dport 80 -j ACCEPT`                                    |
| **Router sim – allow RELATED & ESTABLISHED traffic** | `iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`                                                   |
| **Router sim – allow HTTP to intranet host**         | `iptables -A FORWARD -m conntrack --ctstate NEW -p tcp -d 192.168.1.5 --dport 80 -o eth9 -j ACCEPT`                          |
| **Router sim – allow PING to intranet host**         | `iptables -A FORWARD -m conntrack --ctstate NEW -p icmp --icmp-type echo-request -d 192.168.1.5 -o eth9 -j ACCEPT`           |
| **Restart iptables service (recovery)**              | `systemctl restart iptables.service`                                                                                         |
| **View persistent rule set**                         | `iptables-save`                                                                                                              |
| **Reset firewall (clear all rules & chains)**        | `iptables -F; iptables -X`                                                                                                   |

👤 1️⃣2️⃣ Server Administration & User Management (LinuxZoo Practical)

| **Command / Task**                          | **Description**                                |
| ------------------------------------------- | ---------------------------------------------- |
| `cat /etc/passwd`                           | List all user accounts                         |
| `cat /etc/group`                            | List all groups                                |
| `id <user>`                                 | Show user and group IDs                        |
| `sudo useradd -m <user>`                    | Create new user with home directory            |
| `sudo groupadd <group>`                     | Create new group                               |
| `sudo usermod -g <group> <user>`            | Change user’s primary group                    |
| `sudo passwd <user>`                        | Set or reset a user’s password                 |
| `sudo userdel <user>`                       | Delete user (keep home)                        |
| `sudo userdel -r <user>`                    | Delete user and home directory                 |
| `su - <user>`                               | Switch to another user account                 |
| `ls -ld /home/<user>`                       | Check ownership and permissions of user’s home |
| `sudo chown -R <user>:<group> /home/<user>` | Fix file ownership recursively                 |
| `sudo chmod 700 /home/<user>`               | Restrict access to home directory              |
| `alias`                                     | Show current command aliases                   |
| `unalias <command>`                         | Remove an alias temporarily                    |
| `nano ~/.bashrc` / `nano ~/.bash_profile`   | Edit user’s shell config files                 |
| `sudo tail -n 20 /var/log/secure`           | View authentication logs                       |
| `sudo lastb`                                | View failed login attempts                     |


| **Scenario**                       | **Commands & Purpose**                                                                                                                                                                                                      |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Split into 2 user groups**  | `sudo groupadd hoho`<br>`sudo usermod -g hoho jim`<br>`sudo chown -R jim:hoho /home/jim`<br>✅ Creates new group *hoho*, moves *jim* to it, and updates file ownerships.                                                     |
| **User bill cannot log in**   | `sudo cat /home/bill/.bashrc`<br>`sudo cat /home/bill/.bash_profile`<br>Remove any `exit`, `logout`, or faulty command line.<br>Test with `su - bill`.<br>✅ Fixes login shell scripts so Bill can log in normally.          |
| **User ben cannot save work** | `ls -ld /home/ben`<br>`sudo useradd ben` *(if missing)*<br>`sudo groupadd ben` *(if group missing)*<br>`sudo chown -R ben:ben /home/ben`<br>`sudo chmod 700 /home/ben`<br>✅ Restores Ben’s ownership and write permissions. |
| **User amy cannot run ls**    | `su - amy`<br>`alias` → find `alias ls='echo >/dev/null'`<br>`unalias ls`<br>`sudo nano /home/amy/.bash_profile` → delete that alias line.<br>`source ~/.bashrc`<br>✅ Restores normal *ls* behaviour.                       |

🕸️ 1️⃣3️⃣ Apache Web Server & Virtual Host Configuration (LinuxZoo Practical)

| **Command / Task**                                        | **Description / Purpose**                                                                                                   |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `systemctl start httpd` / `systemctl enable httpd`         | Start and enable the Apache service                                                   |
| `systemctl reload httpd` / `systemctl restart httpd`       | Reload or restart Apache after configuration changes                                  |
| `systemctl restart iptables`                               | Reset firewall configuration (LinuxZoo requirement)                                   |
| `vi /etc/httpd/conf.d/userdir.conf`                        | Enable `UserDir public_html` and disable `UserDir disable` to allow per-user web dirs  |
| `useradd dave` / `su - dave`                               | Create test user and switch into their environment                                   |
| `mkdir public_html` / `cd public_html`                     | Create web directory inside user’s home                                              |
| `vi hello.html`                                            | Create a test HTML page with `<h1>HOST</h1>`                                          |
| `chmod 711 /home/dave /home/dave/public_html`              | Allow directory traversal by others without listing contents                         |
| `chmod 644 /home/dave/public_html/hello.html`              | Allow Apache to read the test file                                                   |
| `setsebool -P httpd_read_user_content 1`                   | Allow Apache to read user home content under SELinux                                 |
| `setsebool -P httpd_enable_homedirs 1`                     | Enable user web directories in SELinux                                               |
| `restorecon -Rv /home/dave`                                | Fix SELinux contexts for Dave’s files and directories                                |
| `hostname`                                                 | Display host machine name (e.g., `host-5-161.linuxzoo.net`)                          |
| `curl http://host-5-161.linuxzoo.net/~dave/hello.html`     | Test local user page works correctly                                                 |
| `mkdir web vm`                                             | Create subdirectories for virtual host testing                                       |
| `cp hello.html web/` / `cp hello.html vm/`                 | Copy the test file into both new directories                                         |
| `sed -i 's/HOST/WEB/' web/hello.html` / `sed -i 's/HOST/VM/' vm/hello.html` | Replace the `<h1>` heading for clarity                                               |
| `chmod 711 web vm` / `chmod 644 web/hello.html vm/hello.html` | Apply correct access permissions                                                     |
| `vi /etc/httpd/conf.d/zvirtual.conf`                       | Create a new Apache config for virtual hosts                                         |
| `httpd -t`                                                 | Check Apache configuration syntax (expect “Syntax OK”)                               |
| `systemctl reload httpd`                                   | Reload configuration after edits                                                     |

---

## 🔹 Example VirtualHost Configuration

```apache
<VirtualHost *:80>
    ServerAdmin root@localhost
    DocumentRoot /home/dave/public_html/web
    ServerName web-5-161.linuxzoo.net
</VirtualHost>

<VirtualHost *:80>
    ServerAdmin root@localhost
    DocumentRoot /home/dave/public_html/vm
    ServerName vm-5-161.linuxzoo.net
    ServerAlias host-5-161.linuxzoo.net

    RewriteEngine On
    RewriteCond %{HTTP_HOST} ^host-5-161\.linuxzoo\.net$ [NC]
    RewriteCond %{REQUEST_URI} !^/~dave
    RewriteRule (.*) http://vm-5-161.linuxzoo.net/$1 [R=301,L]
</VirtualHost>

---

**Created by:** *Jose Bordon – BEng Cybersecurity & Forensics (Napier University)*  
**Practicals covered:** LinuxZoo Networking, SELinux Administration, and System Security  
**Maintained on GitHub:** [jbordon-cybersecurity](https://github.com/jbordon-cybersecurity)

---
