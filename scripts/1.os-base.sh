#!/bin/bash
#-----------------------------------------------------------------------#
# System security initiate hardening tool for CentOS Linux 7 Server.
# WeiyiGeek <master@weiyigeek.top>
# Blog : https://blog.weiyigeek.top
# 微信公众号: 全栈工程师修炼指南
# The latest version of my giuthub can be found at:
# https://github.com/WeiyiGeek/SecOpsDev/
#
# Copyright (C) 2020-2023 WeiyiGeek
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------#

# 函数名称: base_hostname
# 函数用途: 配置系统主机名称相关文件
# 函数参数: 无
function base_hostname () {
  log::info "[${COUNT}] 配置系统主机名称-Configure OS Hostname."
  cp /etc/hosts ${BACKUPDIR}

  # 1.配置文件中IP地址获取
  local IP
  IP=${VAR_IP%%/*}

  if [[ "${HOSTNAME}" != "${VAR_HOSTNAME}" ]];then
  # 2.设置系统主机名称base_formatPS1
    sudo hostnamectl set-hostname --static ${VAR_HOSTNAME} 

  # 3.替换主机hosts文件
    sed -i "s/127.0.0.1  /127.0.0.1 ${VAR_HOSTNAME}/g" /etc/hosts
    sed -i "s/::1      /::1 ${VAR_HOSTNAME}/g" /etc/hosts
    # hostname -I:all addresses for the host
    grep -q "^\$(hostname -I)\s.\w.*$" /etc/hosts && sed -i "s/\$(hostname -I)\s.\w.*$/${IP} ${VAR_HOSTNAME}" /etc/hosts || echo "${IP} ${VAR_HOSTNAME}" >> /etc/hosts
  fi

  if [ $? == 0 ];then log::info "${IP} ${VAR_HOSTNAME} write /etc/hosts." ;fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: base_mirror
# 函数用途: 配置系统主机软件仓库镜像源
# 函数参数: 无
function base_mirror() {
  log::info "[${COUNT}] 配置主机软件仓库源-Configure os software mirror"
  cp -a /etc/yum.repos.d/*.repo ${BACKUPDIR}

  # 1.获取操作系统发行版
  local release
  release=$(cat /etc/redhat-release)
  log::info "[${COUNT}] ${release}"

  # 2.验证配置镜像仓库源
  log::info "配置镜像仓库源为阿里云镜像源."
  curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
  sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/CentOS-Base.repo

  # 3.配置 epel 仓库镜像源
  log::info "配置 epel 仓库镜像源为阿里云镜像源."
  curl -o /etc/yum.repos.d/CentOS-epel.repo http://mirrors.aliyun.com/repo/epel-7.repo

  # 4.清理缓存并创建仓库元数据
  log::info "清理缓存并创建仓库元数据"
  sudo yum clean all && sudo yum makecache

  # 5.验证仓库源
  yum repolist epel -v

  # read -p : 指定提示符，用于提示用户输入数据
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, Perform system software update and upgrade, But Not Upgrade Kernel. (Y/N) : " VERIFY
  if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then
    sudo yum update --exclude=kernel* -y && sudo yum upgrade -y
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

# 函数名称: base_software
# 函数用途: 安装更新常用软件包，编译环境及常用软件工具
# 函数参数: 无
function base_software() {
  log::info "[${COUNT}] 安装常规软件-Installation and compilation environment and common software tools."
  
  # 1.安装更新系统软件
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, Perform system software update and upgrade, But Not Upgrade Kernel (Y/N) : " VERIFY
  if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then
   yum repolist && sudo yum update --exclude=kernel* && sudo yum upgrade -y 
  fi

  # 2.安装系统主机运维所需的常规软件
  sudo yum install -y gcc make gcc-c++ openssl-devel bzip2-devel libpam-cracklib policycoreutils-python
  sudo yum install -y nano vim git unzip unrar chrony ftp wget dos2unix net-tools tree htop sysstat psmisc bash-completion jq rpcbind dialog nfs-utils 

  # 补充：代理方式进行更新
  # echo "proxy=http://127.0.0.1:8080/" >> /etc/yum.conf
  # sudo yum clean all -y && sudo yum update -y && sudo yum upgrade -y
  # sudo yum install -y 软件包

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: base_software_chrony
# 函数用途: 安装配置 chrony 时间同步服务器
# 函数参数: 无
function base_software_chrony() {
  log::info "[${COUNT}] 安装时间同步工具-Installation time sync chrony."
  cp /etc/chrony.conf ${BACKUPDIR}

  # 1.安装 Chrony 客户端配置
  # 方式1.使用 chrony 
  if [[ $(rpm -qa | grep -c "chrony") -eq 0 ]];then
    yum install -y chrony
  fi

  # 2.配置 chrony 时间同步服务器
  grep -E -q "^server" /etc/chrony.conf | sed -i 's/^server/# server/g' /etc/chrony.conf 
  grep -E -q "^pool" /etc/chrony.conf | sed -i 's/^pool/# pool/g' /etc/chrony.conf 
  for ntp in ${VAR_NTP_SERVER[@]};do 
    echo "ntp server => ${ntp}"
    if [[ ${ntp} =~ "ntp" ]];then
      echo "pool ${ntp} iburst maxsources 4" >> /etc/chrony.conf;
    else
      echo "pool ${ntp} iburst maxsources 1" >> /etc/chrony.conf;
    fi
  done

  # 3.重启 chronyd 服务
  systemctl enable chronyd.service && systemctl restart chronyd.service

  ## chrony.conf 配置示例
  # sudo tee /etc/chrony.conf <<'EOF'
  # confdir /etc/conf.d
  # server ntp.aliyun.com iburst maxsources 4
  # server ntp.tencent.com iburst maxsources 4
  # pool 192.168.10.254 iburst maxsources 1
  # pool 192.168.12.254 iburst maxsources 2
  # pool 192.168.4.254 iburst maxsources 3
  # sourcedir /run/chrony-dhcp
  # sourcedir /etc/sources.d
  # keyfile /etc/chrony.keys
  # driftfile /var/lib/chrony/chrony.drift
  # ntsdumpdir /var/lib/chrony
  # logdir /var/log/chrony
  # maxupdateskew 100.0
  # rtcsync
  # makestep 1 3
  # leapsectz right/UTC
  # EOF

  # 方式2.使用 ntpdate 工具定时同步，不过作者建议使用 chrony 工具。
  # sudo ntpdate 192.168.10.254 || sudo ntpdate 192.168.12.254 || sudo ntpdate ntp1.aliyun.com
  
  # 方式3.使用系统 systemd-timesyncd
  # echo 'NTP=192.168.10.254 192.168.4.254' >> /etc/systemd/timesyncd.conf
  # echo 'FallbackNTP=ntp.aliyun.com' >> /etc/systemd/timesyncd.conf
  # systemctl restart systemd-timesyncd.service

  if [[ ${VAR_VERIFY_RESULT} == "Y" ]];then systemctl status chronyd.service -l --no-pager;fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: base_timezone
# 函数用途: 主机时间同步校准与时区设置
# 函数参数: 无
function base_timezone() {
  log::info "[${COUNT}] 目前时间时区设置-Configure OS Time and TimeZone."
  log::info "目前时间: $(date -u), 时区：$(date +'%::z')"

  # 1.设置时区
  sudo cp -a /usr/share/zoneinfo/${VAR_TIMEZONE} /etc/localtime
  sudo timedatectl set-timezone ${VAR_TIMEZONE}
  # sudo dpkg-reconfigure tzdata  # 修改确认
  # sudo bash -c "echo 'Asia/Shanghai' > /etc/timezone" # 与上一条命令一样

  # 2.将当前的 UTC 时间写入硬件时钟 (硬件时间默认为UTC)
  sudo timedatectl set-local-rtc 0

  # 3.启用NTP时间同步：
  sudo timedatectl set-ntp yes

  # 4.校准时间服务器-时间同步(推荐使用chronyc进行平滑同步)
  sudo chronyc tracking

  # 5.手动校准-强制更新时间
  # chronyc -a makestep

  # 6.系统时钟同步硬件时钟
  # sudo hwclock --systohc
  sudo hwclock -w
  log::info "设置时间同步与时区后: $(date -u)，时区：$(date +'%::z')"

  # 7.重启依赖于系统时间的服务
  sudo systemctl restart rsyslog.service crond.service

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

# 函数名称: base_formatPS1
# 函数用途: 设置shell终端命令行显示格式,防止在执行命令时执行错误机器。
# 函数参数:
# [app@weiyigeek-Security ~ 10.20.176.120 15:53]$ 
# [\u@\h ${HOST_IP} \A \W]: \u代表用户名，\h代表主机名，\W代表利用basename取得工作目录名称，所以只会列出最后一个目录 \A:时间
function base_formatPS1() {
  log::info "[${COUNT}] 设置终端命令行显示格式-Set Shell Terminal Command Line Display Format."

  tee -a /etc/bashrc <<'EOF'
  HOST_IP=$(hostname -I|cut -d ' ' -f 1)
if [ $UID -eq 0 ];then
export PS1="[\u@\h ${HOST_IP} \A \W] ➤ "
else
export PS1="[\u@\h ${HOST_IP} \A \W]\$ "
fi
EOF

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: base_banner
# 函数用途: 远程本地登陆主机信息展示
# 函数参数: 无
function base_banner() {
  log::info "[${COUNT}] 设置远程登录警告及提示信息-Configure OS Local or Remote Login Banner Tips."

  # 1.SSH登录前警告Banner提示
  local author
  author=${VAR_MANAGER_DEPARTMENT}
  egrep -q "^\s*(banner|Banner)\s+\W+.*$" /etc/ssh/sshd_config && sed -ri "s/^\s*(banner|Banner)\s+\W+.*$/Banner \/etc\/issue.net/" /etc/ssh/sshd_config || \
  echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sudo tee /etc/issue <<EOF
************************* [ 安全登陆 (Security Login) ] ************************
Authorized users only. All activity will be monitored and reported.By ${author} Security Center.
Manager: ${author}
Security Center: ${VAR_MANAGER_URL}

EOF
sudo tee /etc/issue.net <<EOF
************************* [ 安全登陆 (Security Login) ] *************************
Authorized users only. All activity will be monitored and reported.By ${author} Security Center.
Manager: ${author}
Security Center: ${VAR_MANAGER_URL}

EOF

  # 2.本地控制台与SSH登录后提示自定义提示信息
  # motd是什么： 常用于通告信息，如计划关机时间的警告等，登陆后的提示信息，文件/etc/motd，(motd即motd即message of today布告栏信息的缩写)
tee /etc/motd <<'EOF'
Welcome to Visit CentOS Linux 7 Private Computer Server!
If the server is abnormal, please contact IT security center.

                   _ooOoo_
                  o8888888o
                  88" . "88
                  (| -_- |)
                  O\  =  /O
               ____/`---'\____
             .'  \\|     |//  `.
            /  \\|||  :  |||//  \
           /  _||||| -:- |||||-  \
           |   | \\\  -  /// |   |
           | \_|  ''\---/''  |   |
           \  .-\__  `-`  ___/-. /
         ___`. .'  /--.--\  `. . __
      ."" '<  `.___\_<|>_/___.'  >'"".
     | | :  `- \`.;`\ _ /`;.`/ - ` : | |
     \  \ `-.   \_ __\ /__ _/   .-` /  /
======`-.____`-.___\_____/___.-`____.-'======
                   `=---='
 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
           佛祖保佑       永不死机
           心外无法       法外无心
EOF

  # 3.自定义登录后显示主机相关信息脚本
tee /usr/local/bin/00-custom-header <<'EOF'
#!/bin/bash
#-----------------------------------------------------------------------#
# System security initiate hardening tool for Linux CentOS 7 Server.
# WeiyiGeek <master@weiyigeek.top>
# Blog : https://blog.weiyigeek.top
#
# The latest version of my giuthub can be found at:
# https://github.com/WeiyiGeek/SecOpsDev/
# 
# Copyright (C) 2020-2023 WeiyiGeek
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------#
# Get last login time
LAST_LOGIN=$(last -n 2 | sed -n '2p;')
LAST_LOGIN_T=$(echo ${LAST_LOGIN} | awk '{print $2}')
LAST_LOGIN_IP=$(echo ${LAST_LOGIN} | awk '{print $3}')
LAST_LOGIN_TIME=$(echo ${LAST_LOGIN} | awk '{print $4,$5,$6,$7}')
LAST_LOGOUT_TIME=$(echo ${LAST_LOGIN} | awk '{print $9}')

# Get load averages
LOAD1=$(grep "" /proc/loadavg | awk '{print $1}')
LOAD5=$(grep "" /proc/loadavg | awk '{print $2}')
LOAD15=$(grep "" /proc/loadavg | awk '{print $3}')

# Get free memory
MEMORY_USED=$(free -t -m | grep "Mem" | awk '{print $3}')
MEMORY_ALL=$(free -t -m | grep "Mem" | awk '{print $2}')
MEMORY_PERCENTAGE=$(free | awk '/Mem/{printf("%.2f%"), $3/$2*100}')

# Get system uptime
UPTIME=$(grep "" /proc/uptime | cut -f1 -d.)
UPTIME_DAYS=$((${UPTIME}/60/60/24))
UPTIME_HOURS=$((${UPTIME}/60/60%24))
UPTIME_MINS=$((${UPTIME}/60%60))
UPTIME_SECS=$((${UPTIME}%60))

# Get processes
PROCESS=$(ps -eo user=|sort|uniq -c | awk '{print $2 " " $1 }')
PROCESS_ALL=$(echo "${PROCESS}" | awk '{print $2}' | awk '{SUM += $1} END {print SUM}')
PROCESS_ROOT=$(echo "${PROCESS}" | grep root | awk '{print $2}')
PROCESS_USER=$(echo "${PROCESS}" | grep -v root | awk '{print $2}' | awk '{SUM += $1} END {print SUM}')

# Get processors
PROCESSOR_NAME=$(grep "model name" /proc/cpuinfo | cut -d ' ' -f3- | awk '{print $0}' | head -1)
PROCESSOR_COUNT=$(grep -ioP 'processor\t:' /proc/cpuinfo | wc -l)

# Colors
G="\033[01;32m"
R="\033[01;31m"
B="\033[01;34m"
P="\033[01;35m"  # purple
D="\033[39m\033[2m"
N="\033[0m"

echo -e "\e[01;38;44;5m##################### 主机资源信息 (Host resource information ) #######################\e[0m"
echo -e "[Login Info]\n"
echo -e "USER: ${G}$(whoami)${N}"
echo -e "You last logged in to ${G}${LAST_LOGIN_T}${N} of ${G}$(uname -n)${N} system with IP ${P}${LAST_LOGIN_IP}${N}, \nLast Login time is ${P}${LAST_LOGIN_TIME}${N}, Logout time is ${R}${LAST_LOGOUT_TIME}${N}.\n"

echo -e "[System Info]\n"
echo -e "  SYSTEM    : $(awk -F'[="]+' '/PRETTY_NAME/{print $2}' /etc/os-release)"
echo -e "  KERNEL    : $(uname -sr)"
echo -e "  ARCH      : $(uname -m)"
echo -e "  UPTIME    : ${G}${UPTIME_DAYS}${N} days ${G}${UPTIME_HOURS}${N} hours ${G}${UPTIME_MINS}${N} minutes ${G}${UPTIME_SECS}${N} seconds"
echo -e "  CPU       : ${PROCESSOR_NAME} (${G}${PROCESSOR_COUNT}${N} vCPU)\n"
echo -e "  MEMORY    : ${MEMORY_USED} MB / ${MEMORY_ALL} MB (${G}${MEMORY_PERCENTAGE}${N} Used)"
echo -e "  LOAD AVG  : ${G}${LOAD1}${N} (1m), ${G}${LOAD5}${N} (5m), ${G}${LOAD15}${N} (15m)"
echo -e "  PROCESSES : ${G}${PROCESS_ROOT}${N} (root), ${G}${PROCESS_USER}${N} (user), ${G}${PROCESS_ALL}${N} (total)"
echo -e "  USERS     : ${G}$(users | wc -w)${N} users logged in"
echo -e "  BASH      : ${G}${BASH_VERSION}${N}\n"

echo -e "[Disk Usage]\n"
mapfile -t DFH < <(df -h -x zfs -x squashfs -x tmpfs -x devtmpfs -x overlay --output=target,pcent,size,used | tail -n+2)
for LINE in "${DFH[@]}"; do
    # Get disk usage
    DISK_USAGE=$(echo "${LINE}" | awk '{print $2}' | sed 's/%//')
    USAGE_WIDTH=$(((${DISK_USAGE}*60)/100))

    # If the usage rate is <90%, the color is green, otherwise it is red
    if [ "${DISK_USAGE}" -gt 90 ]; then
        COLOR="${R}"
    else
        COLOR="${G}"
    fi

    # Print the used width
    BAR="[${COLOR}"
    for ((i=0; i<"${USAGE_WIDTH}"; i++)); do
        BAR+="="
    done

    # Print unused width
    BAR+=${D}
    for ((i="${USAGE_WIDTH}"; i<60; i++)); do
        BAR+="="
    done
    BAR+="${N}]"

    # Output
    echo "${LINE}" | awk '{ printf("Mounted: %-32s %s / %s (%s Used)\n", $1, $4, $3, $2); }' | sed -e 's/^/  /'
    echo -e "${BAR}" | sed -e 's/^/  /'
done
echo       
EOF
  chmod +755 /usr/local/bin/00-custom-header 

  # 将脚本文件添加到 /etc/profile 末尾，以便每次登录时自动执行
  if [ $(grep -c "00-custom-header" /etc/profile) -eq 0 ];then 
    echo "/usr/local/bin/00-custom-header" >> /etc/profile
  else
    log::warn "00-custom-header already exists in the /etc/profile file "
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: base_update_kernel
# 函数用途: 升级系统内核版本(慎用、按需使用)
# 函数参数: 无
function base_update_kernel() {
  log::info "[${COUNT}] 升级系统内核版本（谨慎）-Update OS kernel Version."
  printf "\n[Kernel Version]:\033[34m $(uname -r) \033[0m \n"

  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, Do you want to update the system kernel (谨慎使用). (Y/N) : " VERIFY
  if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then
    # 安装ELRepo仓库
    wget -O /etc/yum.repos.d/epel.repo https://mirrors.aliyun.com/repo/epel-7.repo
    # 查看可安装的内核版本信息
    yum --disablerepo="*" --enablerepo=epel list kernel*
    # 内核安装，服务器里我们选择长期lt版本，安全稳定是我们最大的需求，除非有特殊的需求内核版本需求;
    yum update -y --enablerepo=epel
    # 内核版本介绍, lt:longterm 的缩写长期维护版, ml:mainline 的缩写最新主线版本;
    yum install -y --enablerepo=epel --skip-broken kernel kernel-devel kernel-tools

    # 当前操作系统可切换的内核版本
    awk -F \' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg
    
    # 查看当前默认启动内核,0 表示最新安装的内核，设置为 0 表示以新版本内核启动
    sudo grub2-set-default 0

    # 限制系统上安装的内核数量，保留最新的三个内核版本。
    sed -i "/installonly_limit/c installonly_limit=3" /etc/yum/yum.conf

    # 更新GRUB2配置文件
    grub2-mkconfig -o /boot/grub2/grub.cfg
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: base_reboot
# 函数用途: 初始化与安全配置完成后，选择是否进行重启或者关闭服务器（建议重启）
# 函数参数: 无
function base_reboot() {
  log::info "[${COUNT}] Do you want to restart or shut down the server."

  log::info "[-] 选择重启或者关闭服务器(默认选项)，注意执行后需要等待1分钟."
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input,Do you want to restart (Y) or shut down (N) the server. (Y/N) : " VERIFY
  if [[ ${VERIFY:="Y"} == "N" || ${VERIFY:="y"} == "n" ]];then
    shutdown --poweroff --no-wall
  else
    shutdown --reboot --no-wall
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

