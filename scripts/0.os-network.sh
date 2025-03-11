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

# 函数名称: net_ip
# 函数用途: 主机IP地址与网关设置
# 函数参数: 无
function net_ip () 
{
  log::info "[${COUNT}] 主机网络配置-Configure IP address and IP Gateway."
  cp -a /etc/sysconfig/network-scripts/* ${BACKUPDIR}

  # 创建网卡配置脚本文件及权限赋予
  if [ ! -f /opt/init/ ];then 
  mkdir -vp /opt/init/
sudo tee /opt/init/network.sh <<'EOF'
#!/bin/bash
# @Description: Configure CentOS Linux 7 Network
# @Author: WeiyiGeek
# @E-mail: master@weiyigeek.top
# @Blog: https://www.weiyigeek.top
if [[ $# -lt 4 ]];then
  echo "Usage: $0 NetInterface IP/NETMASK GATEWAY DNS"
  echo "Example: $0 ens192 192.168.12.12/24 192.168.12.1 223.6.6.6"
  echo "@Author: WeiyiGeek"
  echo "@Blog: https://blog.weiyigeek.top"
  exit
fi

echo "Setting Network interface card: ${1}, IP: ${2} , GATEWAY: ${3}"
CURRENT_IP=$(hostname -I | cut -f 1 -d " ")
CURRENT_GATEWAY=$(hostname -I | cut -f 1,2,3,4 -d ".")
CURRENT_FILE=/etc/sysconfig/network-scripts/ifcfg-${1}
CONFIG_IP=${2%%/*}
CONFIG_PREFIX=${2##*/}

echo "Original Network info: IP: ${CURRENT_IP} , GATEWAY: ${CURRENT_GATEWAY}"
echo "Setting Network interface card: ${1}, IP/NETMASK: ${2} , GATEWAY: ${3}, DNS: ${4}"

if [[ -f ${CURRENT_FILE} ]];then
  # 已存在网卡配置文件的情况下
  egrep -q "^\s*ONBOOT=.*$" ${CURRENT_FILE} && sed -ri "s/^\s*ONBOOT=.*$/ONBOOT=yes/" ${CURRENT_FILE}|| echo "ONBOOT=yes" >> ${CURRENT_FILE}
  egrep -q "^\s*BOOTPROTO=.*$" ${CURRENT_FILE} && sed -ri "s/^\s*BOOTPROTO=.*$/BOOTPROTO=none/" ${CURRENT_FILE}|| echo "BOOTPROTO=none" >> ${CURRENT_FILE}
  egrep -q "^\s*IPADDR=.*$" ${CURRENT_FILE} && sed -ri "s/^\s*IPADDR=.*$/IPADDR=${CONFIG_IP}/" ${CURRENT_FILE}|| echo "IPADDR=${CONFIG_IP}" >> ${CURRENT_FILE}
  egrep -q "^\s*PREFIX=.*$" ${CURRENT_FILE} && sed -ri "s/^\s*PREFIX=.*$/PREFIX=${CONFIG_PREFIX}/" ${CURRENT_FILE}|| echo "PREFIX=${CONFIG_PREFIX}" >> ${CURRENT_FILE}
  egrep -q "^\s*GATEWAY=.*$" ${CURRENT_FILE} && sed -ri "s/^\s*GATEWAY=.*$/GATEWAY=${3}/" ${CURRENT_FILE}|| echo "GATEWAY=${3}" >> ${CURRENT_FILE}
  egrep -q "^\s*DNS1=.*$" ${CURRENT_FILE} && sed -ri "s/^\s*DNS1=.*$/DNS1=${4}/" ${CURRENT_FILE}|| echo "DNS1=${4}" >> ${CURRENT_FILE}
else
  # 修改 IP 地址和掩码
  sudo ip addr add ${2} dev ${1}
  # 修改默认网关
  sudo ip route add default via ${3} dev ${1}
  # 若存在 nmcli 命令则可以使用如下命令
  # nmcli conn add connection.id ${1}-staic connection.interface-name ${1} connection.autoconnect yes type Ethernet ifname ${1} ipv4.method manual ipv4.address ${2} ipv4.gateway ${3} ipv4.dns ${4} ipv4.ignore-auto-dns true
fi
EOF
  sudo chmod +x /opt/init/network.sh

  # 执行网卡配置脚本文件
  echo "Try Run: /opt/init/network.sh ${VAR_NETINTERFACE} ${VAR_IP} ${VAR_GATEWAY} ${VAR_DNS_SERVER}"
  /opt/init/network.sh ${VAR_NETINTERFACE} ${VAR_IP} ${VAR_GATEWAY} ${VAR_DNS_SERVER}

  # 是否重新加载网络配置
  read -t 5 -p "reload network card configure, It is recommended to enter N during initialization (Y/N):" VERTIFY
  if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then
    sudo systemctl restart network
    ip addr show ${VAR_NETINTERFACE}
  else
    log::warn "Please Check network card configure and reload the network card manually, run sudo systemctl restart network."
  fi

  else
    log::error "已存在网络配置脚本-Already exists configure networking script."
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: net_dns
# 函数用途: 设置主机DNS解析服务器
# 函数参数: 无
function net_dns () {
  log::info "[${COUNT}] 配置主机DNS-Configure Domain Server."
  cp /etc/resolv.conf  ${BACKUPDIR}

  # 清空原始的DNS配置文件
  truncate -s 0 /etc/resolv.conf

  # 此处配置DNSPod 以及 阿里云 DNS
  for dns in ${VAR_DNS_SERVER[@]};do 
    grep -q "${dns}" /etc/resolv.conf 
    if [ $? != 0 ];then 
tee -a /etc/resolv.conf <<-EOF
nameserver ${dns}
EOF
    fi
  done
  
  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}
