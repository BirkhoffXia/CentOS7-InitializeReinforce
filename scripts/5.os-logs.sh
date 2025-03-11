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

# 函数名称: logs_historypolicy
# 函数用途: 记录用户终端执行的历史命令记录安全策略设置
# 函数参数: 无
function logs_historypolicy () {
  log::info "[${COUNT}] 用户历史密码策略设置-System user shell command record security policy setting."

  # 1.历史命令条数限制以及历史命令输出文件
  log::info "[-] 用户终端执行的历史命令记录."
  egrep -q "^HISTSIZE\W\w+.*$" /etc/profile && sed -ri "s/^HISTSIZE\W\w+.*$/HISTSIZE=${VAR_HISTSIZE}/" /etc/profile || echo "HISTSIZE=${VAR_HISTSIZE}" >> /etc/profile
  echo
  # who -u am i ：root     pts/1        2025-03-04 14:33   .         18050 (10.30.10.39)
  # awk '{print $NF}' : 打印每一行最后一个字段
  tee /etc/profile.d/history-record.sh <<'EOF'
# 历史命令执行记录文件路径.
LOGTIME=$(date +%Y%m%d%H%M%S)
# 按照用户以及客户端地址分割
if [ ! -d "/var/log/.history/${USER}" ];then
  mkdir -vp /var/log/.history/${USER} > /dev/null
fi
ClientIP=$(who -u am i 2>/dev/null| awk '{print $NF}'|sed -e 's/[()]//g')
export HISTFILE="/var/log/.history/${USER}/${LOGTIME}-${ClientIP}.history"
if [ ! -f ${HISTFILE} ];then
  touch ${HISTFILE}
fi
chmod 600 ${HISTFILE}
# 历史命令执行文件大小记录设置.
HISTFILESIZE=128
HISTTIMEFORMAT="%F_%T $(whoami)#$(who -u am i 2>/dev/null| awk '{print $NF}'|sed -e 's/[()]//g'):"
EOF

  # 2.执行权限赋予与及时生效 
  chmod a+x /etc/profile.d/history-record.sh
  source /etc/profile.d/history-record.sh

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: logs_rsyslogpolicy
# 函数用途: 系统记录检查安全日志事件策略
# 函数参数: 无
function logs_rsyslogpolicy () {
  log::info "[${COUNT}] 系统安全事件策略配置-System Rsyslog security policy setting."
  
  # 检查使用sudo相关信息记录
  egrep -q "^(#)?local2.debug.*sudo.*$" /etc/rsyslog.conf  && sed -r "s|^(#)?local2.debug.*sudo.*$|local2.debug -${SUDO_LOG_FILE}|" /etc/rsyslog.conf  || echo "local2.debug -${SUDO_LOG_FILE}" >>  /etc/rsyslog.conf 

  # 检查配置内核以及守护进程情况记录
  if [ ! -f /var/log/.run/message ];then
    echo "创建 rsyslog 记录文件"
    mkdir -vp /var/log/.run
    touch /var/log/.run/message
  fi 
  grep -q "/var/log/.run/message" /etc/rsyslog.conf
  if [ $? -ne 0 ];then
tee -a /etc/rsyslog.conf <<EOF
authpriv.*   /var/log/.run/message
EOF
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: logs_auditdpolicy
# 函数用途: 系统审计规则安全策略，其包含
# 1.身份鉴别、自主访问控制、标记和强制访问控制等安全功能的使用
# 2.创建、删除客体的操作
# 3.所有管理员的操作
# 4.每条审计记录应包括：事件类型、事件发生的日期和时间、触发事件的用户、事件
# 成功或失败等字段
# 5.创建和删除客体的事件审计记录还应包括客体的名字、客体的安全属性
# 6.网络会话事件审计记录还应包括：网络程序名称、协议类型、源IP地址、目的IP地址、源端口、目的端口、会话总字节数等字段
# 函数参数: 无
function logs_auditdpolicy () {
  log::info "[${COUNT}] 配置系统审计服务于策略-System audit security policy setting."

  # 检查 audit 服务是否启动
  systemctl status auditd.service | grep "Active: active"
  if [ $? != 0 ];then 
    systemctl start auditd.service
    systemctl enable auditd.service
    systemctl mask fauditd.servicee >/dev/null 2>&1
  fi

  echo -e "设置 audit 审计规则：监控 /etc/passwd、/etc/group、/etc/shadow 以及 /etc/sudoers 等文件的arwx"
  # 监控 /etc/passwd、/etc/group、/etc/shadow 以及 /etc/sudoers 等文件的arwx
  auditctl -w /etc/passwd -k file
  auditctl -w /etc/shadow -k file
  auditctl -w /etc/group -k file
  auditctl -w /etc/sudoers -k file
  
  # 监控 root 用户下的系统调用 execv
  auditctl -a exit,always -F arch=b64 -S execve -F uid=0 

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

