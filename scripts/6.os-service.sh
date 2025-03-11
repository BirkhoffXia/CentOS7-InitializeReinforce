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


# 函数名称: svc_disableservicepolicy
# 函数用途: 用于关闭与禁用某些服务端口，请根据需要进行更改。
# 函数参数: 无
svc_disableservicepolicy () {
  log::info "[${COUNT}] 关闭与禁用某些服务端口-Stop or Disable app and system service port."

  # 1.关闭或要禁用得服务
  local VAR_APP_SERVICE VAR_SYSTEM_SERVICE
  VAR_APP_SERVICE="telnet.socket printer sendmail nfs kshell lpd tftp ident time ntalk bootps klogin ypbind daytime nfslock echo discard chargen debug-shell.service"
  VAR_SYSTEM_SERVICE="chargen-dgram daytime-stream echo-streamklogin tcpmux-server chargen-stream discard-dgram eklogin krb5-telnet tftp cvs discard-stream ekrb5-telnet kshell time-dgram daytime-dgram echo-dgram gssftp rsync time-stream"
  
  # 2.禁用非必须得服务
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, Do you want to disable or turn off the service. (Y/N) : " VERIFY
  if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then
    for i in ${VAR_APP_SERVICE};do
      echo "# Status and Disable APP ${i} Service."
      systemctl status ${i}
      systemctl stop ${i};systemctl disable ${i};
    done
    
    for i in ${VAR_SYSTEM_SERVICE};do
      echo "- Status and Disable System ${i} Service."
      systemctl status ${i}
      systemctl stop ${i};systemctl disable ${i};
    done
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

# 函数名称: svc_debugshell
# 函数用途: 在系统启动时禁用debug-shell服务
# 函数参数: 无
function svc_debugshell(){   
  log::info "[${COUNT}] 禁用debug-shell服务-Disable debug-shell service"

  systemctl stop debug-shell.service
  systemctl disable debug-shell.service
  systemctl mask debug-shell.service >/dev/null 2>&1

  if [[ $VAR_VERIFY_RESULT == "Y" ]]; then
    systemctl status debug-shell.service --no-pager
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: svc_ftppolicy
# 函数用途: 系统ftp服务安全权限策略设置
# 函数参数: 无
function svc_ftppolicy() {
  log::info "[${COUNT}] ftp服务权限策略设置-System FTP Services policy setting."

  # 禁止匿名 WU-FTP 用户登录
  if [[ -f /etc/ftpaccess ]];then
    egrep -q "^\s*class all real.*$" /etc/ftpaccess  && sed -ri "s/^\s*class all real.*$/#class all real,guest,anonymous */" /etc/ftpaccess || echo "# class all real,guest,anonymous *" >> /etc/ftpaccess
    # 禁止 root 登录 WU-FTP
    if [[ $(grep -wc root /etc/ftpusers) -eq 1 ]];then
      log::warn "[-] 请手动禁止 root 登录 WU-FTP."
    fi
  fi

  # 禁止匿名 VSFTP 用户登录
   if [[ -f /etc/vsftpd.conf ]];then
    egrep -q "^\s*anonymous_enable.*$" /etc/vsftpd.conf && sed -ri "s/^\s*anonymous_enable.*$/anonymous_enable=NO/" /etc/vsftpd.conf || echo "anonymous_enable=NO" >> /etc/vsftpd.conf
  # 禁止 root 登录 VSFTP
    if [[ $(grep -wc root /etc/vsftpd/ftpusers) -eq 1 ]] || [[ $(grep -wc root /etc/vsftpd/user_list) -eq 1 ]];then
      log::warn "[-] 请手动禁止 root 登录 VSFTP."
    fi
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))  
}
