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

# 函数名称: sec_selinuxpolicy
# 函数用途: 操作系统selinux安全策略设置（按需使用）
# 函数参数: 无
function sec_selinuxpolicy () {
  log::info "[${COUNT}] 配置Selinux安全策略-Operating System Selinux Security Policy Settings."
  cp -a /etc/selinux/config ${BACKUPDIR}

  if [ "$(getenforce)" == "Enforcing" ];then
    echo -e "\033[34m SELinux security policy is enforced. \033[0m"
  else
    echo -e "\033[34m SELinux security policy is not enforced. \033[0m"
    read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, Do you want to force SELinux security policy settings (是否强制设置SELinux安全策略，有需要时开启否则影响业务). (Y/N) : " VERIFY
    if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then
      # 临时生效
      setenforce Enforcing
      # 永久生效
      sed -i -e "s/^SELINUX=\S.*/SELINUX=enforcing/g" /etc/selinux/config
    fi
  fi

  # 输出安全策略配置文件内容
  log::info "View SELinux security policy file /etc/selinux/config."
  egrep "^SELINUX|^SELINUXTYPE" /etc/selinux/config
  # 或者使用 setstatus 命令

  # 更改SELinux系统上的端口，则必须将此更改告知SELinux，例如 sshd 服务端口
  sudo yum install policycoreutils-python
  semanage port -a -t ssh_port_t -p tcp ${VAR_SSHD_PORT}
  semanage port -l | grep "ssh"

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: sec_sshdpolicy
# 函数用途: 操作系统sshd服务安全权限策略设置
# 函数参数: 无
function sec_sshdpolicy () {
  log::info "[${COUNT}] SSHD服务安全配置-System sshd service security policy setting."
  cp -a /etc/ssh/sshd_config ${BACKUPDIR}

  # 0.设置SSH登录前Banner警告提示
  egrep -q "^\s*(banner|Banner)\s+\W+.*$" /etc/ssh/sshd_config && sed -ri "s/^\s*(banner|Banner)\s+\W+.*$/Banner \/etc\/issue.net/" /etc/ssh/sshd_config || \
  echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

  # 1.设置SSH禁止root远程登录（推荐配置-但还是要根据需求配置）
  egrep -q "^\s*PermitRootLogin\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*PermitRootLogin\s+.+$/PermitRootLogin no/" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config

  # 2.设置SSH严格模式
  sudo egrep -q "^(#)?\s*StrictModes\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*StrictModes\s+.+$/StrictModes yes/" /etc/ssh/sshd_config || echo "StrictModes yes" >> /etc/ssh/sshd_config

  # 3.更改SSH服务端口
  sudo egrep -q "^(#)?\s*Port\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*Port\s+.+$/Port ${VAR_SSHD_PORT}/" /etc/ssh/sshd_config || echo "Port ${VAR_SSHD_PORT}" >> /etc/ssh/sshd_config

  # 4.关闭禁用用户的 .rhosts 文件 ~/.ssh/.rhosts 来做为认证，缺省 IgnoreRhosts yes.
  egrep -q "^(#)?\s*IgnoreRhosts\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*IgnoreRhosts\s+.+$/IgnoreRhosts yes/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
  egrep -q "^(#)?\s*HostbasedAuthentication \s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*HostbasedAuthentication \s+.+$/HostbasedAuthentication  no/" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config

  # 5.设置安全协议版本
  egrep -q "^(#)?\s*Protocol\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*Protocol\s+.+$/Protocol 2/" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config

  # 6.设置日志等级 默认是VERBOSE,设置为INFO
  egrep -q "^(#)?\s*LogLevel\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*LogLevel\s+.+$/LogLevel INFO/" /etc/ssh/sshd_config || echo "LogLevel INFO" >> /etc/ssh/sshd_config

  # 7.禁用空密码用户登录
  egrep -q "^(#)?\s*PermitEmptyPasswords\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*PermitEmptyPasswords\s+.+$/PermitEmptyPasswords no/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

  # 8.配置失败尝试次数（此处，设置为5次）
  egrep -q "^(#)?\s*MaxAuthTries\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*MaxAuthTries\s+.+$/MaxAuthTries 5/" /etc/ssh/sshd_config || echo "MaxAuthTries 5" >> /etc/ssh/sshd_config

  # 9.配置连接空闲超时 (每120s进行心跳连接测试，若三次失败则断开链接)
  egrep -q "^(#)?\s*ClientAliveInterval\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*ClientAliveInterval\s+.+$/ClientAliveInterval ${VAR_LOGIN_TIMEOUT}/" /etc/ssh/sshd_config || echo "ClientAliveInterval ${VAR_LOGIN_TIMEOUT}" >> /etc/ssh/sshd_config
  egrep -q "^(#)?\s*ClientAliveCountMax\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*ClientAliveCountMax\s+.+$/ClientAliveCountMax 3/" /etc/ssh/sshd_config || echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config

  # 10.不允许用户向ssh守护程序呈现环境
  egrep -q "^(#)?\s*PermitUserEnvironment\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*PermitUserEnvironment\s+.+$/PermitUserEnvironment no/" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config

  # 11.设置SSH强加密算法
  egrep "^\s*Ciphers\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^\s*Ciphers\s+.+$/Ciphers aes256-ctr,aes128-ctr,aes192-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com/" /etc/ssh/sshd_config || echo "Ciphers aes256-ctr,aes128-ctr,aes192-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com" >> /etc/ssh/sshd_config

  # 12.设置成功验证SSH服务器的时间为一分钟或更短
  egrep -q "^(#)?\s*LoginGraceTime\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*LoginGraceTime\s+.+$/LoginGraceTime 60/" /etc/ssh/sshd_config || echo "LoginGraceTime 60" >> /etc/ssh/sshd_config

  # 13.禁用X11转发及端口转发
  egrep -q "^(#)?\s*X11Forwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*X11Forwarding\s+.+$/X11Forwarding no/" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config
  egrep -q "^(#)?\s*X11UseLocalhost\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*X11UseLocalhost\s+.+$/X11UseLocalhost yes/" /etc/ssh/sshd_config || echo "X11UseLocalhost yes" >> /etc/ssh/sshd_config
  egrep -q "^(#)?\s*AllowTcpForwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*AllowTcpForwarding\s+.+$/AllowTcpForwarding no/" /etc/ssh/sshd_config || echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
  egrep -q "^(#)?\s*AllowAgentForwarding\s+.+$" /etc/ssh/sshd_config && sed -ri "s/^(#)?\s*AllowAgentForwarding\s+.+$/AllowAgentForwarding no/" /etc/ssh/sshd_config || echo "AllowAgentForwarding no" >> /etc/ssh/sshd_config

  # 14.设置SSH服务配置文件权限
  chown root:root /etc/ssh/sshd_config 
  chmod og-rwx /etc/ssh/sshd_config
  chown -R root:ssh_keys /etc/ssh/*key 
  chmod -R 400 /etc/ssh/*key 
  chown -R root:root /etc/ssh/*key.pub
  chmod -R 444 /etc/ssh/*key.pub

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: sec_lockuserpolicy
# 函数用途: 用于锁定或者删除多余的系统账户
# 函数参数: 无
function sec_lockuserpolicy () {
  log::info "[${COUNT}] 核验多余账户并删除-Lock or delete redundant system accounts."
  cp -a /etc/shadow ${BACKUPDIR}

  # 1.检查不在缺省账户列表中得用户
  local defaultuser
  # awk -F ':' '{ printf $1" "}' /etc/passwd
  defaultuser=(root bin daemon adm lp sync shutdown halt mail operator games ftp nobody dbus systemd-coredump systemd-resolve tss unbound polkitd sssd pesign chrony sshd admin rpc rpcuser systemd-network)
  for i in $(cat /etc/passwd | cut -d ":" -f 1,7);do # root:/bin/bash
    flag=0; name=${i%%:*};  terminal=${i##*:} 
    # 删掉第一个:及其右边的字符串
    # 删掉最后一个:及其左边的字符串
    if [[ "${terminal}" == "/bin/bash" || "${terminal}" == "/bin/sh" ]];then
      echo "${name} 用户，shell终端为 /bin/bash 或者 /bin/sh"
    fi
    for j in ${defaultuser[@]};do
      if [[ "${name}" == "${j}" ]];then
        flag=1
        break;
      fi
    done
    if [[ $flag -eq 0 ]];then
      echo "${name} 为非默认用户, 请排查是否为内部人员创建服务所需."
    fi
  done

  # 2.加固 uid 为 0 除 root 之外的帐户
  for i in $(cat /etc/passwd | cut -d ":" -f 1,3);do
    name=${i%%:*}; uid=${i##*:}
    if [[ ${uid} -eq 0 ]] && [[ "${name}" != "root" ]];then
      echo "${name} 用户 uid 为 0,请排查是否为内部人员创建服务所需."
    fi
  done

  # 3.请输入是否删除无用服务账号以及锁定服务账号登陆,缺省为N
  echo .
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, Lock useless account. (Y/N) : " VERIFY
  if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then
    echo "[-] 正在锁定系统多余的服务账户......"
    defaultuser=(adm avahi apache bin dbus daemon distcache dbus ftp gdm games gopher haldaemon lxd listen pcap nfs ntp nscd named nobody nobody4 noaccess polkitd mail mailnull sys sync sshd squid smmsplp sabayon uucp nuucp operator webservd webalizer rpm rpc rpcuser vcsa xfs)
    for j in ${defaultuser[@]};do
      echo "正在锁定账户 ${j} ......"
      usermod -L ${j}&>/dev/null 2&>/dev/null;
    done
  fi

  log::info "若要删除用户请手动确认后执行，userdel -r [用户名] && groupdel [用户名] ."

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

# 函数名称: sec_userpasswdpolicy
# 函数用途: 针对拥有ssh远程登陆权限的用户进行密码口令及失效设置(三权分离)。
# 函数参数: 无
function sec_userpasswdpolicy () {
  log::info "[${COUNT}] 配置用户口令及失效时间-System account password setting."
  cp -a /etc/passwd /etc/group /etc/shadow ${BACKUPDIR}

  # 1.root超级管理员密码更改及失效策略设置
  echo .
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, restart setting super account [${VAR_SUPER_USER}] password. (Y/N) : " VERIFY
  echo .
  if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then
    echo "正在重置 ${VAR_SUPER_USER} 用户密码及密码使用周期策略."
    echo  "${VAR_SUPER_USER}:${VAR_SUPER_PASS}" | chpasswd
    chage -d 0 -m 0 -M 90 -W 15 ${VAR_SUPER_USER} 
  fi
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, setting super account [${VAR_SUPER_USER}] password expire time. (Y/N) : " VERIFY
  echo .
  if [[ ${VERIFY:="N"} == "Y" || ${VERIFY:="N"} == "y" ]]; then 
      echo "正在重置 ${VAR_SUPER_USER} 用户密码过期时间."
      passwd --expire ${VAR_SUPER_USER}; 
  fi

  # 2.系统管理员密码更改及失效策略设置
  echo .
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, restart setting normal account [${VAR_USER_NAME}] password. (Y/N) : " VERIFY
  echo .
  if [ $( grep -c "^${VAR_USER_NAME}:" /etc/passwd) -eq 0 ];then 
    echo "正在创建 ${VAR_USER_NAME} 用户."
    groupadd ${VAR_USER_NAME} && useradd -m -s /bin/bash -c "Custom System Operation users" -g ${VAR_USER_NAME} ${VAR_USER_NAME}
  else
    log::warn "Don't create ${VAR_USER_NAME} account, This is account already exist."
  fi
  if [[ ${VERIFY:="Y"} == "Y" || ${VERIFY:="Y"} == "y" ]]; then
    echo "正在重置 ${VAR_USER_NAME} 用户密码及密码使用周期策略."
    echo  "${VAR_USER_NAME}:${VAR_USER_PASS}" | chpasswd
    chage -d 0 -m 0 -M 90 -W 15 ${VAR_USER_NAME} 
  fi
  echo .
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, setting normal account [${VAR_USER_NAME}] password expire time. (Y/N) : " VERIFY
  echo .
  if [[ ${VERIFY:="Y"} == "Y" || ${VERIFY:="Y"} == "y" ]]; then echo "正在重置 ${VAR_USER_NAME} 用户密码过期时间.";passwd --expire ${VAR_USER_NAME}; fi

  # 3.业务系统用户密码更改及失效策略设置
  echo .
  read -t ${VAR_VERIFY_TIMEOUT} -p "Please input, create ${VAR_APP_USER} account. (Y/N) : " VERIFY
  echo .
  grep -q "^${VAR_APP_USER}:" /etc/passwd
  if [ $? == 1 ];then 
    echo "正在创建 ${VAR_APP_USER} 用户密码及密码使用周期策略."
    groupadd ${VAR_APP_USER} && useradd -m -s /bin/bash -c "Application low privilege users" -g ${VAR_APP_USER} ${VAR_APP_USER}
  else
    echo "创建 ${VAR_APP_USER} 用户失败, 因为此账户已经存在。"
  fi
  if [[ ${VERIFY:="Y"} == "Y" || ${VERIFY:="Y"} == "y" ]]; then
    echo "正在设置 ${VAR_APP_USER} 用户密码."
    echo "${VAR_APP_USER}:${VAR_APP_PASS}" | chpasswd
    echo "正在重置 ${VAR_APP_USER} 密码使用周期策略及密码过期时间." ;
    chage -d 0 -m 0 -M 90 -W 15 ${VAR_APP_USER} && passwd --expire ${VAR_APP_USER}
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: sec_userpasswordpolicy
# 函数用途: 用户密码复杂性策略设置 (密码过期周期0~90、到期前15天提示、密码长度至少12、复杂度设置至少有一个大小写、数字、特殊字符、密码三次不能一样、尝试次数为三次）
# 函数参数: 无
function sec_userpasswordpolicy () {
  log::info "[${COUNT}] 配置用户密码复杂性策略-System account password policy setting."
  cp -a /etc/login.defs ${BACKUPDIR}/login.defs.1
  cp -a /etc/pam.d/system-auth ${BACKUPDIR}
  cp -a /etc/security/pwquality.conf ${BACKUPDIR}
  cp -a /etc/pam.d/password-auth ${BACKUPDIR}
  cp -a /etc/profile ${BACKUPDIR}
  
  ## 配置点.设置用户密码长度、加密方式以及到期时间设置.
  # 配置文件: "/etc/login.defs"，建议通过配置文件设置
  egrep -q "^\s*PASS_MIN_DAYS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S*(\s*#.*)?\s*$/PASS_MIN_DAYS  ${PASS_MIN_DAYS}/" /etc/login.defs || echo "PASS_MIN_DAYS  ${PASS_MIN_DAYS}" >> /etc/login.defs

  egrep -q "^\s*PASS_MAX_DAYS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S*(\s*#.*)?\s*$/PASS_MAX_DAYS  ${PASS_MAX_DAYS}/" /etc/login.defs || echo "PASS_MAX_DAYS  ${{PASS_MAX_DAYS}}" >> /etc/login.defs

  egrep -q "^\s*PASS_WARN_AGE\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S*(\s*#.*)?\s*$/PASS_WARN_AGE  ${PASS_WARN_AGE}/" /etc/login.defs || echo "PASS_WARN_AGE  ${PASS_WARN_AGE}" >> /etc/login.defs

  egrep -q "^\s*PASS_MIN_LEN\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_LEN\s+\S*(\s*#.*)?\s*$/PASS_MIN_LEN ${PASS_MIN_LEN}/" /etc/login.defs || echo "PASS_MIN_LEN  ${PASS_MIN_LEN}" >> /etc/login.defs
  
  egrep -q "^\s*ENCRYPT_METHOD\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)ENCRYPT_METHOD\s+\S*(\s*#.*)?\s*$/ENCRYPT_METHOD ${VAR_PASS_ENCRYPT}/" /etc/login.defs || echo "ENCRYPT_METHOD  ${VAR_PASS_ENCRYPT}" >> /etc/login.defs

  ## 配置点.设置用户新密码复杂度策略
  # retry=${VAR_PASS_RETRY} 
  # difok=${VAR_PASS_DIFOK} 
  # minlen=${PASS_MIN_LEN} 
  # minclass=${VAR_PASS_MINCLASS} 
  # ucredit=${VAR_PASS_UCREDIT} 
  # lcredit=${VAR_PASS_LCREDIT} 
  # dcredit=${VAR_PASS_DCREDIT} 
  # ocredit=${VAR_PASS_OCREDIT}
  egrep -q "^password\s.+pam_pwquality.so\s+\w+.*$" /etc/pam.d/system-auth && sed -ri "/^password\s.+pam_pwquality.so/{s/pam_pwquality.so\s+\w+.*$/pam_pwquality.so try_first_pass local_users_only enforce_for_root minlen=${PASS_MIN_LEN} retry=${VAR_PASS_RETRY} difok=${VAR_PASS_DIFOK} minclass=${VAR_PASS_MINCLASS} ucredit=${VAR_PASS_UCREDIT} lcredit=${VAR_PASS_LCREDIT} dcredit=${VAR_PASS_DCREDIT} ocredit=${VAR_PASS_OCREDIT}/g;}" /etc/pam.d/system-auth || sed -ri "/^password\s.+sufficient\s.+pam_unix.so/i\password    requisite     try_first_pass local_users_only enforce_for_root minlen=${PASS_MIN_LEN} retry=${VAR_PASS_RETRY} difok=${VAR_PASS_DIFOK} minclass=${VAR_PASS_MINCLASS} ucredit=${VAR_PASS_UCREDIT} lcredit=${VAR_PASS_LCREDIT} dcredit=${VAR_PASS_DCREDIT} ocredit=${VAR_PASS_OCREDIT}" /etc/pam.d/system-auth 

  egrep -q "^password\s.+pam_pwquality.so\s+\w+.*$" /etc/pam.d/password-auth && sed -ri "/^password\s.+pam_pwquality.so/{s/pam_pwquality.so\s+\w+.*$/pam_pwquality.so try_first_pass local_users_only enforce_for_root  minlen=${PASS_MIN_LEN} retry=${VAR_PASS_RETRY} difok=${VAR_PASS_DIFOK} minclass=${VAR_PASS_MINCLASS} ucredit=${VAR_PASS_UCREDIT} lcredit=${VAR_PASS_LCREDIT} dcredit=${VAR_PASS_DCREDIT} ocredit=${VAR_PASS_OCREDIT}/g;}" /etc/pam.d/password-auth || sed -ri "/^password\s.+sufficient\s.+pam_unix.so/i\password    requisite     try_first_pass local_users_only enforce_for_root minlen=${PASS_MIN_LEN} retry=${VAR_PASS_RETRY} difok=${VAR_PASS_DIFOK} minclass=${VAR_PASS_MINCLASS} ucredit=${VAR_PASS_UCREDIT} lcredit=${VAR_PASS_LCREDIT} dcredit=${VAR_PASS_DCREDIT} ocredit=${VAR_PASS_OCREDIT}" /etc/pam.d/password-auth

  ## 配置点."/etc/security/pwquality.conf"
  # 设置的新密码的最小长度
  egrep -q "^(#)?\s*minlen\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*minlen\s+.+$/minlen = ${PASS_MIN_LEN}/" /etc/security/pwquality.conf ||  echo "minlen = ${PASS_MIN_LEN}" >> /etc/security/pwquality.conf

  # 表示在密码不符合要求时有3次重试机会
  egrep -q "^(#)?\s*retry\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*retry\s+.+$/retry = ${VAR_PASS_RETRY}/" /etc/security/pwquality.conf ||  echo "retry = ${VAR_PASS_RETRY}" >> /etc/security/pwquality.conf

  # 设置的新密码中允许的最大连续相同字符数
  egrep -q "^(#)?\s*difok\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*difok\s+.+$/difok = ${VAR_PASS_DIFOK}/" /etc/security/pwquality.conf ||  echo "difok = ${VAR_PASS_DIFOK}" >> /etc/security/pwquality.conf

  # 设置的新密码的包含几种字符类型（大小写、数字、其他）
  # password (digits, uppercase, lowercase, others)
  egrep -q "^(#)?\s*minclass\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*minclass\s+.+$/minclass = ${VAR_PASS_MINCLASS}/" /etc/security/pwquality.conf || echo "minclass = ${VAR_PASS_MINCLASS}" >> /etc/security/pwquality.conf
  
  # 设置的新密码中包含【大写】最少位数
  egrep -q "^(#)?\s*ucredit\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*ucredit\s+.+$/ucredit = ${VAR_PASS_UCREDIT}/" /etc/security/pwquality.conf || echo "ucredit = ${VAR_PASS_UCREDIT}" >> /etc/security/pwquality.conf

  # 设置的新密码中包含【小写】最少位数
  egrep -q "^(#)?\s*lcredit\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*lcredit\s+.+$/lcredit = ${VAR_PASS_LCREDIT}/" /etc/security/pwquality.conf || echo "lcredit = ${VAR_PASS_LCREDIT}" >> /etc/security/pwquality.conf

  # 设置的新密码中包含【数字】最少位数
  egrep -q "^(#)?\s*dcredit\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*dcredit\s+.+$/dcredit = ${VAR_PASS_DCREDIT}/" /etc/security/pwquality.conf || echo "dcredit = ${VAR_PASS_DCREDIT}" >> /etc/security/pwquality.conf

  # 设置的新密码中包含【其他字符】最少位数
  egrep -q "^(#)?\s*ocredit\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*ocredit\s+.+$/ocredit = ${VAR_PASS_OCREDIT}/" /etc/security/pwquality.conf || echo "ocredit = ${VAR_PASS_OCREDIT}" >> /etc/security/pwquality.conf

  # 设置的新密码中不能包含用户名字符串
  egrep -q "^(#)?\s*usercheck\s+.+$" /etc/security/pwquality.conf && sed -ri "s/^(#)?\s*usercheck\s+.+$/usercheck = ${VAR_PASS_USERCHECK}/" /etc/security/pwquality.conf || echo "usercheck = ${VAR_PASS_USERCHECK}" >> /etc/security/pwquality.conf

  ## 配置点.检查密码重复使用次数限制, 设置记录旧用户密码传输、存储加密方式为Sha512并且不允许密码为空nullok
  # 方式1
  egrep -q "^password\s.+sufficient\s.+pam_unix.so\s+\w+.*$" /etc/pam.d/system-auth && sed -ri "/^password\s.+sufficient\s.+pam_unix.so/{s/pam_unix.so\s+\w+.*$/pam_unix.so try_first_pass use_authtok authtok_type=sha512 nullok sha512 shadow remember=${VAR_PASS_REMEMBER}/g;}" /etc/pam.d/system-auth

  egrep -q "^password\s.+sufficient\s.+pam_unix.so\s+\w+.*$" /etc/pam.d/password-auth && sed -ri "/^password\s.+sufficient\s.+pam_unix.so/{s/pam_unix.so\s+\w+.*$/pam_unix.so try_first_pass use_authtok authtok_type=sha512 nullok sha512 shadow remember=${VAR_PASS_REMEMBER}/g;}" /etc/pam.d/password-auth

  # 方式2
  ## 配置文件: "/etc/security/pwhistory.conf"，建议通过配置文件设置, 上述使用pam_unix模块配置了此处无需重复配置。
  # if [ -f /usr/lib64/security/pam_pwhistory.so ];then
  #   egrep -q "^password\s.+pam_pwhistory.so\s+\w+.*$" /etc/pam.d/system-auth && sed -ir "/^password\s.+pam_pwhistory.so/{s/pam_pwhistory.so\s+\w+.*$/pam_pwhistory.so  enforce_for_root/;}" /etc/pam.d/system-auth || sed -ri "/^password\s.+pam_pwquality.so/a\password  requisite pam_pwhistory.so enforce_for_root" /etc/pam.d/system-auth
  #   egrep -q "^password\s.+pam_pwhistory.so\s+\w+.*$" /etc/pam.d/password-auth && sed -ri "/^password\s.+pam_pwhistory.so/{s/pam_pwhistory.so\s+\w+.*$/    pam_pwhistory.so  enforce_for_root/;}" /etc/pam.d/password-auth || sed -ri "/^password\s.+pam_pwquality.so/a\password    requisite pam_pwhistory.so enforce_for_root" /etc/pam.d/password-auth
  # fi
  # # 记住历史密码的次数
  # egrep -q "^(#)?\s*remember\s+.+$" /etc/security/pwhistory.conf && sed -ri "s/^(#)?\s*remember\s+.+$/remember = ${VAR_PASS_REMEMBER}/" /etc/security/pwhistory.conf || echo "remember = ${VAR_PASS_REMEMBER}" >> /etc/security/pwhistory.conf
  # # 提示输入密码的次数
  # egrep -q "^(#)?\s*remember\s+.+$" /etc/security/pwhistory.conf && sed -ri "s/^(#)?\s*retry\s+.+$/retry = ${VAR_PASS_RETRY}/" /etc/security/pwhistory.conf || echo "retry = ${VAR_PASS_RETRY}" >> /etc/security/pwhistory.conf

  log::info "查验用户密码复杂性策略设置."
  if [[ ${VAR_VERIFY_RESULT} == "Y" ]];then 
    grep "^PASS_" /etc/login.defs
    egrep "pam_pwquality.so | pam_pwhistory.so" /etc/pam.d/system-auth
    egrep "pam_pwquality.so | pam_pwhistory.so" /etc/pam.d/password-auth
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

# 函数名称: sec_loginpolicy
# 函数用途: 用户登陆安全策略设置
# 函数参数: 无
function sec_loginpolicy () {
  log::info "[${COUNT}] 设置用户登陆安全策略-System user login security policy setting."

  # 启用成功登录的日志记录
  egrep -q "^\s*LOG_OK_LOGINS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)LOG_OK_LOGINS\s+\S*(\s*#.*)?\s*$/LOG_OK_LOGINS ${VAR_LOG_OK_LOGINS}/" /etc/login.defs || echo "LOG_OK_LOGINS ${VAR_LOG_OK_LOGINS}" >> /etc/login.defs
  
  # 禁止没有主目录的用户登录
  egrep -q "^\s*DEFAULT_HOME\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)DEFAULT_HOME\s+\S*(\s*#.*)?\s*$/DEFAULT_HOME ${VAR_DEFAULT_HOME}/" /etc/login.defs || echo "DEFAULT_HOME ${VAR_DEFAULT_HOME}" >> /etc/login.defs
  
  # 删除用户时禁止同步删除用户组
  egrep -q "^\s*USERGROUPS_ENAB\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)USERGROUPS_ENAB\s+\S*(\s*#.*)?\s*$/USERGROUPS_ENAB  ${VAR_USERGROUPS_ENAB}/" /etc/login.defs || echo "USERGROUPS_ENAB ${VAR_USERGROUPS_ENAB}" >> /etc/login.defs

  # 设置终端登陆超时时间
  log::info "[-] 设置登录超时时间为${VAR_LOGIN_TIMEOUT}秒 "
  egrep -q "^\s*(export|)\s*TMOUT\S\w+.*$" /etc/profile && sed -ri "s/^\s*(export|)\s*TMOUT.\S\w+.*$/export TMOUT=${VAR_LOGIN_TIMEOUT}\nreadonly TMOUT/" /etc/profile || echo -e "export TMOUT=${VAR_LOGIN_TIMEOUT}\nreadonly TMOUT" >> /etc/profile
  # 额外方式:
  # egrep -q "^\s*.*ClientAliveInterval\s\w+.*$" /etc/ssh/sshd_config && sed -ri "s/^\s*.*ClientAliveInterval\s\w+.*$/ClientAliveInterval ${VAR_LOGIN_TIMEOUT}/" /etc/ssh/sshd_config || echo "ClientAliveInterval ${VAR_LOGIN_TIMEOUT}" >> /etc/ssh/sshd_config

  # 注意：CentOS7 使用的是 pam_tally2.so 模块了而非 pam_faillock.so 
  log::info "[-] 用户远程连续登录失败6次锁定帐号5分钟包括root账号"

  # requisite: 与 required 的验证方式大体相似，但是只要某个规则项验证失败则立即结束整个验证过程，并返回一个错误信息。使用此关键字可以防止一些通过暴力猜解密码的攻击，但是由于它会返回信息给用户，因此它也有可能将系统的用户结构信息透露给攻击者。
  # 远程登陆
  sed -ri "/^\s*auth\s+required\s+pam_tally2.so\s+.+(\s*#.*)?\s*$/d" /etc/pam.d/sshd 
  sed -ri "2a auth   required   pam_tally2.so deny=${VAR_LOGIN_FAIL_COUNT} unlock_time=${VAR_LOGIN_LOCK_TIME} even_deny_root root_unlock_time=${VAR_LOGIN_LOCK_TIME}" /etc/pam.d/sshd 
  sed -ri '3a account    required     pam_tally2.so' /etc/pam.d/sshd 

  # 宿主机控制台登陆(可选)
  # sed -ri "/^\s*auth\s+required\s+pam_tally2.so\s+.+(\s*#.*)?\s*$/d" /etc/pam.d/login
  # sed -ri '2a auth required pam_tally2.so deny=10 unlock_time=300 even_deny_root root_unlock_time=300' /etc/pam.d/login

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

# 函数名称: sec_grubpolicy
# 函数用途: 系统 GRUB 安全设置防止物理接触从grub菜单中修改密码（按需设置）
# 函数参数: 无
function sec_grubpolicy() {
  log::info "[${COUNT}] 设置访问 grub 引导菜单密码 System GRUB security policy setting."
  log::info "防止物理接触从grub菜单中修改密码, 缺省账户密码为 grub/WeiyiGeek"

  # 1.GRUB 关键文件备份
  cp -a /etc/grub.d/00_header ${BACKUPDIR}
  cp -a /etc/grub.d/10_linux ${BACKUPDIR}

  # 2.设置GRUB菜单界面显示时间
  # sed -i -e 's|GRUB_TIMEOUT_STYLE=hidden|#GRUB_TIMEOUT_STYLE=hidden|g' -e 's|GRUB_TIMEOUT=0|GRUB_TIMEOUT=3|g' /etc/default/grub
  sed -i -e 's|set timeout_style=${style}|#set timeout_style=${style}|g' -e 's|set timeout=${timeout}|set timeout=3|g' /etc/grub.d/00_header
  # 自行创建认证密码 (此处密码: WeiyiGeek)
  # sudo grub-mkpasswd-pbkdf2
  # Enter password:
  # Reenter password:
  # PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.21AC9CEF61B96972BF6F918D2037EFBEB8280001045ED32DFDDCC260591CC6BC8957CF25A6755904A7053E97940A9E4CD5C1EF833C1651C1BCF09D899BED4C7C.9691521F5BB34CD8AEFCED85F4B830A86EC93B61A31885BCBE3FEE927D54EFDEE69FA8B51DBC00FCBDB618D4082BC22B2B6BA4161C7E6B990C4E5CFC9E9748D7
  # 设置认证用户以及password_pbkdf2认证
tee -a /etc/grub.d/00_header <<'END'
cat <<'EOF'
# GRUB Authentication
set superusers="grub"
password_pbkdf2 grub grub.pbkdf2.sha512.10000.21AC9CEF61B96972BF6F918D2037EFBEB8280001045ED32DFDDCC260591CC6BC8957CF25A6755904A7053E97940A9E4CD5C1EF833C1651C1BCF09D899BED4C7C.9691521F5BB34CD8AEFCED85F4B830A86EC93B61A31885BCBE3FEE927D54EFDEE69FA8B51DBC00FCBDB618D4082BC22B2B6BA4161C7E6B990C4E5CFC9E9748D7
EOF
END

  # 3.设置进入正式系统不需要认证如进入单用户模式进行重置账号密码时需要进行认证。 （高敏感数据库系统不建议下述操作）
  # 在 135 加入 -unrestricted ，例如, 此处与Ubuntu不同的是不加--user=grub
  # 133 echo "menuentry $(echo "$title" | grub_quote)' ${CLASS} \$menuentry_id_option 'gnulinux-$version-$type-    $boot_device_id' {" | sed "s/^/$submenu_indentation/"
  # 134   else
  # 135 echo "menuentry --unrestricted '$(echo "$os" | grub_quote)' ${CLASS} \$menuentry_id_option 'gnulinux-simple-$boot_devic    e_id' {" | sed "s/^/$submenu_indentation/"
  sed -i '/echo "$title" | grub_quote/ { s/menuentry /menuentry /;}' /etc/grub.d/10_linux
  sed -i '/echo "$os" | grub_quote/ { s/menuentry /menuentry --unrestricted /;}' /etc/grub.d/10_linux

  # 4.更新GRUB从而生成boot启动文件。
  grub2-mkconfig -o /boot/grub2/grub.cfg

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: sec_sudopolicy
# 函数用途: 用户su与sudo权限配置及其日志记录配置(可选)
# 函数参数: 无
function sec_sudopolicy() {
  log::info "[${COUNT}] 配置用户使用sudo权限-Rename su command to SU command."
  cp -a /etc/sudoers ${BACKUPDIR}

  # /etc/login.defs 帮助文档: https://man7.org/linux/man-pages/man5/login.defs.5.html
  if [ ! -f  ${SU_LOG_FILE} ];then touch ${SU_LOG_FILE};fi
  egrep -q "^(\s*)SULOG_FILE\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)SULOG_FILE\s+\S*(\s*#.*)?\s*$/\SULOG_FILE ${SU_LOG_FILE}/" /etc/login.defs || echo "SULOG_FILE  ${SU_LOG_FILE}" >> /etc/login.defs

  # 将 su 移动更名为 SU 或者其他（可选）
  # mv /usr/bin/su /usr/bin/SU
  # 例如，如果将其定义为“SU”，则“ps”将显示命令为“-SU”而非sh
  # egrep -q "^\s*SU_NAME\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)SU_NAME\s+\S*(\s*#.*)?\s*$/\SU_NAME  ${VAR_SU_NAME}/" /etc/login.defs || echo "SU_NAME ${VAR_SU_NAME}" >> /etc/login.defs
 
  log::info "配置指定wheel用户组（成员）使用su命令切换用户 "
  gpasswd -a ${VAR_USER_NAME} wheel
  egrep -q "^(\s*)SU_WHEEL_ONLY\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)SU_WHEEL_ONLY\s+\S*(\s*#.*)?\s*$/\SULOG_FILE ${VAR_SU_WHEEL_ONLY}/" /etc/login.defs || echo "SU_WHEEL_ONLY  ${VAR_SU_WHEEL_ONLY}" >> /etc/login.defs
  egrep -q "^(#)?auth\s.*required\s.*pam_wheel.so.*use_uid.*$" /etc/pam.d/su && sed -ri "/^(#)?auth\s.*required\s.*pam_wheel.so use_uid.*$/{s/^(#)?auth\s.*required\s.*pam_wheel.so use_uid.*$/auth required pam_wheel.so use_uid/;}" /etc/pam.d/su
  
  # log::info "配置指定组禁止使用su命令切换root，例如此处阻止app用户 "
  # egrep -q "^(#)?auth\s.*required\s.*pam_wheel.so.*use_uid.*$" /etc/pam.d/su && sed -ri "/^(#)?auth\s.*required\s.*pam_wheel.so use_uid.*$/{s/^(#)?auth\s.*required\s.*pam_wheel.so use_uid.*$/auth required pam_wheel.so use_uid deny group=${VAR_APP_USER}/;}" /etc/pam.d/su

  log::info "配置不允许指定用户使用 sudo 修改 root 密码及切换到root"
  # 安装时您创建的用户, 防止直接通过 sudo passwd 修改root密码 以及 sudo -i 、sudo -s、sudo su - root 登陆到 shell 终端
  # visudo -f /etc/sudoers.d/user
tee /etc/sudoers.d/user <<EOF
${VAR_USER_NAME}  ALL=(root) PASSWD:!/bin/su,!/bin/bash,!/usr/sbin/visudo,!/usr/bin/passwd,!/usr/bin/passwd [A-Za-z]*,!/usr/bin/chattr,!/usr/bin/vi /etc/sudoers*,!/usr/bin/vim /etc/sudoers*,!/usr/bin/nano /etc/sudoers*,!/usr/bin/sudo -i
${VAR_APP_USER}  ALL=(root)  PASSWD:!/usr/sbin/*
EOF
  chmod 0440 /etc/sudoers.d/user

  # 配置记录用户使用 sudo 权限日志
  log::info "配置记录用户使用 sudo 权限日志"
  egrep -q "^(#)?Defaults\s+*logfile.*$" /etc/sudoers && sed -ri "s|^(#)?Defaults\s+*logfile.*$|\Defaults logfile=${SUDO_LOG_FILE}|" /etc/sudoers || echo "Defaults logfile=${SUDO_LOG_FILE}" >>  /etc/sudoers
  egrep -q "^(#)?local2.debug.*sudo.*$" /etc/rsyslog.conf  && sed -r "s|^(#)?local2.debug.*sudo.*$|local2.debug -${SUDO_LOG_FILE}|" /etc/rsyslog.conf  || echo "local2.debug -${SUDO_LOG_FILE}" >>  /etc/rsyslog.conf 

  # 验证 sudo 文件配置
  visudo -c && systemctl restart rsyslog 

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

# 函数名称: sec_privilegepolicy
# 函数用途: 系统用户权限与文件目录创建权限策略设置
# 函数参数: 无
function sec_privilegepolicy() {
  log::info "[${COUNT}]设置文件目录创建权限策略-System account password security policy setting."

  log::info "配置用户 umask 为 022."
  egrep -q "^\s*umask\s+\w+.*$" /etc/profile && sed -ri "s/^\s*umask\s+\w+.*$/umask ${VAR_UMASK}/" /etc/profile || echo "umask ${VAR_UMASK}" >> /etc/profile
  egrep -q "^\s*(umask|UMASK)\s+\w+.*$" /etc/login.defs && sed -ri "s/^\s*(umask|UMASK)\s+\w+.*$/UMASK ${VAR_UMASK}/" /etc/login.defs || echo "UMASK ${VAR_UMASK:=0022}" >> /etc/login.defs

  log::info "设置/恢复重要目录和文件的权限."
  touch /etc/security/opasswd && chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd 
  find /home -name authorized_keys -exec chmod 600 {} \;
  chmod 600 ~/.ssh/authorized_keys
  chmod 0600 /etc/ssh/sshd_config
  chmod 644 /etc/group /etc/services
  chmod 700 /etc/inetd.conf&>/dev/null 2&>/dev/null; 
  chmod 755 /etc /etc/passwd /etc/shadow /etc/security /etc/rc*.d

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: sec_aliasespolicy
# 函数用途: 禁用系统不必要的别名
# 函数参数: 无
function sec_aliasespolicy() {
  log::info "[${COUNT}] 禁用系统不必要的别名策略设置-Disable System aliases security policy setting."

  log::info "[-] 禁用系统不必要的别名策略设置."
  if [ -f /etc/aliases ]; then
    cp -a /etc/aliases  ${BACKUPDIR}
    sed -ri -e "s/^games/#games/" /etc/aliases
    sed -ri -e "s/^ingres/#ingres/" /etc/aliases
    sed -ri -e "s/^system/#system/" /etc/aliases
    sed -ri -e "s/^toor/#toor/" /etc/aliases
    sed -ri -e "s/^uucp/#uucp/" /etc/aliases
    sed -ri -e "s/^manager/#manager/" /etc/aliases
    sed -ri -e "s/^dumper/#dumper/" /etc/aliases
    sed -ri -e "s/^operator/#operator/" /etc/aliases
    sed -ri -e "s/^decode/#decode/" /etc/aliases
    sed -ri -e "s/^operator/#operator/" /etc/aliases
    sed -ri -e "s/^root/#operator/" /etc/aliases
  fi

  log::info "[-] 禁用邮件服务系统不必要的别名策略设置."
  if [ -f /etc/mail/aliases ]; then
    cp -a /etc/mail/aliases  ${BACKUPDIR}
    sed -ri -e "s/^games/#games/" -e "s/^ingres/#ingres/" -e "s/^system/#system/" -e "s/^toor/#toor/" -e "s/^uucp/#uucp/"  -e "s/^manager/#manager/" -e "s/^dumper/#dumper/"  -e "s/^operator/#operator/"  -e "s/^decode/#decode/"  -e "s/^operator/#operator/" -e "s/^root/#operator/" /etc/mail/aliases
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


# 函数名称: sec_firewallpolicy
# 函数用途: 系统防火墙策略设置, 建议操作完成后重启计算机.
# 函数参数: 无
function sec_firewallpolicy() {
  log::info "[${COUNT}] 启用主机系统防火墙-System Firewall security policy setting."
    firewall-cmd --state | grep -q "running"
  if [ $? != 0 ];then 
    systemctl start firewalld.service
    systemctl enable firewalld.service
    systemctl mask firewalld.servicee >/dev/null 2>&1
    firewall-cmd --state   
  fi

  log::info "设置主机防火墙通行策略"
  for port in ${VAR_ALLOW_PORT[@]};do 
    echo "firewall-cmd --add-port=${port} --permanent"
    firewall-cmd --add-port=${port} --permanent 
  done

  log::info "主机防火墙服务及策略显示"
  systemctl status firewalld.service --no-pager

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}