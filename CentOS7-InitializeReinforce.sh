#!/bin/bash
# @Author: WeiyiGeek
# @Description: CentOS Liunx 7 Security Reinforce and System initialization
# @Create Time:  2023年3月4日 09:39:06
# @Last Modified time: 
# @E-mail: master@weiyigeek.top
# @Blog: https://www.weiyigeek.top
# @wechat: WeiyiGeeker
# @公众号: 全栈工程师修炼指南
# @Github: https://github.com/WeiyiGeek/SecOpsDev/
# @Version: 1.1
#-----------------------------------------------------------------------#
# System security initiate hardening tool for CentOS7 Server.
# WeiyiGeek <master@weiyigeek.top>
# Blog : https://blog.weiyigeek.top

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

# script execute language family
# export LC_ALL=C.UTF-8

# tool version and 
VAR_VERSION='1.1'

# Error reporting for non-existent variables and pipeline 
# set -u选项的作用是当脚本中使用未定义的变量时导致脚本退出。这可以帮助发现拼写错误或由于变量未正确初始化而引发的问题。默认情况下，Bash会将未定义的变量视为空，不会报错。启用set -u后，任何未定义的变量引用都会导致脚本报错并退出，从而避免潜在的运行时错误‌
# set -o pipefail选项的作用是当管道中的任意命令失败时，整个管道的返回值为失败（非零退出状态）。通常，只有最后一个命令的退出状态会被管道返回，启用pipefail后，即使管道中间的命令失败，脚本也会捕捉到并停止执行。这确保了即使管道中的某个命令失败，整个脚本也不会继续执行，从而避免了潜在的问题‌
set -u -o pipefail

## 名称: err、warn、info 、succ
## 用途：全局Log信息打印函数
## 参数: $@ 输入的参数的具体内容（将输入的参数作为一个多个对象，即是所有参数的一个列表）
## 补充: 文字颜色也可使用 $(tput setaf 1)
log::error() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S')] \033[31mERROR: $@ \033[0m\n" #红色
}
log::warn() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S')] \033[33mWARNING: $@ \033[0m\n" #黄色
} 
log::info() {
  printf "[$(date +'%Y-%m-%dT%H:%M:%S')] \033[34mINFO: $@ \033[0m\n" #蓝色
}
log::succ() { 
  printf "[$(date +'%Y-%m-%dT%H:%M:%S')] \033[32mSUCC: $@ \033[0m\n" #绿色
}

## 名称: Start::PreDetection
## 用途: 安全加固脚本前置运行检测及所需目录创建
## 参数: 无
Start::PreDetection () {
  # Verify that you are an administrator
  # $EUID 表示 "有效" 用户 ID
  if (( $EUID != 0 )); then
    # tput setaf 1:将文本设置为红色   tput sgr0：恢复默认颜色
    printf '%s\n' "$(tput setaf 1)Error: script requires an account with root privileges. Try using 'sudo bash ${0}'.$(tput sgr0)" >&2
    exit 1
  fi

  # Verify if it is an CentOS 7 distribution
  # Eqi：
  grep -Eqi "CentOS" /etc/redhat-release
  if [ $? != 0 ]; then
    printf '%s\n' "$(tput setaf 1)Error: script is only available for CentOS systems.$(tput sgr0)" >&2
    exit 1
  fi
  grep -Eqi 'VERSION_ID="7"' /etc/os-release
  if [ $? != 0 ]; then
    printf '%s\n' "$(tput setaf 1)Error: script is only available for CentOS7 systems.$(tput sgr0)" >&2
    exit 1
  fi

  # Verify bash.
  if [ "$SHELL" != "/bin/bash" ]; then
    printf '%s\n' "$(tput setaf 1)Error: script needs to be run with bash.$(tput sgr0)" >&2
    exit 1
  fi

  # Verify BACKUP DIR.
  # ! -e：如果filename不存在则为真 | mkdir -vp : 递归创建多个目录、打印创建细节 | chattr：用于更改文件或目录的属性
  if [ ! -e $BACKUPDIR ];then mkdir -vp ${BACKUPDIR} > /dev/null 2>&1; chattr +a ${BACKUPDIR};fi

  # Verify HISTORY DIR.
  if [ ! -e $HISTORYDIR ];then mkdir -vp ${HISTORYDIR} > /dev/null 2>&1; chmod -R 1777 ${HISTORYDIR}; chattr -R +a ${HISTORYDIR};fi
} 

## 名称: Start::Banner 
## 用途：程序执行时显示头部Banner信息
## 参数: 无
## 艺术字B格: http://www.network-science.de/ascii/
Start::Banner (){
  tput clear
  printf "\033[32m     __          __  _       _  _____           _       \033[0m\n"   
  printf "\033[32m     \ \        / / (_)     (_)/ ____|         | |      \033[0m\n"
  printf "\033[32m     \ \  /\  / /__ _ _   _ _| |  __  ___  ___| | __    \033[0m\n"
  printf "\033[32m       \ \/  \/ / _ \ | | | | | | |_ |/ _ \/ _ \ |/ /   \033[0m\n"
  printf "\033[32m       \  /\  /  __/ | |_| | | |__| |  __/  __/   <     \033[0m\n"
  printf "\033[32m         \/  \/ \___|_|\__, |_|\_____|\___|\___|_|\_\   \033[0m\n"
  printf "\033[32m                      __/ |                             \033[0m\n"
  printf "\033[32m                      |___/                             \033[0m\n"
  printf "\033[32m====================================================================== \033[0m\n"
  printf "\033[32m@ Desc: CentOS Liunx 7 Security Reinforce and System initialization (PS: 符合等保三级要求)  \033[0m\n"
  printf "\033[32m@ Mail bug reports: master@weiyigeek.top or pull request (pr) \033[0m\n"
  printf "\033[32m@ Author : WeiyiGeek                                          \033[0m\n"
  printf "\033[32m@ Wechat Publc: WeiyiGeeker                           \033[0m\n"
  printf "\033[32m@ Follow me on Wechat : WeiyiGeeker                           \033[0m\n"
  printf "\033[32m@ Follow me on Blog   : https://blog.weiyigeek.top/           \033[0m\n"
  printf "\033[32m@ Communication group : https://weiyigeek.top/visit.html      \033[0m\n"
  printf "\033[32m@ Wechat official account : https://weiyigeek.top/wechat.html?key=欢迎关注 \033[0m\n"
  printf "\033[32m====================================================================== \033[0m\n"
  sleep 1
  COUNT=1
}

## 名称: Start::Help 
## 用途：程序执行帮助命令
## 参数: 无
Start::Help ()
{
  echo -e "\nUsage: $0 [--start ] [--network] [--function] [--clear] [--version] [--help]"
  echo -e "Option: "
  echo -e "  --start            Start System initialization and security reinforcement."
  echo -e "  --network          Configure the system network and DNS resolution server."
  echo -e "  --function         PCall the specified shell function."
  echo -e "  --clear            Clear all system logs, cache and backup files."
  echo -e "  --info             Print System information and exit."
  echo -e "  --version          Print version and exit."
  echo -e "  --help             Print help and exit."
  echo -e "\nMail bug reports or suggestions to <master@weiyigeek.top> or pull request (pr)."
  echo -e "current version : ${VAR_VERSION}"
  log::warn "温馨提示：使用前先请配置机器上网环境及其在config文件夹中的CentOS7.conf配置进行对应配置."
  exit 0
}


## 名称: Start::Script
## 用途：调用脚本中指定的初始化安全加固函数
## 参数: 无
Start::Script () {
  
  # 主机IP地址与网关设置 (建议提前单独配置)
  # net_ip
  # 设置主机DNS解析服务器 (建议提前单独配置)
  # net_dns

  ## [1.os-base.sh]
  # 主机名称设置
  base_hostname
  # 主机终端命令行格式设置
  base_formatPS1
  # 主机登录banner及操作系统资源提示
  base_banner
  # 主机系统镜像软件源
  base_mirror
  # 基础软件安装
  base_software
  # 安装配置java环境(需自行下载 jdk 压缩包)
  # install_java /root/Downloads/jdk-8u211-linux-x64.tar.gz
  # 在主机上安装最新版本的 Docker 环境（可选）
  # install_docker
  # 在主机上安装 Dockercompose 环境（需自行指定版本）
  # install_dockercompose "v2.16.0"

  # 安装配置时间同步工具
  base_software_chrony
  # 配置主机系统时区
  base_timezone
  # 升级系统内核版本(按需使用)
  base_update_kernel

  ## 6.os-service.sh
  # 禁用多余服务（若为生产环境，请按需使用）
  # svc_disableservicepolicy
  # 禁用debug-shell服务
  svc_debugshell
  # ftp 服安全策略
  svc_ftppolicy

  ## 2.os-security.sh
  # 主机selinux安全策略
  sec_selinuxpolicy
  # sshd 服务安全策略
  sec_sshdpolicy
  # 锁定多余系统账户
  sec_lockuserpolicy
  # 主机系统用户登录策略
  sec_loginpolicy
  # 主机系统用户密码策略
  sec_userpasswordpolicy
  # 主机系统初始化用户密码、过期时间
  sec_userpasswdpolicy
  # 主机系统sudo安全策略
  sec_sudopolicy
  # 主机系统敏感文件权限策略
  sec_privilegepolicy
  # 主机系统别名策略
  sec_aliasespolicy
  # grub 引导加固，防止进入单用户模式进行更改系统密码(请根据需求选择，若需开启请去掉下行 # ）
  sec_grubpolicy

  ## 3.os-optimize.sh
  # 主机系统内核优化
  optimize_kernel
  # 主机系统资源限制优化
  optimize_resources_limits
  # 创建系统swap分区（请根据业务需求开启）
  # optimize_swap_partition

  ## 5.os-logs.sh
  # 历史命令日志策略
  logs_historypolicy
  # 安全事件记录日志策略
  logs_rsyslogpolicy
  # 安全事件审计日志策略
  logs_auditdpolicy

  ## 4.os-opssec.sh
  # 运维操作安全相关配置
  # 禁用控制台 ctrl+alt+del 组合键对系统重启 (必须要配置我曾入过坑)
  opssec_ctrlaltdel
  # 设置文件删除回收站别名(防止误删文件)(必须要配置,我曾入过坑)
  opssec_recyclebin

  ## 2.os-security.sh
  # 主机系统防火墙配置
  sec_firewallpolicy

  ## n.os-clean.sh
  # 清理主机系统基线
  clean_garbage

  # 重启加固主机
  base_reboot
}

## 名称: main 
## 用途：程序入口函数
## 参数: 无
main () {
  # Load Configure File Environment Variable
  source config/CentOS7.conf

  # Initialization Start
  Start::Banner

  # Initialization Check.
  Start::PreDetection

  # Create Log File.
  # 调整文件的大小，可以将日志文件的大小调整为零，从而清空文件内容
  truncate -s0 "${LOGFILE}"

  # Load Scripts Function.
  for SCRIPTS in scripts/*.sh; do
    [[ -f ${SCRIPTS} ]] || break
    source "${SCRIPTS}"
  done

  if [ $# -eq 0 ];then
    Start::Help
  fi

while :; do
    # [ -z "$1" ] && exit 0;
    [ -z "$1" ] && exit 0;
    case $1 in
        --start)
          Start::Script
          exit 0
        ;;
        --network)
          base_hostname
          net_ip
          net_dns
          exit 0
        ;;
        --info)
          info_system
          exit 0
        ;;
        --function)
          echo -e "Call function : $2"
          $2
          exit 0
        ;;
        --clear)
          system_clean
          exit 0
        ;;
        --version)
          echo -e "$0 version : ${VAR_VERSION}"
          exit 0
        ;;
        --help)
          Start::Help
          exit 0
        ;;
        *)
          echo -e "Invalid Option: $1"
          echo -e "Usage: $0 [--version] [--help]"
          echo -e "\nUse \"$0 --help\" for complete list of options"
          echo -e "Blog : https://blog.weiyigeek.top"
          echo -e "Wechat : WeiyiGeeker"
          exit 1
        ;;
    esac
done
}

main $@

