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

# 函数名称: clean_garbage
# 函数用途: 删除安全加固过程临时文件清理为基线镜像做准备
# 函数参数: 无
function clean_garbage () {
  log::info "[${COUNT}] 清理脚本执行过程中得临时文件-Solve the problem that regular user scheduled tasks cannot be executed regularly."

  # 历史命令记录目录停止不能删除的
  chattr -R -a /var/log/.history

  log::info "[-] 删除潜在威胁文件 "
  find / -maxdepth 3 -name hosts.equiv | xargs rm -rf
  find / -maxdepth 3 -name equiv | xargs rm -rf
  find / -maxdepth 3 -name .netrc | xargs rm -rf
  find / -maxdepth 3 -name .rhosts | xargs rm -rf
  find / -maxdepth 3 -name rhosts | xargs rm -rf

  log::info "[-] 清理安装软件缓存"
  dnf autoremove -y
  yum clean all

  log::info "[-] 清理备份与缓存文件目录"
  # /var/cache/fontconfig/
  find /var/cache/fontconfig -type f -delete
  # /var/backups/
  find /var/backups -type f -delete

  log::info "[-] 清理应用日志缓存文件即临时目录"
  # /var/log/
  find /var/log/ -name "*.log-*" -type f -delete
  find /var/log/ -name "*.log.*" -type f -delete
  find /var/log/ -name "*-*" -type f -delete
  find /var/log -name "vmware-*.*.log" -name "*.log-*" -name "*.gz" -name "*log.*" -delete
  find /var/log -type f -name "*log" -exec truncate -s 0 {} \;
  find /var/log/.history -type f -exec truncate -s 0 {} \;

  log::info "[-] 清理系统回收站"
  # ~/.trash/
  find ~/.trash/* -delete
  find /home/ -type d -name .trash -exec find {} -delete \;
  find /var/log ! -t file | grep -v ".history"

  log::info "[-] 清理命令行历史命令"
  history -c

  # 启用历史命令记录目录停止不能删除
  chattr -R +a /var/log/.history
  
  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}

  