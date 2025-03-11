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


# 函数名称: opssec_ctrlaltdel
# 函数用途: 禁用控制台 ctrl+alt+del 组合键对系统重启 (必须要配置我曾入过坑)
# 函数参数: 无
function opssec_ctrlaltdel() {
  log::info "[${COUNT}] 禁用Ctrl+Alt+Del快捷键重启-Disable ctrl+alt+del key restart computer."

  if [ -f /usr/lib/systemd/system/ctrl-alt-del.target ];then
    systemctl stop ctrl-alt-del.target
    systemctl mask ctrl-alt-del.target >/dev/null 2>&1
    sed -i 's/^#CtrlAltDelBurstAction=.*/CtrlAltDelBurstAction=none/' /etc/systemd/system.conf
    mv /usr/lib/systemd/system/ctrl-alt-del.target ${BACKUPDIR}/ctrl-alt-del.target.bak
  fi

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
} 

    
# 函数名称: opssec_recyclebin
# 函数用途: 设置文件删除回收站别名(防止误删文件)(必须要配置,我曾入过坑)
# 函数参数: 无
function opssec_recyclebin() {
  log::info "[${COUNT}] 设置文件删除回收站防止误删文件-Enable file or dirctory delete recycle bin."

  # 1.防止rm -rf误操作为其设置别名
tee -a /etc/bashrc <<'EOF'
alias rm="sh /usr/local/bin/remove.sh"
EOF

tee /etc/profile.d/alias.sh <<'EOF'
# User specific aliases and functions
# 删除回收站
# find ~/.trash -delete
# 删除空目录
# find ~/.trash -type d -delete
alias rm="sh /usr/local/bin/remove.sh"
EOF

tee /usr/local/bin/remove.sh <<'EOF'
#!/bin/sh
# 定义回收站文件夹目录.trash
trash="/.trash"
deltime=$(date +%Y%m%d%H%M%S)
TRASH_DIR="${HOME}${trash}/${deltime}"
# 建立回收站目录当不存在的时候
if [ ! -e ${TRASH_DIR} ];then
   mkdir -p ${TRASH_DIR}
fi
for i in $*;do
  if [ "$i" = "-rf" ];then continue;fi
  # 防止误操作
  if [ "$i" = "/" ];then echo '# Danger delete command, Not delete / directory!';exit -1;fi
  # 得到文件名称(非文件夹)，参考man basename
  fileName=$(basename $i)
  # 将输入的参数，对应文件mv至.trash目录，文件后缀，为当前的时间戳
  mv $i ${TRASH_DIR}/${fileName}
done
EOF

  # 2.执行权限赋予立即生效
  sudo chmod a+x /usr/local/bin/remove.sh /etc/profile.d/alias.sh
  source /etc/profile.d/alias.sh

  log::succ "[${COUNT}] This operation is completed."
  sleep 1
  ((COUNT++))
}


