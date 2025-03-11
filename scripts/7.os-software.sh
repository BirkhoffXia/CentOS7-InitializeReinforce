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

# 函数名称: install_java
# 函数用途: 安装配置java环境
# 函数参数: 无
function install_java() {
  log::info "安装配置java环境-Install Java dependent environment"

  # 1.定义JDK压缩包名称 
  JDK_FILE="${1}"  #  /root/Downloads/jdk-8u211-linux-x64.tar.gz
  JDK_SRC="/usr/local/"
  JDK_DIR="/usr/local/jdk"

  # 2.解压与环境配置
  sudo tar -zxvf ${JDK_FILE} -C ${JDK_SRC}
  sudo rm -rf /usr/local/jdk 
  JDK_SRC=$(ls /usr/local/ | grep "jdk")
  sudo ln -s ${JDK_SRC} ${JDK_DIR}
  export PATH=${JDK_DIR}/bin:${PATH}
  sudo tee -a /etc/profile <<'EOF'
export JAVA_HOME=/usr/local/jdk
export JRE_HOME=/usr/local/jdk/jre
export CLASSPATH=.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar
export PATH=$JAVA_HOME/bin:$PATH
EOF

  # 3.安装版本验证
  java -version
}

## 函数名称: install_docker
## 函数用途: 在主机上安装最新版本的Docker
## 函数参数: 无
# 帮助: https://docs.docker.com/engine/install/centos
function install_docker(){
  log::info "[-] 安装配置Docker容器运行环境-Install docker environment"
  
  # 1.卸载旧版本 
  sudo yum remove docker docker-engine docker.io containerd runc
  sudo yum remove docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-engine

  # 2.安装相关依赖包
  sudo yum install -y yum-utils

  # 3.设置稳定镜像源存储库，此处采用阿里的docker源
  # DOCKER_COMPOSE_MIRRORS='https://github.com'
  # DOCKER_CE_MIRRORS='https://download.docker.com'
  # DOCKER_MIRRORS='https://docker.io'

  # Official
  # sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  # sed -i 's#download.docker.com#mirrors.aliyun.com/docker-ce#' /etc/yum.repos.d/docker-ce.repo
  yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
  # 使用 CentOS 8 的源
  # echo "8" > /etc/yum/vars/centos_version
  # sed -i 's/$releasever/$centos_version/g'  /etc/yum.repos.d/docker-ce.repo

  # 4.查看Docker特定的相关版本，使用如下命令列出可用的版本
  yum list docker-ce  --showduplicates | sort -r | grep "docker-ce" | head -n 2
  yum list docker-ce-cli --showduplicates | sort -r | grep "docker-ce-cli" | head -n 2
  yum list containerd.io --showduplicates | sort -r | grep "containerd" | head -n 2

  # 5.安装Docker最新版本，此处我们指定的是最新版本。
  # 使用第二列中的版本字符串安装特定的版本，例如:containerd.io.x86_64  1.6.9-3.1.el8 docker-ce-stable
  # $sudo apt-get install docker-ce-<VERSION_STRING> docker-ce-cli-<VERSION_STRING> containerd.io
  # yum install docker-ce-3:23.0.1-1.el8 docker-ce-cli-1:23.0.1-1.el8 containerd.io-1.6.9-3.1.el8 -y
  sudo yum install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  # 6.将当前（低）用户加入docker用户组然后重新登陆当前用户使得低权限用户
  sudo gpasswd -a ${VAR_USER_NAME} docker

  # 7.配置docker后台守护进程
  mkdir -vp /etc/docker/
sudo tee /etc/docker/daemon.json <<-'EOF'
{
  "data-root":"/var/lib/docker",
  "registry-mirrors": ["https://xlx9erfu.mirror.aliyuncs.com"],
  "exec-opts": ["native.cgroupdriver=systemd"],
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-level": "warn",
  "log-opts": {
    "max-size": "100m",
    "max-file": "10"
  },
  "live-restore": true,
  "dns": ["223.6.6.6","114.114.114.114"],
  "insecure-registries": [ "harbor.weiyigeek.top"]
}
EOF

  # 8.自启与启动
  sudo systemctl daemon-reload
  sudo systemctl enable docker.service --now
  # sudo systemctl restart docker.service

  # 9.验证安装的 docker 服务
  systemctl status docker.service --no-pager -l
  docker info

  # 10.启动一个 hello-world 容器，验证是否正常
  docker run --rm hello-world
}


## 函数名称: install_dockercompose
## 函数用途: 在主机上安装 Dockercompose 工具
## 函数参数: 无
function install_dockercompose(){
  printf "\n\033[34mINFO: [*] Install docker-compose environment \033[0m \n"
  log::info "[-] 安装配置Docker-Compose环境"

  # Setting Docker-Compose MIRRORS
  DOCKER_COMPOSE_MIRRORS='https://get.daocloud.io'
  # Default New Version v2.16.0 (2023年3月8日 18:57:48)
  DOCKER_COMPOSE_VERSION=${1}
  # Download、Install Docker-Compose
  curl -L ${DOCKER_COMPOSE_MIRRORS}/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION:="v2.16.0"}/docker-compose-"$(uname -s)"-"$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
  # Verify Install
  docker-compose version
}

