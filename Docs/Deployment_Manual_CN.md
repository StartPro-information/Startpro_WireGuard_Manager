一、准备系统环境
### 操作系统**: Ubuntu 20.04 LTS
- **CPU**: 最少2核心
- **内存**: 最少4GB
- **磁盘空间**: 10GB可用空间

二、准备wireguard运行环境
1.	准备wireguard环境
sudo apt update
sudo apt install -y wireguard-tools resolvconf git curl wget nginx  #安装必要的软件包
2.开启系统ipv4转发
编辑 /etc/sysctl.conf 文件 ，找到并取消 net.ipv4.ip_forward=1 的注释，或直接添加这行 。然后执行 sudo sysctl -p 让配置立即生效
2.	关闭系统防火墙
sudo ufw disable

三、准备后端程序运行环境
1.	安装go1.12.1版本
wget https://go.dev/dl/go1.21.1.linux-amd64.tar.gz    #国内需要挂梯子才能下载
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc    #配置go环境变量
source ~/.bashrc
go version
2.	安装并初始化mysql数据库
sudo apt install -y mysql-server
sudo systemctl start mysql
sudo systemctl enable mysql
sudo mysql
CREATE DATABASE wireguard_manager;
CREATE USER 'wireguard'@'localhost' IDENTIFIED BY 'wireguard123';
GRANT ALL PRIVILEGES ON wireguard_manager.* TO 'wireguard'@'localhost';
FLUSH PRIVILEGES;
EXIT;

四、通过nginx发布wireguard-manager前端界面
sudo rm -f /etc/nginx/sites-enabled/defaule  #删除nginx默认配置文件
sudo cp /your_project_path/wireguard-manager/web/wireguard-manager.conf /etc/nginx/sites-available/    #将/your_project_path替换为你的真实项目目录
sudo ln -s /etc/nginx/sites-available/wireguard-manager.conf /etc/nginx/sites-enabled/
sudo mkdir -p /var/www/wireguard-manager
sudo cp -r /your_project_path/wireguard-manager/web/dist/* /var/www/wireguard-manager/    #将/your_project_path替换为你的真实项目目录
sudo systemctl restart nginx

五、启动后端进程
1.	导入mysql数据库
mysql -u wireguard -pwireguard123 wireguard_manager < /your_project_path/wireguard-manager/backend/wireguard_manager_full_backup.sql    #将/your_project_path替换为你的真实项目目录
2.	更改wireguard-manager.service中的路径
将wireguard-manager/backend/wireguard-manager.server文件中WorkingDirectory和ExecStart字段的/your_project_path替换为你的真实项目路径。
3.	启动wireguard-manager后端服务
sudo cp /your_project_path/wireguard-manager/backend/wireguard-manager.server /etc/systemd/system/    #将/your_project_path替换为你的真实项目目录
sudo systemctl daemon-reload
sudo systemctl start wireguard-manager
sudo systemctl enable wireguard-manager

六、登录wireguard-manager
浏览器访问http://your_server_ip，可进入wireguard-manager登录界面，使用默认账号密码admin/admin进行登录。

