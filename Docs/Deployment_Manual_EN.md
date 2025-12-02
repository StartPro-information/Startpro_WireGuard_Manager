I. Prepare the System Environment
Operating System: Ubuntu 20.04 LTS

CPU: Minimum 2 cores

Memory: Minimum 4 GB

Disk Space: At least 10 GB of free space


II. Prepare the WireGuard Runtime Environment

Install WireGuard and Required Packages

sudo apt update
sudo apt install -y wireguard-tools resolvconf git curl wget nginx


This installs all necessary dependencies.

Enable IPv4 Forwarding
Edit the /etc/sysctl.conf file, find and uncomment the line:

net.ipv4.ip_forward=1


If it doesn’t exist, add it manually. Then apply the change immediately:

sudo sysctl -p


Disable the Firewall

sudo ufw disable


III. Prepare the Backend Runtime Environment

Install Go 1.21.1

wget https://go.dev/dl/go1.21.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version


Install and Initialize MySQL

sudo apt install -y mysql-server
sudo systemctl start mysql
sudo systemctl enable mysql
sudo mysql


Inside the MySQL shell:

CREATE DATABASE wireguard_manager;
CREATE USER 'wireguard'@'localhost' IDENTIFIED BY 'wireguard123';
GRANT ALL PRIVILEGES ON wireguard_manager.* TO 'wireguard'@'localhost';
FLUSH PRIVILEGES;
EXIT;

IV. Deploy the WireGuard Manager Frontend via Nginx
sudo rm -f /etc/nginx/sites-enabled/default
sudo cp /your_project_path/wireguard-manager/web/wireguard-manager.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/wireguard-manager.conf /etc/nginx/sites-enabled/
sudo mkdir -p /var/www/wireguard-manager
sudo cp -r /your_project_path/wireguard-manager/web/dist/* /var/www/wireguard-manager/
sudo systemctl restart nginx


Replace /your_project_path with your actual project directory.


V. Start the Backend Service

Import the MySQL Database

mysql -u wireguard -pwireguard123 wireguard_manager < /your_project_path/wireguard-manager/backend/wireguard_manager_full_backup.sql


Replace /your_project_path with your actual project directory.

Update Paths in the Service File
Edit the wireguard-manager/backend/wireguard-manager.service file and replace /your_project_path in both the WorkingDirectory and ExecStart fields with your actual project path.

Start and Enable the WireGuard Manager Backend Service

sudo cp /your_project_path/wireguard-manager/backend/wireguard-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start wireguard-manager
sudo systemctl enable wireguard-manager


VI. Access WireGuard Manager

Open a browser and visit:

http://your_server_ip


You should see the WireGuard Manager login page.
Use the default credentials to log in:
Username: admin
Password: admin
