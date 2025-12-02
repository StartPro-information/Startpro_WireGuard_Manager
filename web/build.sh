#!/bin/bash

# Web前端构建脚本

echo "开始构建Web前端..."

# 进入web目录
cd "$(dirname "$0")"

# 检查node_modules是否存在，如果不存在则安装依赖
if [ ! -d "node_modules" ]; then
  echo "安装npm依赖..."
  npm install
fi

# 构建项目
echo "执行构建..."
npm run build

# 检查构建是否成功
if [ $? -eq 0 ]; then
  echo "Web前端构建成功完成!"
  echo "构建输出在dist目录中"
else
  echo "Web前端构建失败!"
  exit 1
fi