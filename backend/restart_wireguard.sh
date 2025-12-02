#!/bin/bash

# 检测并终止占用8080端口的进程
PORT=8080
PID=$(lsof -t -i:$PORT 2>/dev/null)

if [ -n "$PID" ]; then
    echo "检测到进程 $PID 占用端口 $PORT，正在终止..."
    kill -9 $PID
    if [ $? -eq 0 ]; then
        echo "进程 $PID 已成功终止"
    else
        echo "终止进程 $PID 失败，请检查权限"
        exit 1
    fi
else
    echo "未检测到占用端口 $PORT 的进程"
fi

# 等待1秒以确保端口被释放
echo "等待1秒..."
sleep 1

# 启动新版本的wireguard-manager程序
echo "正在启动新版本wireguard-manager程序..."
if [ -f ./wireguard-manager ]; then
    nohup ./wireguard-manager >/dev/null 2>&1 &
    NEW_PID=$!
    echo "wireguard-manager 已启动，PID: $NEW_PID"
    
    # 验证启动是否成功
    sleep 2
    if ps -p $NEW_PID >/dev/null 2>&1; then
        echo "程序启动成功，正在运行中"
        echo "可以通过 'tail -f nohup.out' 查看日志"
    else
        echo "程序启动失败，请查看nohup.out日志"
    fi
else
    echo "错误：未找到wireguard-manager可执行文件"
    exit 1
fi