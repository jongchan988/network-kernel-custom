#!/bin/bash

# 빌드 및 소스 경로 설정
KERNEL_SRC="/usr/src/linux-5.15.90"
MODULE_SRC="/usr/src/lkm"
MODULE_NAME="ocpp_filter"

# 1. 기존에 로드된 모듈이 있으면 제거
if lsmod | grep "$MODULE_NAME" &> /dev/null ; then
    echo "Removing existing $MODULE_NAME module..."
    sudo rmmod $MODULE_NAME
else
    echo "$MODULE_NAME module is not currently loaded."
fi

# 2. 모듈 빌드
echo "Building the $MODULE_NAME module..."
sudo make -C $KERNEL_SRC M=$MODULE_SRC clean
sudo make -C $KERNEL_SRC M=$MODULE_SRC modules

# 3. 빌드된 모듈 로드
if [ -f "$MODULE_SRC/$MODULE_NAME.ko" ]; then
    echo "Loading the $MODULE_NAME module..."
    sudo insmod "$MODULE_SRC/$MODULE_NAME.ko"
else
    echo "Module build failed. $MODULE_NAME.ko not found."
    exit 1
fi

# 4. 모듈 상태 확인
echo "Checking module status..."
lsmod | grep "$MODULE_NAME"

# 5. 커널 로그 출력
echo "Displaying kernel log for $MODULE_NAME..."
dmesg | tail -n 20

