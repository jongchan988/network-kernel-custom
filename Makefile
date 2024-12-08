# 커널 모듈 파일 (ocpp_filter.c)
obj-m += key_mgmt.o ocpp_filter.o

# 기본 타겟: 커널 모듈 빌드
all:
	$(MAKE) -C /usr/src/linux-5.15.90 M=$(PWD) modules

# clean 타겟: 빌드 파일 삭제
clean:
	$(MAKE) -C /usr/src/linux-5.15.90 M=$(PWD) clean
