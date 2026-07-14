cc_cross=/toolchains/tmp/OpenWrt-SDK-15.05.1-ar71xx-generic_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++ -s
cc_local=g++
#cc_mips34kc=/toolchains/OpenWrt-SDK-ar71xx-for-linux-x86_64-gcc-4.8-linaro_uClibc-0.9.33.2/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-g++
cc_mips24kc_be=/toolchains/lede-sdk-17.01.2-ar71xx-generic_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-5.4.0_musl-1.1.16/bin/mips-openwrt-linux-musl-g++
cc_mips24kc_le=/toolchains/lede-sdk-17.01.2-ramips-mt7621_gcc-5.4.0_musl-1.1.16.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-5.4.0_musl-1.1.16/bin/mipsel-openwrt-linux-musl-g++
#cc_arm= /toolchains/gcc-linaro-4.9.4-2017.01-x86_64_arm-linux-gnueabi/bin/arm-linux-gnueabi-g++ -march=armv6 -marm 
cc_arm= /toolchains/arm-2014.05/bin/arm-none-linux-gnueabi-g++
#cc_bcm2708=/home/wangyu/raspberry/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-g++ 
FLAGS= -std=c++11   -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers -ggdb -I. -IUDPspeeder -isystem UDPspeeder/libev ${OPT} 

SOURCES=`ls UDPspeeder/*.cpp UDPspeeder/lib/*.cpp|grep -v main.cpp|grep -v tunnel.cpp` main.cpp tun_dev.cpp tun_dev_client.cpp tun_dev_server.cpp tun_dev_raw_client.cpp tun_dev_raw_server.cpp
OBJECTS=tun_dev_raw.o u2r_udp2raw.o

#INCLUDE= -I.  -IUDPspeeder

NAME=tinyvpn

TARGETS=amd64 arm mips24kc_be x86  mips24kc_le

TAR=${NAME}_binaries.tar.gz `echo ${TARGETS}|sed -r 's/([^ ]+)/tinyvpn_\1/g'` version.txt

export STAGING_DIR=/tmp/    #just for supress warning of staging_dir not define

all:git_version ${OBJECTS}
	rm -f ${NAME}
	${cc_local}   -o ${NAME}      ${INCLUDE}  ${SOURCES} ${OBJECTS} ${FLAGS} -lrt -ggdb -static -O2

debug: git_version ${OBJECTS}
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${OBJECTS} ${FLAGS} -lrt -Wformat-nonliteral -D MY_DEBUG 
debug2: git_version ${OBJECTS}
	rm -f ${NAME}
	${cc_local}   -o ${NAME}          -I. ${SOURCES} ${OBJECTS} ${FLAGS} -lrt -Wformat-nonliteral -ggdb

init:
	git submodule init
	git submodule update

# u2r_udp2raw.o: compiled with udp2raw headers (like tun_dev_raw.o)
u2r_udp2raw.o: u2r_udp2raw.cpp u2r_prefix.h
	${cc_local} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

# tun_dev_raw.o compiled with udp2raw headers for wrapper functions
tun_dev_raw.o: tun_dev_raw.cpp tun_dev_raw.h u2r_prefix.h
	${cc_local} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

mips24kc_be: git_version tun_dev_raw_mips_be.o
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES} tun_dev_raw_mips_be.o ${FLAGS} -lrt -lgcc_eh -static -O3

tun_dev_raw_mips_be.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_mips24kc_be} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

mips24kc_be_debug: git_version tun_dev_raw_mips_be_debug.o
	${cc_mips24kc_be}  -o ${NAME}_$@   -I. ${SOURCES} tun_dev_raw_mips_be_debug.o ${FLAGS} -lrt -lgcc_eh -static -ggdb

tun_dev_raw_mips_be_debug.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_mips24kc_be} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

mips24kc_le: git_version tun_dev_raw_mips_le.o
	${cc_mips24kc_le}  -o ${NAME}_$@   -I. ${SOURCES} tun_dev_raw_mips_le.o ${FLAGS} -lrt -lgcc_eh -static -O3

tun_dev_raw_mips_le.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_mips24kc_le} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

amd64:git_version tun_dev_raw_amd64.o
	${cc_local}   -o ${NAME}_$@    -I. ${SOURCES} tun_dev_raw_amd64.o ${FLAGS} -lrt -static -O3
tun_dev_raw_amd64.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_local} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

amd64_debug:git_version tun_dev_raw_amd64_debug.o
	${cc_local}   -o ${NAME}_$@    -I. ${SOURCES} tun_dev_raw_amd64_debug.o ${FLAGS} -lrt -static -ggdb
tun_dev_raw_amd64_debug.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_local} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

x86:git_version tun_dev_raw_x86.o
	${cc_local}   -o ${NAME}_$@      -I. ${SOURCES} tun_dev_raw_x86.o ${FLAGS} -lrt -static -O3 -m32
tun_dev_raw_x86.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_local} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $< -m32

arm:git_version tun_dev_raw_arm.o
	${cc_arm}   -o ${NAME}_$@      -I. ${SOURCES} tun_dev_raw_arm.o ${FLAGS} -lrt -static -O3
tun_dev_raw_arm.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_arm} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

arm_debug:git_version tun_dev_raw_arm_debug.o
	${cc_arm}   -o ${NAME}_$@      -I. ${SOURCES} tun_dev_raw_arm_debug.o ${FLAGS} -lrt -static -ggdb
tun_dev_raw_arm_debug.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_arm} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

cross:git_version tun_dev_raw_cross.o
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} tun_dev_raw_cross.o ${FLAGS} -lrt -O3
tun_dev_raw_cross.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_cross} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

cross2:git_version tun_dev_raw_cross2.o
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} tun_dev_raw_cross2.o ${FLAGS} -lrt -static -lgcc_eh -O3   
tun_dev_raw_cross2.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_cross} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

cross3:git_version tun_dev_raw_cross3.o
	${cc_cross}   -o ${NAME}_cross    -I. ${SOURCES} tun_dev_raw_cross3.o ${FLAGS} -lrt -static -O3
tun_dev_raw_cross3.o: tun_dev_raw.cpp tun_dev_raw.h udp2raw/u2r_prefix.h
	${cc_cross} -c -o $@ -Iudp2raw -isystem udp2raw/libev ${FLAGS} $<

release: ${TARGETS} 
	cp git_version.h version.txt
	tar -zcvf ${TAR}

clean:	
	rm -f ${TAR}
	rm -f speeder speeder_cross
	rm -f ${NAME} ${NAME}_*
	rm -f git_version.h
	rm -f tun_dev_raw*.o

git_version:
	    echo "const char * const gitversion = \"$(shell git rev-parse HEAD)\";" > git_version.h
	

# targets without restrictions:
nolimit:
	make OPT=-DNOLIMIT
nolimit_all:
	make OPT=-DNOLIMIT
nolimit_cross:
	make cross OPT=-DNOLIMIT
nolimit_cross2:
	make cross2 OPT=-DNOLIMIT
nolimit_cross3:
	make cross3 OPT=-DNOLIMIT
nolimit_release:
	make release OPT=-DNOLIMIT
