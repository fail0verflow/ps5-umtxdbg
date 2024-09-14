# NOTES

The bug was found in early december 2020, not by me, but a genius who looked 15mins at fbsd and immediately spotted it 🙇‍♂️. This c++ impl was made when experimenting with increasing exploit reliability after ps5 kernel added some heap randomization features.

# setup vm

## get vm image

```
wget http://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases/VM-IMAGES/11.0-RELEASE/amd64/Latest/FreeBSD-11.0-RELEASE-amd64.vhd.xz
```

## enable ssh

in the vm: `adduser`, add `sshd_enable="YES"` to `/etc/rc.conf`, `/etc/rc.d/sshd start`

## rebuild kernel with debug

build ON THE VM because the freebsd build system is incompatible with non-freebsd systems (they enabled compat around fbsd 12/13 but we need 11...)

see https://docs.freebsd.org/en/books/handbook/kernelconfig/ or just:

```
cd /usr/src/sys/amd64/conf
cp GENERIC /root/CONFIG
ln -s /root/CONFIG
```

edit CONFIG to __remove__ `options DDB` and __add__ `options GDB`

build and install:
```
cd /src/src
make buildkernel KERNCONF=CONFIG
make installkernel KERNCONF=CONFIG
reboot
```

copy `/usr/obj/usr/src/sys/CONFIG/kernel.debug` out of the vm for use with gdb.

# setup gdb

## get kernel src for browsing / gdb

```
git clone -b releng/11.0 https://github.com/freebsd/freebsd.git
```

## build gdb with fbsd support

fetch latest from https://ftp.gnu.org/gnu/gdb/ and unpack

```
mkdir build
cd build
../configure --disable-binutils --disable-ld --disable-gold --disable-gas --disable-sim --disable-gprof --target=x86_64-unknown-freebsd
make -j64
```

## make gdb suck less

use https://github.com/cyrus-and/gdb-dashboard

### .gdbinit for freebsd kernel

```
set substitute-path /usr/src /home/shawn/freebsd
set disassembly-flavor intel
file kernel.debug
target remote /tmp/fbsd11
```

### wsl interop

https://github.com/weltling/convey
https://github.com/jstarks/npiperelay

### wrapper for starting "loose" gdb

```
#!/bin/sh
GDB_PATH=/home/shawn/gdb-10.1/build/gdb
PATH=$GDB_PATH:$PATH
gdb --data-directory=/home/shawn/gdb-10.1/build/gdb/data-directory
```
 
### gdb initial breakin

in vm:
```
sysctl debug.kdb.enter=1
```
