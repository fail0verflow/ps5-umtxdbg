#!/bin/bash
sshpass -p user scp umtxdbg.cpp user@172.23.28.141:
sshpass -p user ssh user@172.23.28.141 "clang++ -O3 -static -std=c++11 -o umtxdbg umtxdbg.cpp && sync"
