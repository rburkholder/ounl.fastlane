# ounl.fastlane
Embedded Packet/Network Security

    cd /usr/src
    git clone https://github.com/rburkholder/libs-build.git
    cd libs-build
    ./build.sh base
    ./build.sh zlib
    ./build.sh boost
    ./build.sh wt
    ./build.sh vmime
    ./build.sh libnl
    cd /usr/src
    wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.3.1.tar.xz
    unxz linux-5.3.1.tar.xz
    tar -xvf linux-5.3.1.tar
    cd linux-5.3.1
    cp /boot/config-$(uname -r) .config
    make olddefconfig
    scripts/config --disable CONFIG_SYSTEM_TRUSTED_KEYS
    scripts/config --disable DEBUG_INFO
    make
    cd tools/bpf
    make
    cd /usr/src
    unzip ounl.fastlane-master.zip
    cd ounl.fastlane


- adjust clion environment with settings in clion.txt
- open cmake project in clion and try a build, and see how much cpu you need
- I assigned 4GB for memory
- hopefully I havn't left out too many important steps above
- make files rely on linux-5.3.1 being in /usr/src
