#!/bin/bash

SECONDS=0 # builtin bash timer
head=$(git rev-parse --short=7 HEAD)
ZIPNAME="Cryo-ginkgo-$(date '+%Y%m%d')-$head.zip"
TC_DIR="$HOME/Android/Cryo/toolchains/aosp-clang"
GCC_64_DIR="$HOME/Android/Cryo/toolchains/llvm-arm64"
GCC_32_DIR="$HOME/Android/Cryo/toolchains/llvm-arm"
AK3_DIR="$HOME/Android/Cryo/AnyKernel3"
DEFCONFIG="vendor/ginkgo-perf_defconfig"

export PATH="$TC_DIR/bin:$PATH"

export KBUILD_BUILD_USER=lyahi
export KBUILD_BUILD_HOST=idut

if [[ $1 = "-r" || $1 = "--regen" ]]; then
	make O=out ARCH=arm64 $DEFCONFIG savedefconfig
	cp out/defconfig arch/arm64/configs/$DEFCONFIG
	exit
fi

if [[ $1 = "-c" || $1 = "--clean" ]]; then
	rm -rf out
fi

mkdir -p out
make O=out ARCH=arm64 $DEFCONFIG

echo -e "\nStarting compilation...\n"
make -j$(($(nproc) + 1)) O=out ARCH=arm64 CC=clang LD=ld.lld AR=llvm-ar AS=llvm-as NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip CROSS_COMPILE=$GCC_64_DIR/bin/aarch64-linux-android- CROSS_COMPILE_ARM32=$GCC_32_DIR/bin/arm-linux-androideabi- CLANG_TRIPLE=aarch64-linux-gnu- Image.gz-dtb dtbo.img

if [ -f "out/arch/arm64/boot/Image.gz-dtb" ] && [ -f "out/arch/arm64/boot/dtbo.img" ]; then
	echo -e "\nKernel compiled succesfully! Zipping up...\n"
	if [ -d "$AK3_DIR" ]; then
		cp out/arch/arm64/boot/Image.gz-dtb "$AK3_DIR"
		cp out/arch/arm64/boot/dtbo.img "$AK3_DIR"
		cd "$AK3_DIR" || exit
		zip -r9 "../$ZIPNAME" * -x '*.git*' README.md *placeholder
		cd "$OLDPWD" || exit
		rm -rf out/arch/arm64/boot
		echo -e "\nCompleted in $((SECONDS / 60)) minute(s) and $((SECONDS % 60)) second(s) !"
		echo "Zip: $ZIPNAME"
	fi
else
	echo -e "\nCompilation failed!"
	exit 1
fi
