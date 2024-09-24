#!/bin/bash

SECONDS=0 # builtin bash timer
head=$(git rev-parse --short=7 HEAD)
TC_DIR="$HOME/android/toolchains/aosp-clang"
GCC_64_DIR="$HOME/android/toolchains/llvm-arm64"
GCC_32_DIR="$HOME/android/toolchains/llvm-arm"
AK3_DIR="$HOME/android/Anykernel3"
DEFCONFIG="vendor/ginkgo-perf_defconfig"

# Fetch CONFIG_KSU value from defconfig
config_ksu_value() {
    local config_val
    config_val=$(grep -i "^CONFIG_KSU=" "arch/arm64/configs/$DEFCONFIG" | cut -d'=' -f2)

    if [[ -z "$config_val" ]]; then
        printf "Error: CONFIG_KSU not found in %s\n" "$DEFCONFIG" >&2
        return 1
    fi
    printf "%s" "$config_val"
}

# Function to set ZIPNAME based on CONFIG_KSU
set_zipname() {
    local config_ksu
    config_ksu=$(config_ksu_value) || return 1

    if [[ "$config_ksu" == "y" ]]; then
        ZIPNAME="Cryo-ginkgo-$(date '+%Y%m%d')-$head-ksu.zip"
    elif [[ "$config_ksu" == "n" ]]; then
        ZIPNAME="Cryo-ginkgo-$(date '+%Y%m%d')-$head.zip"
    else
        printf "Error: Invalid value for CONFIG_KSU in %s\n" "$DEFCONFIG" >&2
        return 1
    fi
}

# Main function to control script flow
main() {
    export PATH="$TC_DIR/bin:$PATH"
    export KBUILD_BUILD_USER=lyahi
    export KBUILD_BUILD_HOST=idut

    # Handle regeneration and clean options
    if [[ $1 == "-r" || $1 == "--regen" ]]; then
        make O=out ARCH=arm64 "$DEFCONFIG" savedefconfig
        cp out/defconfig "arch/arm64/configs/$DEFCONFIG"
        return
    elif [[ $1 == "-c" || $1 == "--clean" ]]; then
        rm -rf out
    fi

    # Set the ZIPNAME based on CONFIG_KSU value
    if ! set_zipname; then
        exit 1
    fi

    # Create output directory and start compilation
    mkdir -p out
    make O=out ARCH=arm64 "$DEFCONFIG"

    echo -e "\nStarting compilation...\n"
    make -j$(($(nproc) + 1)) O=out ARCH=arm64 CC=clang LD=ld.lld AR=llvm-ar AS=llvm-as NM=llvm-nm \
        OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip \
        CROSS_COMPILE="$GCC_64_DIR/bin/aarch64-linux-android-" \
        CROSS_COMPILE_ARM32="$GCC_32_DIR/bin/arm-linux-androideabi-" \
        CLANG_TRIPLE=aarch64-linux-gnu- Image.gz-dtb dtbo.img

    # Check if compilation was successful
    if [[ -f "out/arch/arm64/boot/Image.gz-dtb" && -f "out/arch/arm64/boot/dtbo.img" ]]; then
        echo -e "\nKernel compiled successfully! Zipping up...\n"
        if [[ -d "$AK3_DIR" ]]; then
            cp out/arch/arm64/boot/Image.gz-dtb "$AK3_DIR"
            cp out/arch/arm64/boot/dtbo.img "$AK3_DIR"
            cd "$AK3_DIR" || return
            zip -r9 "../$ZIPNAME" * -x '*.git*' README.md *placeholder
            cd - || return
            rm -rf out/arch/arm64/boot
            echo -e "\nCompleted in $((SECONDS / 60)) minute(s) and $((SECONDS % 60)) second(s)!"
            echo "Zip: $ZIPNAME"
        fi
    else
        echo -e "\nCompilation failed!"
        exit 1
    fi
}

# Call main function
main "$@"
