#!/bin/bash

# Paths and configurations
TC_DIR="$HOME/android/toolchains/aosp-clang"
GCC_64_DIR="$HOME/android/toolchains/llvm-arm64"
GCC_32_DIR="$HOME/android/toolchains/llvm-arm"
AK3_DIR="$HOME/android/Anykernel3"
DEFCONFIG="vendor/ginkgo-perf_defconfig"

# Export build metadata
export PATH="$TC_DIR/bin:$PATH"
export KBUILD_BUILD_USER=lyahi
export KBUILD_BUILD_HOST=idut

# Function to handle script cleanup on exit or interrupt
cleanup() {
    echo -e "\nScript interrupted! Performing cleanup..."
    rm -rf out/arch/arm64/boot 2>/dev/null
    echo "Temporary files cleaned up."
    echo "Exiting..."
}

# Set trap to call the cleanup function on EXIT or SIGINT (Ctrl+C)
trap cleanup EXIT SIGINT

# Function to show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -r, --regen       Regenerate defconfig and save it to the configuration directory"
    echo "  -c, --clean       Clean the output directory"
    echo "  -g, --get-ksu     Download and set up KernelSU, apply patch, and modify defconfig"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "If no options are provided, the script will proceed to compile the kernel and package it."
    echo "The script will also adjust the output ZIP name based on the presence of the KernelSU directory."
    echo ""
    echo "Example:"
    echo "  $0           # Compile kernel"
    echo "  $0 --regen   # Regenerate defconfig"
    echo "  $0 --clean   # Clean output directory"
    echo "  $0 --get-ksu # Download and set up KernelSU"
}

# Function to start the timer
start_timer() {
    START_TIME=$(date +%s)  # Get the current time in seconds since epoch
}

# Function to end the timer and display elapsed time
end_timer() {
    END_TIME=$(date +%s)  # Get the end time
    ELAPSED_TIME=$(( END_TIME - START_TIME ))  # Calculate elapsed time in seconds

    # Convert seconds to minutes and seconds
    MINUTES=$(( ELAPSED_TIME / 60 ))
    SECONDS=$(( ELAPSED_TIME % 60 ))

    echo -e "\nCompleted in ${MINUTES} minute(s) and ${SECONDS} second(s)!"
}

# Function to determine the ZIP file name based on the presence of KernelSU and date
get_zip_name() {
    local head date
    head=$(git rev-parse --short=7 HEAD)
    date=$(date +%Y%m%d)  # Get the current date in YYYYMMDD format
  
    if [[ -d "KernelSU" ]]; then
        ZIPNAME="Cryo-ginkgo-v359-ksu-${date}.zip"
    else
        ZIPNAME="Cryo-kernel-retrofit-${head}-${date}.zip"
    fi

    echo "$ZIPNAME"
}

# Function to download and set up KernelSU, apply patch and modify defconfig
set_kernelsu() {
    echo "Downloading and setting up KernelSU..."
    curl -kLSs "https://raw.githubusercontent.com/rsuntk/KernelSU/main/kernel/setup.sh" | bash -s main
    if [[ $? -eq 0 ]]; then
        echo "KernelSU downloaded and set up successfully."
        
        if [[ -d "KernelSU" ]]; then
            # Apply KernelSU hook patch
            echo "Applying KernelSU-hook.patch..."
            if [[ -f "KernelSU-hook.patch" ]]; then
                git apply KernelSU-hook.patch
                echo "Patch applied successfully."
            else
                echo "Patch KernelSU-hook.patch not found!"
            fi
            
            # Modify the defconfig to enable KernelSU
            echo "Enabling CONFIG_KSU in $DEFCONFIG..."
            sed -i 's/CONFIG_KSU=n/CONFIG_KSU=y/g' "arch/arm64/configs/$DEFCONFIG"
            echo "CONFIG_KSU enabled in $DEFCONFIG."
        else
            echo "KernelSU directory not found after download!"
        fi
    else
        echo "Failed to download KernelSU."
        exit 1
    fi
}

# Function to regenerate defconfig
regen_defconfig() {
    make O=out ARCH=arm64 "$DEFCONFIG" savedefconfig
    cp out/defconfig "arch/arm64/configs/$DEFCONFIG"
    echo "Defconfig regenerated and saved!"
}

# Function to clean the output directory
clean_output() {
    rm -rf out
    echo "Output directory cleaned."
}

# Function to set up output directory and build kernel using a make command stored in an array
setup_and_compile() {
    mkdir -p out
    make O=out ARCH=arm64 "$DEFCONFIG"
    
    echo -e "\nStarting compilation...\n"
    local jobs
    jobs=$(nproc 2>/dev/null || echo 4)

    # Array holding the make arguments
    make_args=(
        -j$((jobs + 1))
        O=out
        ARCH=arm64
        CC=clang
        LD=ld.lld
        AR=llvm-ar
        AS=llvm-as
        NM=llvm-nm
        OBJCOPY=llvm-objcopy
        OBJDUMP=llvm-objdump
        STRIP=llvm-strip
        CROSS_COMPILE="$GCC_64_DIR/bin/aarch64-linux-android-"
        CROSS_COMPILE_ARM32="$GCC_32_DIR/bin/arm-linux-androideabi-"
        CLANG_TRIPLE=aarch64-linux-gnu-
        Image.gz-dtb
        dtbo.img
    )

    # Invoke make with the arguments from the array
    make "${make_args[@]}"
    
    if [[ -f "out/arch/arm64/boot/Image.gz-dtb" && -f "out/arch/arm64/boot/dtbo.img" ]]; then
        echo -e "\nKernel compiled successfully!"
        package_kernel
    else
        echo -e "\nCompilation failed!"
        exit 1
    fi
}

# Function to package kernel into a zip file
package_kernel() {
    local zip_name
    zip_name=$(get_zip_name)
  
    if [[ -d "$AK3_DIR" ]]; then
        cp out/arch/arm64/boot/Image.gz-dtb "$AK3_DIR"
        cp out/arch/arm64/boot/dtbo.img "$AK3_DIR"
        cd "$AK3_DIR" || { echo "Failed to enter AnyKernel3 directory!"; exit 1; }
        
        zip -r9 "../$zip_name" * -x '*.git*' README.md *placeholder
        cd - || exit 1
        
        rm -rf out/arch/arm64/boot
        echo -e "\nKernel packaged successfully as: $zip_name"
        end_timer  # End the timer and display elapsed time
    else
        echo "AnyKernel3 directory not found!"
        exit 1
    fi
}

# Main function to control script flow
main() {
    start_timer  # Start the timer
    case "$1" in
        -r|--regen)
            regen_defconfig
            ;;
        -c|--clean)
            clean_output
            ;;
        -g|--get-ksu)
            set_kernelsu
            ;;
        -h|--help)
            show_help
            ;;
        *)
            if [[ -n "$1" ]]; then
                echo "Unknown option: $1"
                show_help
                exit 1
            fi
            setup_and_compile
            ;;
    esac
}

# Run the main function
main "$@"
