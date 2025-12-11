# source this file to activate the environment,
# or use "make env" to start a sub-shell

# components managed by ansible
export KAFL_ROOT="/home/lwq/Desktop/kAFL/kafl"
export QEMU_ROOT="/home/lwq/Desktop/kAFL/kafl/qemu"
export LIBXDC_ROOT="/home/lwq/Desktop/kAFL/kafl/libxdc"
export CAPSTONE_ROOT="/home/lwq/Desktop/kAFL/kafl/capstone"
export RADAMSA_ROOT="/home/lwq/Desktop/kAFL/kafl/radamsa"
export GHIDRA_ROOT="/home/lwq/Desktop/kAFL/kafl/ghidra_10.1.3_PUBLIC"
export EXAMPLES_ROOT="/home/lwq/Desktop/kAFL/kafl/examples"

# workspace defaults
export KAFL_WORKSPACE="/home/lwq/Desktop/kAFL"
export KAFL_WORKDIR="/dev/shm/kafl_lwq"
export ABS_SHARED_DIR="/home/lwq/Desktop/kAFL/kafl/examples/linux-user/nvidia_fuzzer/sharedir"
export ABS_IMG="/home/lwq/Desktop/kAFL/kafl/examples/linux-user/nvidia_fuzzer/kafl_guest_prep/ubuntu-nvidia/ubuntu-nvidia.qcow2"
#其他终端执行的
# kAFL configuration override (optional)
# export KAFL_CONFIG_FILE=""

# activate python venv
source $KAFL_ROOT/.venv/bin/activate
