#!/bin/bash -eu
#
# Runs the given binary inside QEMU, with the Intel LAM feature enabled.  Uses
# full system mode due to issues with sanitizers in user mode.
#
# Usage:  ./run_in_qemu_with_lam.sh binary-to-run [argument]...
#
# NOTE:  You also need to ensure the environment variables below point to the
# necessary prerequisites: qemu-system-x86_64, qemu-img, debian-10.qcow2,
# debian-10.key, bzImage, and llvm-symbolizer.

# Path to binary to run in QEMU.
readonly BINARY_PATH="${1}"

# Arguments to pass the binary inside QEMU.
readonly BINARY_ARGS="${@:2}"

# Path to a qemu-system-x86_64 binary built with LAM support.
: ${QEMU:="${PWD}/qemu/build/qemu-system-x86_64"}

# Path to a qemu-img binary.
: ${QEMU_IMG:="${PWD}/qemu/build/qemu-img"}

# Path to a Debian 10 image configured with auto-login and SSH.
: ${IMAGE:="${PWD}/debian-10.qcow2"}

# Path to the SSH key for the root user of the Debian image.
: ${SSH_KEY:="${PWD}/debian-10.key"}

# The directory inside the Debian image where tests should run.  Must exist
# prior to running this script.
: ${QEMU_WORKSPACE_PATH:="/workspace"}

# Path to a Linux kernel bzImage built with LAM support.
: ${KERNEL:="${PWD}/linux/build/arch/x86_64/boot/bzImage"}

# Path to an llvm-symbolizer built with the following config:
#   cmake -GNinja -DLLVM_BUILD_RUNTIME=OFF -DCMAKE_BUILD_TYPE=Release \
#       -DLLVM_STATIC_LINK_CXX_STDLIB=ON ../llvm/
: ${LLVM_SYMBOLIZER:="${PWD}/llvm-project/build/bin/llvm-symbolizer"}

: ${HWASAN_OPTIONS:=""}

readonly QEMU_FORCE_KILL_TIMEOUT=3
readonly QEMU_EXIT_STATUS_PREFIX="command_exit_status:"
readonly HOST_TMPDIR="$(mktemp -d)"
readonly DELTA_IMAGE="${HOST_TMPDIR}/delta.img"
readonly QEMU_PIPE="${HOST_TMPDIR}/qemu"
readonly QEMU_INPUT_PIPE="${QEMU_PIPE}.in"
readonly QEMU_OUTPUT_PIPE="${QEMU_PIPE}.out"
readonly BINARY_NAME="$(basename ${BINARY_PATH})"

QEMU_PID=""
SSH_PORT=""

function force_kill_qemu_after_timeout {
  sleep "${QEMU_FORCE_KILL_TIMEOUT}"
  kill -9 "${QEMU_PID}" &>/dev/null || true
}

function on_exit {
  force_kill_qemu_after_timeout &
  if kill "${QEMU_PID}"; then
    echo "Waiting for QEMU to shutdown..."
    wait "${QEMU_PID}" &>/dev/null || true
  fi

  echo "Done!"
}

function wait_pipe_for_match {
  local match_str="${1}"

  while read line; do
    grep "${match_str}" <<< "${line}" && break
  done < "${QEMU_OUTPUT_PIPE}"
}

function boot_qemu {
  # Create a pipe for communication with QEMU.
  mkfifo "${QEMU_INPUT_PIPE}" "${QEMU_OUTPUT_PIPE}"

  # Create a delta image to boot from.
  "${QEMU_IMG}" create -f qcow2 -b "${IMAGE}" -F qcow2 "${DELTA_IMAGE}"

  echo "Booting QEMU..."

  # Try up to 10 random port numbers until one succeeds.
  for i in {0..10}; do
    SSH_PORT="$(shuf -i 1000-65535 -n 1)"
    "${QEMU}" -hda "${DELTA_IMAGE}" -nographic \
      -net "user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
      -net "nic,model=e1000" -machine "type=q35,accel=tcg" \
      -cpu "qemu64,+la57,+lam" -kernel "${KERNEL}" \
      -append "console=ttyS0 root=/dev/sda1 earlyprintk=serial net.ifnames=0" \
      -serial "pipe:${QEMU_PIPE}" -m "1G" &
    QEMU_PID=$!

    # If QEMU is running, the port number worked.
    sleep 1
    ps -p "${QEMU_PID}" &>/dev/null && break
  done

  # Fail fast if QEMU is not running.
  ps -p "${QEMU_PID}" &>/dev/null

  echo "Waiting for QEMU to login..."
  wait_pipe_for_match "debian login: root (automatic login)"
}

function copy_to_qemu {
  local local_file="${1}"
  local qemu_dir="${2}"

  scp -P "${SSH_PORT}" -o "StrictHostKeyChecking=no" \
    -o "UserKnownHostsFile=/dev/null" -i "${SSH_KEY}" "${local_file}" \
    "root@localhost:${qemu_dir}/"
}

function run_in_qemu {
  local command="${1}"

  echo "Running command in QEMU: ${command}"

  # Execute command via input pipe.
  # Forward HWASan options and append the exit status.
  echo -e "HWASAN_OPTIONS=\"${HWASAN_OPTIONS}\" ${command}; "\
    "echo \"${QEMU_EXIT_STATUS_PREFIX}\$?\"\\n" > "${QEMU_INPUT_PIPE}"

  # Print command output and extract exit status.  If non-zero exit status, quit
  # and return it to the user.
  while read line; do
    # Ignore leading \r which QEMU sometimes emits.
    if grep $'^\r*'"${QEMU_EXIT_STATUS_PREFIX}" <<< "${line}"; then
      local exit_status="$(tr -d $'\r'${QEMU_EXIT_STATUS_PREFIX} <<< ${line})"
      if [[ ${exit_status} -ne 0 ]]; then
        echo "ERROR executing command in qemu: ${command}"
        exit "${exit_status}"
      fi
      break
    fi
    echo "[qemu] ${line}"
  done < "${QEMU_OUTPUT_PIPE}"
}

trap on_exit EXIT

boot_qemu

# Copy llvm-symbolizer to QEMU.
copy_to_qemu "${LLVM_SYMBOLIZER}" "/usr/bin"

# Copy binary to QEMU.
run_in_qemu "rm -rf ${QEMU_WORKSPACE_PATH}/*"
copy_to_qemu "${BINARY_PATH}" "${QEMU_WORKSPACE_PATH}"

# Run binary in QEMU.
run_in_qemu "${QEMU_WORKSPACE_PATH}/${BINARY_NAME} ${BINARY_ARGS}"
