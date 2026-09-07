#!/usr/bin/env bash
#
# M3B §6 — PROVE THE EDGE'S STATE VOLUME IS ENCRYPTED BEFORE THE EDGE STARTS.
#
# WHY NOT ENCRYPT THE SQLITE COLUMNS INSTEAD
# ------------------------------------------
# The obvious answer was application-level field encryption in Node. It was
# rejected, and the reasons are worth keeping next to the alternative:
#
#   - the queue INDEXES identities and ordering, so those columns must stay
#     readable to the query planner. Encrypting the payload while leaving the
#     index keys in cleartext protects the least sensitive part and advertises
#     the rest: who, in what order, how many, and when.
#   - the journal and WAL contain the same rows again, in the clear, and no
#     column-level scheme reaches them.
#   - it would introduce a second cryptographic subsystem, with its own key
#     custody, its own rotation story and its own failure modes, to protect a
#     subset of what one storage boundary protects completely.
#
# So the boundary is the FILESYSTEM. One encrypted volume covers rows, indexes,
# journal, WAL, payloads, envelopes, receipts, queue metadata and the persisted
# trusted-time material as a single object.
#
# WHY THIS IS A SCRIPT AND NOT AN ENVIRONMENT VARIABLE
# ----------------------------------------------------
# The tempting shape is `EDGE_STORAGE_IS_ENCRYPTED=true`. A boolean can lie,
# and this one would lie in exactly the situation it exists to catch: an
# operator who intended encryption, mis-mounted the volume, and set the flag
# from memory. Every check below reads the RUNNING SYSTEM. Nothing here can be
# satisfied by asserting it.
#
# WHY A DOCKER NAMED VOLUME IS NOT ENOUGH
# ---------------------------------------
# A named volume lives under the Docker root and inherits whatever that
# filesystem happens to be. It proves nothing about encryption. Production must
# therefore use an explicit host path whose backing device this script has
# confirmed is dm-crypt/LUKS.
#
# EXIT CODES
#   0  every check passed; the caller may start the Edge
#   1  a check failed; the caller must NOT start the Edge
#   2  the script cannot answer (missing tool, unsupported platform)
#
# Exit 2 is deliberately distinct from exit 1. "I checked and it is not
# encrypted" and "I could not check" are different facts, and a caller that
# treats them alike will eventually treat an unrunnable probe as a pass.
#
# Usage:  scripts/edge-storage-preflight.sh /var/lib/sentinel-edge
set -euo pipefail

STATE_PATH="${1:-${EDGE_STORAGE_PATH:-/var/lib/sentinel-edge}}"

# The uid/gid the Edge container runs as. Defaults match the non-root user in
# services/edge-runtime's image.
EXPECTED_UID="${EDGE_STORAGE_UID:-10001}"
EXPECTED_GID="${EDGE_STORAGE_GID:-10001}"

# 0700. The Edge's queue holds field operations; a mode that lets any local
# account read them has moved the boundary this script exists to establish.
EXPECTED_MODE="${EDGE_STORAGE_MODE:-700}"

fail() { echo "edge storage preflight: FAILED - $*" >&2; exit 1; }
cannot() { echo "edge storage preflight: CANNOT VERIFY - $*" >&2; exit 2; }
note() { echo "edge storage preflight: $*"; }

# ---------------------------------------------------------------------------
# 0. Can this script answer at all?
# ---------------------------------------------------------------------------
[[ "$(uname -s)" == "Linux" ]] || cannot "dm-crypt verification requires Linux (found $(uname -s))"
command -v findmnt >/dev/null 2>&1 || cannot "findmnt is not installed (util-linux)"
command -v lsblk >/dev/null 2>&1 || cannot "lsblk is not installed (util-linux)"
command -v stat >/dev/null 2>&1 || cannot "stat is not installed (coreutils)"

# ---------------------------------------------------------------------------
# 1. The path exists and is a directory
# ---------------------------------------------------------------------------
[[ -e "${STATE_PATH}" ]] || fail "${STATE_PATH} does not exist"
[[ -d "${STATE_PATH}" ]] || fail "${STATE_PATH} is not a directory"

# ---------------------------------------------------------------------------
# 2. Ownership and mode
#
# Checked BEFORE the encryption check on purpose: an encrypted volume that is
# world-readable while mounted is decrypted for every local account, and the
# encryption is then protecting only the powered-off disk. Both matter, and
# this one is the more commonly wrong of the two.
# ---------------------------------------------------------------------------
ACTUAL_UID="$(stat -c '%u' "${STATE_PATH}")"
ACTUAL_GID="$(stat -c '%g' "${STATE_PATH}")"
ACTUAL_MODE="$(stat -c '%a' "${STATE_PATH}")"

[[ "${ACTUAL_UID}" == "${EXPECTED_UID}" ]] || fail "${STATE_PATH} is owned by uid ${ACTUAL_UID}, expected ${EXPECTED_UID}"
[[ "${ACTUAL_GID}" == "${EXPECTED_GID}" ]] || fail "${STATE_PATH} is owned by gid ${ACTUAL_GID}, expected ${EXPECTED_GID}"
[[ "${ACTUAL_MODE}" == "${EXPECTED_MODE}" ]] || fail "${STATE_PATH} is mode ${ACTUAL_MODE}, expected ${EXPECTED_MODE}"

# ---------------------------------------------------------------------------
# 3. It is its own mount point
#
# If the path is merely a directory on the root filesystem, then whatever is
# said about "the Edge volume" is a statement about the root filesystem. A
# dedicated mount is what makes the rest of this script meaningful.
# ---------------------------------------------------------------------------
findmnt --target "${STATE_PATH}" >/dev/null 2>&1 || fail "${STATE_PATH} is not on any mounted filesystem"

MOUNTPOINT="$(findmnt --noheadings --output TARGET --target "${STATE_PATH}" | head -1)"
[[ "${MOUNTPOINT}" == "${STATE_PATH}" ]] || \
  fail "${STATE_PATH} is not its own mount point (nearest mount is ${MOUNTPOINT}); a directory on a shared filesystem is not a dedicated Edge state volume"

SOURCE_DEVICE="$(findmnt --noheadings --output SOURCE --target "${STATE_PATH}" | head -1)"
[[ -n "${SOURCE_DEVICE}" ]] || fail "could not determine the backing device for ${STATE_PATH}"

# ---------------------------------------------------------------------------
# 4. THE ONE THAT MATTERS: the backing device is dm-crypt/LUKS
#
# Walked through lsblk rather than trusted from the device name. A device
# called `/dev/mapper/sentinel-edge-crypt` is not encrypted because of its
# name, and a preflight that pattern-matched the name would pass for anyone who
# named a plain LVM volume convincingly.
# ---------------------------------------------------------------------------
DEVICE_NAME="$(basename "${SOURCE_DEVICE}")"
DEVICE_TYPE="$(lsblk --noheadings --output TYPE "${SOURCE_DEVICE}" 2>/dev/null | head -1 | tr -d '[:space:]' || true)"

if [[ "${DEVICE_TYPE}" != "crypt" ]]; then
  # One level of indirection is legitimate: a filesystem on an LVM logical
  # volume that sits on a LUKS container. Anything deeper is not rejected
  # because it is impossible, but because an unbounded walk would eventually
  # find SOME crypt ancestor on a machine with any encrypted disk at all, and
  # report a plaintext volume as encrypted.
  PARENT_TYPES="$(lsblk --noheadings --inverse --output TYPE "${SOURCE_DEVICE}" 2>/dev/null | tr -d ' ' | head -3 || true)"
  if ! grep -qx 'crypt' <<<"${PARENT_TYPES}"; then
    fail "${STATE_PATH} is backed by ${SOURCE_DEVICE} (type '${DEVICE_TYPE:-unknown}'), which is not a dm-crypt/LUKS device. A Docker named volume or a plain partition is NOT at-rest encryption."
  fi
  note "backing device ${DEVICE_NAME} sits above a dm-crypt layer"
else
  note "backing device ${DEVICE_NAME} is dm-crypt"
fi

# ---------------------------------------------------------------------------
# 5. The key is not lying next to the lock
#
# Not exhaustive, and not meant to be. It catches the specific mistake of
# keeping a LUKS keyfile inside the very volume it unlocks, which is a
# surprisingly easy thing to do while automating an unattended boot.
# ---------------------------------------------------------------------------
if find "${STATE_PATH}" -maxdepth 2 -type f \
     \( -name '*.key' -o -name '*keyfile*' -o -name '*.luks' -o -name '*.pem' \) 2>/dev/null | grep -q .; then
  fail "key-shaped files are present inside ${STATE_PATH}; an unlock key stored in the volume it unlocks is not custody"
fi

note "PASSED - ${STATE_PATH} on ${SOURCE_DEVICE} (uid=${ACTUAL_UID} gid=${ACTUAL_GID} mode=${ACTUAL_MODE})"
note "this proves the storage boundary only. It says nothing about key custody, which is a host and TPM concern."
exit 0
