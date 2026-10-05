#!/bin/bash
# EC2 user data that turns a fresh Amazon Linux instance into a TTKServer parent instance: it
# installs the Nitro Enclaves tooling, downloads the EIF, the `vsock-proxy` binary and the systemd units
# from an HTTP server, and starts the enclave and the relay (both also start on every reboot).
#
# Launch the instance with:
#   - Amazon Linux 2023 (or Amazon Linux 2), on an enclave-capable type with at least 4 vCPUs
#     (e.g. m6i.xlarge / c6g.xlarge); the AMI's architecture must match the EIF and the relay.
#   - Nitro Enclaves enabled (console: Advanced details > Nitro Enclave; CLI:
#     `--enclave-options Enabled=true`).
#   - A security group allowing inbound UDP 443.
#   - This file as user data, with TTK_BASE_URL (and ideally the SHA-256 values) filled in.
#
# The HTTP server must serve, under TTK_BASE_URL:
#   ttkserver.eif               scripts/build-eif.sh output (out/ttk-<relay|terminal|root>_v<ver>_<arch>.eif)
#   ttk-relay                   target/release/vsock-proxy, built for Linux on the same architecture
#   ttk-relay.service           deploy/systemd/ttk-relay.service
#   ttkserver-enclave.service   deploy/systemd/ttkserver-enclave.service
#
# Progress: /var/log/ttk-user-data.log (also /var/log/cloud-init-output.log).
# Afterwards: nitro-cli describe-enclaves; journalctl -u ttkserver-enclave -u ttk-relay
set -euo pipefail

# ---- Configuration ----------------------------------------------------------------------------
TTK_BASE_URL="https://aptrepo.move.ai/ttkserver"   # no trailing slash
# SHA-256 of the downloads; leave empty to skip the check (not recommended over plain HTTP).
TTK_EIF_SHA256=""
TTK_RELAY_SHA256=""

TTK_ENCLAVE_CID=16
TTK_ENCLAVE_CPUS=2
TTK_ENCLAVE_MEMORY=2048       # MiB; raise it if nitro-cli reports the EIF needs more
TTK_ENCLAVE_EXTRA_ARGS=""     # e.g. --debug-mode (debug only: zeroes PCRs)
TTK_RELAY_LISTEN=0.0.0.0:443
# -----------------------------------------------------------------------------------------------

exec > >(tee -a /var/log/ttk-user-data.log) 2>&1
echo "==> TTKServer user data starting at $(date -Is)"

download() { # <name> <dest> <mode> <eif|elf|unit>
    echo "==> Downloading $TTK_BASE_URL/$1"
    curl --fail --silent --show-error --location --retry 5 --retry-delay 3 --retry-all-errors \
        -o "$2.tmp" "$TTK_BASE_URL/$1"
    # A CDN may answer a missing file with an HTML error page and status 200, which --fail
    # accepts, so check that the content is what we expect.
    case "$4" in
        eif) magic=$(head -c 4 "$2.tmp") && [ "$magic" = ".eif" ] ;;
        elf) magic=$(head -c 4 "$2.tmp" | tail -c 3) && [ "$magic" = "ELF" ] ;;
        unit) grep -q '^\[Service\]' "$2.tmp" ;;
    esac || {
        echo "error: $TTK_BASE_URL/$1 is not a valid $4 file (missing on the server?):" >&2
        head -c 200 "$2.tmp" >&2
        rm -f "$2.tmp"
        exit 1
    }
    chmod "$3" "$2.tmp"
    mv -f "$2.tmp" "$2"
}

verify() { # <file> <expected sha256 or empty>
    [ -z "$2" ] && { echo "warning: no SHA-256 for $1, skipping check"; return 0; }
    echo "$2  $1" | sha256sum --check --strict -
}

echo "==> Installing Nitro Enclaves CLI"
if grep -q 'Amazon Linux 2023' /etc/os-release; then
    dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
else
    amazon-linux-extras install -y aws-nitro-enclaves-cli
    yum install -y aws-nitro-enclaves-cli-devel
fi

echo "==> Reserving $TTK_ENCLAVE_CPUS vCPUs and $TTK_ENCLAVE_MEMORY MiB for enclaves"
cat > /etc/nitro_enclaves/allocator.yaml << EOF
---
memory_mib: $TTK_ENCLAVE_MEMORY
cpu_count: $TTK_ENCLAVE_CPUS
EOF
systemctl enable nitro-enclaves-allocator.service
systemctl restart nitro-enclaves-allocator.service

mkdir -p /opt/ttkserver
download ttkserver.eif /opt/ttkserver/ttkserver.eif.dl 0644 eif
verify /opt/ttkserver/ttkserver.eif.dl "$TTK_EIF_SHA256"
mv -f /opt/ttkserver/ttkserver.eif.dl /opt/ttkserver/ttkserver.eif

download ttk-relay /usr/local/bin/ttk-relay.dl 0755 elf
verify /usr/local/bin/ttk-relay.dl "$TTK_RELAY_SHA256"
mv -f /usr/local/bin/ttk-relay.dl /usr/local/bin/ttk-relay

download ttkserver-enclave.service /etc/systemd/system/ttkserver-enclave.service 0644 unit
download ttk-relay.service /etc/systemd/system/ttk-relay.service 0644 unit

echo "==> Writing unit configuration"
cat > /etc/default/ttkserver-enclave << EOF
TTK_EIF=/opt/ttkserver/ttkserver.eif
TTK_ENCLAVE_CID=$TTK_ENCLAVE_CID
TTK_ENCLAVE_CPUS=$TTK_ENCLAVE_CPUS
TTK_ENCLAVE_MEMORY=$TTK_ENCLAVE_MEMORY
TTK_ENCLAVE_EXTRA_ARGS=$TTK_ENCLAVE_EXTRA_ARGS
EOF
cat > /etc/default/ttk-relay << EOF
TTK_ENCLAVE_CID=$TTK_ENCLAVE_CID
TTK_RELAY_LISTEN=$TTK_RELAY_LISTEN
RUST_LOG=info
EOF

echo "==> Starting the enclave and the relay"
systemctl daemon-reload
systemctl enable --now ttkserver-enclave.service
systemctl enable --now ttk-relay.service

nitro-cli describe-enclaves
echo "==> TTKServer user data finished at $(date -Is)"
