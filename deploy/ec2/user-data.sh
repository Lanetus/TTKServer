#!/bin/bash
# EC2 user data that turns a fresh Amazon Linux instance into a TTKServer parent instance: it
# installs the Nitro Enclaves tooling, downloads the EIF, the `vsock-proxy` binary and the systemd units
# from an HTTP server, and starts the enclave and the proxy (both also start on every reboot).
# With TTK_NODE=s3-server it also installs `vsock-proxy-tcp`, through which the enclave reaches
# the S3 endpoint of TTK_S3_REGION, and a second instance of it (vsock-proxy-imds) through which
# the enclave gets the instance role's credentials from the instance metadata service.
# TTK_NODE=echo runs the echo terminal (replies with each decrypted /faf message; no S3).
#
# Launch the instance with:
#   - Amazon Linux 2023 (or Amazon Linux 2), on an enclave-capable type with at least 4 vCPUs
#     (e.g. m6i.xlarge / c6g.xlarge); the AMI's architecture must match the EIF and vsock-proxy.
#   - Nitro Enclaves enabled (console: Advanced details > Nitro Enclave; CLI:
#     `--enclave-options Enabled=true`).
#   - A security group allowing inbound UDP 443.
#   - This file as user data, with TTK_BASE_URL (and ideally the SHA-256 values) filled in.
#   - s3-server: an EIF built for the bucket's region (scripts/build-eif.sh with TTK_S3_BUCKET /
#     AWS_REGION), and TTK_S3_REGION below set to that region; an instance profile whose role
#     can read and write the bucket (scope it to the bucket: the parent holds these credentials).
#
# The HTTP server must serve, under TTK_BASE_URL:
#   ttk-<node>.eif              scripts/build-eif.sh output (out/ttk-<node>_v<ver>_<arch>.eif)
#   vsock-proxy                 target/release/vsock-proxy, built for Linux on the same architecture
#   vsock-proxy.service         deploy/systemd/vsock-proxy.service
#   ttk-<node>-enclave.service  deploy/systemd/ttk-<node>-enclave.service
#                               (s3-server and echo run under ttk-terminal-enclave.service)
#   vsock-proxy-tcp             s3-server only: target/release/vsock-proxy-tcp, like vsock-proxy
#   vsock-proxy-tcp.service     s3-server only: deploy/systemd/vsock-proxy-tcp.service
#   vsock-proxy-imds.service    s3-server only: deploy/systemd/vsock-proxy-imds.service
#
# The node then serves only POST /evidence and POST /certificate until a CA installs a
# certificate for it (after every enclave restart: the RA-TLS key is ephemeral); the node trusts
# only the TTK root CA built into the binary. Authorize root nodes before the nodes fetching from them.
#
# Progress: /var/log/ttk-user-data.log (also /var/log/cloud-init-output.log).
# Afterwards: nitro-cli describe-enclaves; journalctl -u ttk-<node>-enclave -u vsock-proxy
#             (echo: journalctl -u ttk-terminal-enclave -u vsock-proxy)
#             (s3-server: journalctl -u ttk-terminal-enclave -u vsock-proxy -u vsock-proxy-tcp
#              -u vsock-proxy-imds)
set -euo pipefail

# ---- Configuration ----------------------------------------------------------------------------
TTK_BASE_URL="https://aptrepo.move.ai/ttkserver"   # no trailing slash
TTK_NODE=s3-server                # enclave node to run: relay, s3-server or echo (<node> above)
# SHA-256 of the downloads; leave empty to skip the check (not recommended over plain HTTP).
TTK_EIF_SHA256=""
TTK_VSOCK_PROXY_SHA256=""
TTK_VSOCK_PROXY_TCP_SHA256=""   # s3-server only

TTK_ENCLAVE_CID=16
TTK_ENCLAVE_CPUS=2
TTK_ENCLAVE_MEMORY=4096       # MiB; at least 4096 (worst case of the server's request limits); raise it if nitro-cli reports the EIF needs more
TTK_ENCLAVE_EXTRA_ARGS=""     # e.g. --debug-mode (debug only: zeroes PCRs)
TTK_RELAY_LISTEN=0.0.0.0:443

# s3-server only: the bucket's region (must match the AWS_REGION baked into the EIF), the S3
# endpoint vsock-proxy-tcp forwards to, and its vsock port (must match TTK_S3_VSOCK_PORT in the EIF).
TTK_S3_REGION=eu-south-1
TTK_S3_REMOTE="s3.$TTK_S3_REGION.amazonaws.com:443"
TTK_TCP_VSOCK_PORT=8001
# s3-server only: vsock port of the instance metadata proxy (must match TTK_IMDS_VSOCK_PORT in the EIF).
TTK_IMDS_VSOCK_PORT=8002
# -----------------------------------------------------------------------------------------------

exec > >(tee -a /var/log/ttk-user-data.log) 2>&1
echo "==> TTKServer user data starting at $(date -Is)"

# s3-server and echo are terminal nodes: they run under the terminal's enclave unit; s3-server
# also needs the TCP proxy to S3 alongside the UDP one.
case "$TTK_NODE" in
    relay) enclave_unit="ttk-$TTK_NODE-enclave"; with_s3=0 ;;
    s3-server) enclave_unit=ttk-terminal-enclave; with_s3=1 ;;
    echo) enclave_unit=ttk-terminal-enclave; with_s3=0 ;;
    *)
        echo "error: unknown TTK_NODE '$TTK_NODE' (expected relay, s3-server or echo)" >&2
        exit 1
        ;;
esac

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
download "ttk-$TTK_NODE.eif" "/opt/ttkserver/ttk-$TTK_NODE.eif.dl" 0644 eif
verify "/opt/ttkserver/ttk-$TTK_NODE.eif.dl" "$TTK_EIF_SHA256"
mv -f "/opt/ttkserver/ttk-$TTK_NODE.eif.dl" "/opt/ttkserver/ttk-$TTK_NODE.eif"

download vsock-proxy /usr/local/bin/vsock-proxy.dl 0755 elf
verify /usr/local/bin/vsock-proxy.dl "$TTK_VSOCK_PROXY_SHA256"
mv -f /usr/local/bin/vsock-proxy.dl /usr/local/bin/vsock-proxy

if [ "$with_s3" = 1 ]; then
    download vsock-proxy-tcp /usr/local/bin/vsock-proxy-tcp.dl 0755 elf
    verify /usr/local/bin/vsock-proxy-tcp.dl "$TTK_VSOCK_PROXY_TCP_SHA256"
    mv -f /usr/local/bin/vsock-proxy-tcp.dl /usr/local/bin/vsock-proxy-tcp
    download vsock-proxy-tcp.service /etc/systemd/system/vsock-proxy-tcp.service 0644 unit
    download vsock-proxy-imds.service /etc/systemd/system/vsock-proxy-imds.service 0644 unit
fi

download "$enclave_unit.service" "/etc/systemd/system/$enclave_unit.service" 0644 unit
download vsock-proxy.service /etc/systemd/system/vsock-proxy.service 0644 unit

echo "==> Writing unit configuration"
cat > "/etc/default/$enclave_unit" << EOF
TTK_EIF=/opt/ttkserver/ttk-$TTK_NODE.eif
TTK_ENCLAVE_NAME=ttk-$TTK_NODE
TTK_ENCLAVE_CID=$TTK_ENCLAVE_CID
TTK_ENCLAVE_CPUS=$TTK_ENCLAVE_CPUS
TTK_ENCLAVE_MEMORY=$TTK_ENCLAVE_MEMORY
TTK_ENCLAVE_EXTRA_ARGS=$TTK_ENCLAVE_EXTRA_ARGS
EOF
cat > /etc/default/vsock-proxy << EOF
TTK_ENCLAVE_CID=$TTK_ENCLAVE_CID
TTK_RELAY_LISTEN=$TTK_RELAY_LISTEN
RUST_LOG=info
EOF
if [ "$with_s3" = 1 ]; then
    cat > /etc/default/vsock-proxy-tcp << EOF
TTK_ENCLAVE_CID=$TTK_ENCLAVE_CID
TTK_TCP_REMOTE=$TTK_S3_REMOTE
TTK_TCP_VSOCK_PORT=$TTK_TCP_VSOCK_PORT
RUST_LOG=info
EOF
    cat > /etc/default/vsock-proxy-imds << EOF
TTK_ENCLAVE_CID=$TTK_ENCLAVE_CID
TTK_TCP_VSOCK_PORT=$TTK_IMDS_VSOCK_PORT
RUST_LOG=info
EOF
fi

echo "==> Starting the enclave and the vsock proxies"
systemctl daemon-reload
# The TCP proxies first, so S3 and its credentials are reachable as soon as the enclave starts.
if [ "$with_s3" = 1 ]; then
    systemctl enable --now vsock-proxy-tcp.service vsock-proxy-imds.service
fi
systemctl enable --now "$enclave_unit.service"
systemctl enable --now vsock-proxy.service

nitro-cli describe-enclaves
echo "==> TTKServer user data finished at $(date -Is)"
