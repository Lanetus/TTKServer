#!/usr/bin/env sh
# Builds a TTKServer Nitro Enclave image file (EIF) locally with Docker, mirroring the
# "Build EIF" step of .github/workflows/main.yml, which runs this script.
#
# Usage: scripts/build-eif.sh [amd64|arm64] [relay|s3-server|root|echo]
#        (defaults: this machine's architecture, and the relay node)
#
# s3-server (a terminal storing files in S3) needs TTK_S3_BUCKET and AWS_REGION, which are baked
# into the image (so they are part of the measurements); TTK_S3_VSOCK_PORT (default 8001) must
# match the parent's vsock-proxy-tcp, and TTK_IMDS_VSOCK_PORT (default 8002; empty = no instance
# role credentials) the parent's vsock-proxy-imds.
#
# echo is a terminal replying to each /faf message with the decrypted message unchanged (for
# testing a route end to end); it needs no extra configuration.
#
# TTK_DEBUG=1 builds a debug image (suffix _debug): RUST_LOG=info and
# TTK_ALLOW_MOCK_ATTESTATION=1 baked in, for running with `nitro-cli run-enclave --debug-mode`
# and reading logs with `nitro-cli console`. Never deploy it for production, and never add its
# PCR0 to an image allowlist (it accepts mock next hops).
#
# Builds are reproducible: the same commit, architecture, node and build arguments give the same
# PCR0. Base images and nitro-cli are pinned (see the Dockerfile and below), and file timestamps
# are set to SOURCE_DATE_EPOCH (default: the commit time of HEAD).
#
# TTK_EIF_SIGNING_CERT and TTK_EIF_SIGNING_KEY (both or neither; PEM files) sign the EIF, which
# adds PCR8 (the SHA-384 of the signing certificate) to the measurements; the root servers are
# pinned by PCR8. Debug images are never signed.
#
# Output: out/ttk-<node>_v<version>_<arch>.eif and .json (nitro-cli's measurements: PCR0-2, and
# PCR8 if signed; the reference values a Verifier appraises the enclave's evidence against).
#
# Needs only Docker (with buildx). nitro-cli runs in an Amazon Linux container that reaches the
# host's Docker daemon through its socket. Building for another architecture uses emulation and
# is slow.
set -eu

cd "$(dirname "$0")/.."

case "${1:-$(uname -m)}" in
    amd64 | x86_64) arch=amd64 ;;
    arm64 | aarch64) arch=arm64 ;;
    -h | --help)
        sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "error: unknown architecture '$1' (expected amd64 or arm64)" >&2
        exit 2
        ;;
esac
platform="linux/$arch"

case "${2:-relay}" in
    relay | s3-server | root | echo) node="${2:-relay}" ;;
    *)
        echo "error: unknown node '$2' (expected relay, s3-server, root or echo)" >&2
        exit 2
        ;;
esac

node_args=""
if [ "$node" = s3-server ]; then
    if [ -z "${TTK_S3_BUCKET:-}" ] || [ -z "${AWS_REGION:-}" ]; then
        echo "error: s3-server needs TTK_S3_BUCKET and AWS_REGION" >&2
        exit 2
    fi
    node_args="--build-arg TTK_S3_BUCKET=$TTK_S3_BUCKET --build-arg AWS_REGION=$AWS_REGION"
    node_args="$node_args --build-arg TTK_S3_VSOCK_PORT=${TTK_S3_VSOCK_PORT:-8001}"
    node_args="$node_args --build-arg TTK_IMDS_VSOCK_PORT=${TTK_IMDS_VSOCK_PORT-8002}"
fi

version=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n 1)
name="ttk-${node}_v${version}_${arch}"
debug_args=""
if [ "${TTK_DEBUG:-0}" = 1 ]; then
    name="${name}_debug"
    debug_args="--build-arg RUST_LOG=info --build-arg TTK_ALLOW_MOCK_ATTESTATION=1"
fi

# Prints the absolute path of file $1.
abs_path() {
    printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")"
}

sign_mounts=""
sign_args=""
if [ -n "${TTK_EIF_SIGNING_CERT:-}" ] || [ -n "${TTK_EIF_SIGNING_KEY:-}" ]; then
    if [ -z "${TTK_EIF_SIGNING_CERT:-}" ] || [ -z "${TTK_EIF_SIGNING_KEY:-}" ]; then
        echo "error: set both TTK_EIF_SIGNING_CERT and TTK_EIF_SIGNING_KEY, or neither" >&2
        exit 2
    fi
    if [ "${TTK_DEBUG:-0}" = 1 ]; then
        echo "error: debug images are never signed" >&2
        exit 2
    fi
    for file in "$TTK_EIF_SIGNING_CERT" "$TTK_EIF_SIGNING_KEY"; do
        if [ ! -r "$file" ]; then
            echo "error: cannot read $file" >&2
            exit 2
        fi
    done
    sign_mounts="-v $(abs_path "$TTK_EIF_SIGNING_CERT"):/sign/cert.pem:ro"
    sign_mounts="$sign_mounts -v $(abs_path "$TTK_EIF_SIGNING_KEY"):/sign/key.pem:ro"
    sign_args="--signing-certificate /sign/cert.pem --private-key /sign/key.pem"
fi

# Timestamp of every file in the image, so that rebuilding a commit gives the same PCR0.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2> /dev/null || echo 0)
fi

app_image="ttk-$node:local-$arch"
# nitro-cli (and the kernel and init it puts into every EIF) is pinned: another version changes
# PCR0. Bump the image digest and the package version together.
nitro_cli_version=1.5.0-0.amzn2023
cli_base=amazonlinux:2023@sha256:8ed3c0a996841537f75607e7d1de2114d8150391f75792e8da9268738547e73f
cli_image="ttkserver-nitro-cli:$nitro_cli_version-$arch"

echo "==> Building app image $app_image ($platform, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
mkdir -p out
# Exported to a tarball and loaded: rewriting timestamps cannot be combined with unpacking
# straight into a containerd image store.
app_tar="out/.$name.image.tar"
# shellcheck disable=SC2086 # $debug_args and $node_args are lists of arguments
docker buildx build --platform "$platform" --build-arg NODE="$node" $debug_args $node_args \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    --output "type=docker,name=$app_image,dest=$app_tar,rewrite-timestamp=true" .
docker load -i "$app_tar"
rm -f "$app_tar"

# nitro-cli image, built once per architecture and nitro-cli version and reused on later runs.
if ! docker image inspect "$cli_image" > /dev/null 2>&1; then
    echo "==> Building nitro-cli image $cli_image"
    docker build --platform "$platform" -t "$cli_image" - << DOCKERFILE
FROM $cli_base
RUN dnf install -y aws-nitro-enclaves-cli-$nitro_cli_version \
        aws-nitro-enclaves-cli-devel-$nitro_cli_version && \
    dnf clean all && \
    mkdir -p /var/log/nitro_enclaves
DOCKERFILE
fi

echo "==> Building $name.eif"
# shellcheck disable=SC2086 # $sign_mounts and $sign_args are lists of arguments
docker run --rm --platform "$platform" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PWD/out:/out" \
    $sign_mounts \
    "$cli_image" \
    nitro-cli build-enclave \
    --docker-uri "$app_image" \
    $sign_args \
    --output-file "/out/$name.eif" > "out/$name.json"

cat "out/$name.json"
echo "==> Wrote out/$name.eif and out/$name.json"
