#!/usr/bin/env sh
# Builds a TTKServer Nitro Enclave image file (EIF) locally with Docker, mirroring the
# "Build EIF" steps of .github/workflows/build.yml.
#
# Usage: scripts/build-eif.sh [amd64|arm64] [relay|terminal|root]
#        (defaults: this machine's architecture, and the relay node)
#
# TTK_DEBUG=1 builds a debug image (suffix _debug): RUST_LOG=info and
# TTK_ALLOW_MOCK_ATTESTATION=1 baked in, for running with `nitro-cli run-enclave --debug-mode`
# and reading logs with `nitro-cli console`. Never deploy it for production.
#
# Output: out/ttk-<node>_v<version>_<arch>.eif and .json (nitro-cli's measurements: PCR0-2,
# the reference values a Verifier appraises the enclave's evidence against).
#
# Needs only Docker. nitro-cli runs in an Amazon Linux container that reaches the host's Docker
# daemon through its socket. Building for another architecture uses emulation and is slow.
set -eu

cd "$(dirname "$0")/.."

case "${1:-$(uname -m)}" in
    amd64 | x86_64) arch=amd64 ;;
    arm64 | aarch64) arch=arm64 ;;
    -h | --help)
        sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "error: unknown architecture '$1' (expected amd64 or arm64)" >&2
        exit 2
        ;;
esac
platform="linux/$arch"

case "${2:-relay}" in
    relay | terminal | root) node="${2:-relay}" ;;
    *)
        echo "error: unknown node '$2' (expected relay, terminal or root)" >&2
        exit 2
        ;;
esac

version=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n 1)
name="ttk-${node}_v${version}_${arch}"
debug_args=""
if [ "${TTK_DEBUG:-0}" = 1 ]; then
    name="${name}_debug"
    debug_args="--build-arg RUST_LOG=info --build-arg TTK_ALLOW_MOCK_ATTESTATION=1"
fi
app_image="ttk-$node:local-$arch"
cli_image="ttkserver-nitro-cli:$arch"

echo "==> Building app image $app_image ($platform)"
# shellcheck disable=SC2086 # $debug_args is a list of arguments
docker build --platform "$platform" --build-arg NODE="$node" $debug_args -t "$app_image" .

# nitro-cli image, built once per architecture and reused on later runs.
if ! docker image inspect "$cli_image" > /dev/null 2>&1; then
    echo "==> Building nitro-cli image $cli_image"
    docker build --platform "$platform" -t "$cli_image" - << 'EOF'
FROM amazonlinux:2023
RUN dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel && \
    dnf clean all && \
    mkdir -p /var/log/nitro_enclaves
EOF
fi

echo "==> Building $name.eif"
mkdir -p out
docker run --rm --platform "$platform" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PWD/out:/out" \
    "$cli_image" \
    nitro-cli build-enclave \
    --docker-uri "$app_image" \
    --output-file "/out/$name.eif" > "out/$name.json"

cat "out/$name.json"
echo "==> Wrote out/$name.eif and out/$name.json"
