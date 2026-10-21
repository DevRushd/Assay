#!/usr/bin/env bash
#
# Runs the Go test suite with network access removed.
#
# CONTRIBUTING.md promises "tests must not require network access". A promise
# with nothing enforcing it holds only while everyone remembers it, and it
# breaks the first time someone adds a test that reaches a live source: that
# test passes for its author, passes in CI, and then flakes for everyone else --
# or keeps passing only for as long as a third party stays up. This is the
# enforcement.
#
# Isolation is a network namespace (`unshare -n`). That is stricter than
# pointing HTTP_PROXY/HTTPS_PROXY at a closed port: a namespace has no route to
# any host, so a client is offline whether or not it honours proxy settings.
# Loopback is brought back up inside the namespace, because httptest servers
# listen on 127.0.0.1 and a test that uses httptest is offline already and must
# keep passing.
#
# Module download and compilation happen BEFORE isolation, with the network,
# because those legitimately need it. Only the tests run without it.
#
# Exit codes:
#   0  the suite passed with no network
#   1  a test failed (with the network removed, that usually means it needed it)
#   2  the isolation could not be established. That is unknown, not clean: a run
#      without isolation would pass for the wrong reason and must not be
#      reported as a success.
#
# Run it as `make offline-test`, or directly: scripts/offline-test.sh

set -u

PKG=${PKG:-./...}
RACE=${RACE:--race}

die_mechanism() {
    for line in "$@"; do
        echo "offline-test: $line" >&2
    done
    exit 2
}

# 1. Everything the isolation needs must be present. A missing tool is the
#    mechanism failing, not a test, so it is reported as such rather than
#    running the suite with the network still up.
for tool in unshare ip go; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        die_mechanism "$tool not found" \
            "it is required for the offline run; refusing to run with the network up."
    fi
done

# 2. Resolve modules and compile the test binaries. `-run '^$'` matches no test,
#    so this builds everything it needs and runs nothing.
echo "offline-test: resolving modules and compiling test binaries (network allowed)..." >&2
race_args=()
if [ -n "${RACE}" ]; then race_args=("$RACE"); fi
if ! go test "${race_args[@]}" -run '^$' "$PKG"; then
    echo "offline-test: the suite did not build" >&2
    exit 1
fi

# 3. Choose how to create the namespace: root can, a CI runner can via
#    passwordless sudo, and anyone else is told so rather than silently running
#    the tests online.
UNSHARE=()
if [ "$(id -u)" -eq 0 ]; then
    UNSHARE=(unshare -n)
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    UNSHARE=(sudo -n unshare -n)
else
    die_mechanism "cannot create a network namespace" \
        "run as root, or with passwordless sudo (CI runners have it)." \
        "refusing to run the suite with the network up, because a pass would" \
        "not prove what this check exists to prove."
fi

# 4. Enter the namespace once as a pre-flight. A failure here is the mechanism,
#    not a test.
if ! "${UNSHARE[@]}" -- true >/dev/null 2>&1; then
    die_mechanism "could not create a network namespace (unshare failed)" \
        "this is the isolation failing, not a test."
fi

# 5. Positive control: inside the namespace a TCP connection to a literal
#    address must fail. If it succeeds, the namespace did not remove the
#    network and every test below would pass for the wrong reason. `/dev/tcp`
#    is a bash feature, so the probe runs under bash.
PROBE=(bash -c 'exec 3<>/dev/tcp/1.1.1.1/443')
if command -v timeout >/dev/null 2>&1; then
    PROBE=(timeout 5 "${PROBE[@]}")
fi
if "${UNSHARE[@]}" -- "${PROBE[@]}" >/dev/null 2>&1; then
    die_mechanism "the network is still reachable inside the namespace" \
        "isolation did not take effect, so a pass would be meaningless."
fi

# 6. Run the suite with no network. Carry the Go environment across sudo so the
#    module and build caches resolved above are reused and nothing tries to
#    download inside the namespace. `go env` prints the effective values, so
#    this works whether or not they were exported.
GO_BIN=$(command -v go)
IP_BIN=$(command -v ip)
inner="$(printf '%q' "$IP_BIN") link set lo up && exec env HOME=$(printf '%q' "$HOME")"
for name in GOCACHE GOMODCACHE GOPATH GOFLAGS GOTOOLCHAIN; do
    inner="$inner $name=$(printf '%q' "$(go env "$name")")"
done
inner="$inner $(printf '%q' "$GO_BIN") test"
if [ -n "${RACE}" ]; then inner="$inner $(printf '%q' "$RACE")"; fi
inner="$inner -count=1 $(printf '%q' "$PKG")"

echo "offline-test: running $PKG with network access removed..." >&2
"${UNSHARE[@]}" -- bash -c "$inner"
