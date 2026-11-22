# Pinned upstream sources shared by bench.sh and e2e.sh. Source after setting $root.
# fastcrypto must be checked out at .upstream/fastcrypto: its patched benchmark includes
# chunked16/src/lib.rs through a relative #[path].

export RUSTUP_TOOLCHAIN=1.98.0
upstream="$root/.upstream"

fetch_upstream() {
    local name=$1 remote=$2 revision=$3
    local checkout="$upstream/$name"
    if [[ -e "$checkout" ]]; then
        if [[ $(git -C "$checkout" rev-parse HEAD) == "$revision" ]] &&
            git -C "$checkout" apply --reverse --check "$root/patches/$name.patch"; then
            return
        fi
        printf 'Existing upstream checkout does not match the pinned patch: %s\n' "$checkout" >&2
        return 1
    fi
    mkdir -p "$upstream"
    git init -q "$checkout"
    git -C "$checkout" fetch -q --depth=1 "$remote" "$revision"
    git -C "$checkout" checkout -q --detach FETCH_HEAD
    git -C "$checkout" apply "$root/patches/$name.patch"
}

fetch_zk_elgamal_proof() {
    fetch_upstream zk-elgamal-proof https://github.com/solana-program/zk-elgamal-proof.git \
        caebf47f7af8d59b24280d67c8728272d753cd46
}

fetch_fastcrypto() {
    fetch_upstream fastcrypto https://github.com/MystenLabs/fastcrypto.git \
        2a17486674e2173e5ee4ce3f790850f0e45c222c
}
