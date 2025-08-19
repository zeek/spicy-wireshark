#! /bin/sh

git_describe() {
    git describe --dirty --always --match 'v[0-9]*' | sed -e 's/^v\(.*\)/\1/'
}

update_version() {
    out="$1"
    tmp="$(mktemp "${out}.XXXXXX")"
    trap 'rm -f "${tmp}"' EXIT

    printf '#define PLUGIN_VERSION_NUMBER "' >>"${tmp}"
    printf '%s"' "$(git_describe)" >>"${tmp}"

    if ! cmp "${tmp}" "${out}" >/dev/null 2>&1; then
        cp -f "${tmp}" "${out}"
    fi
}

usage() {
    echo "Usage: $0 --print | --update <target-file.h>" >&2
    exit 1
}

if [ ! -d .git ]; then
    echo "Not inside a git repository; cannot determine version." >&2
    exit 1
fi

# Test if git binary is available
if ! command -v git >/dev/null 2>&1; then
    echo "Git is not installed or not in PATH; cannot determine version." >&2
    exit 1
fi

case "$1" in
    --print)
        git_describe
        ;;
    --update)
        test "$#" != 2 && usage
        update_version "$2"
        ;;
    *)
        usage
        ;;
esac
