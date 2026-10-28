#!/bin/bash
set +x
set -euo pipefail

usage() {
    printf 'Usage: %s --item ITEM [--vault VAULT] -- CLI_ARGUMENTS...\n' "$0"
}

fail() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

item=''
op_args=(item get --fields label=username,label=password --format json --reveal)
while (($#)); do
    case "$1" in
        --item)
            [[ $# -ge 2 && -n "$2" ]] || fail '--item requires a non-empty value'
            item=$2
            shift 2
            ;;
        --vault)
            [[ $# -ge 2 && -n "$2" ]] || fail '--vault requires a non-empty value'
            op_args+=(--vault "$2")
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *) fail 'expected --item, --vault, or -- before CLI arguments' ;;
    esac
done
[[ -n "$item" && $# -gt 0 ]] || { usage >&2; exit 2; }

for command in op jq netgear-cm500-cli; do
    command -v "$command" >/dev/null || fail "required command not found: $command"
done

fields=$(op "${op_args[@]}" -- "$item" </dev/null 2>/dev/null) ||
    fail 'failed to resolve credentials from 1Password item'

credential() {
    printf '%s' "$fields" | jq -erj --arg label "$1" '
        if type != "array" then error("invalid fields") else . end
        | map(select(.label == $label))
        | if length != 1 then error("ambiguous field") else .[0].value end
        | if type != "string" then error("invalid value") else . end
        | if length == 0 or contains("\u0000") then error("invalid value") else . end
    ' 2>/dev/null && printf '.'
}

# The suffix preserves trailing newlines through shell command substitution.
username=$(credential username) || fail 'item needs exactly one non-empty username'
password=$(credential password) || fail 'item needs exactly one non-empty password'
CM500_USER=${username%.}
CM500_PASS=${password%.}
export CM500_USER CM500_PASS
unset fields username password
exec netgear-cm500-cli "$@"
