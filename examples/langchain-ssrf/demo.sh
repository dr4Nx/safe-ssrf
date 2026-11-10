#!/bin/sh
set -eu

demo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
safe_egress_root=$(CDPATH= cd -- "$demo_dir/../.." && pwd)
community_dir="$safe_egress_root/../ssrf-study/checkout/libs/community"

if [ ! -d "$community_dir" ]; then
    echo "LangChain checkout not found: $community_dir" >&2
    exit 2
fi

cd "$community_dir"
PYTHONPATH="$safe_egress_root/src:$demo_dir${PYTHONPATH:+:$PYTHONPATH}" \
    poetry run python "$demo_dir/interactive_demo.py" "$@"
