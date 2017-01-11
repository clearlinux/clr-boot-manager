#!/bin/bash
set -e
clang-format -i $(find . -not -path '*/libnica/*' -name '*.[ch]')

# Check we have no typos.
which misspell 2>/dev/null >/dev/null
if [[ $? -eq 0 ]]; then
    misspell -error `find . -name '*.[ch]'`
fi
