Implemented: word-diff plain/porcelain/none, color-words→plain, word-diff-regex, color/no-color, -C copies, diff-filter, text/no-text, -b/-w/blank-lines/space-at-eol, inter-hunk-context, src/dst/line-prefix, shortstat/numstat/summary/raw (+Bin lines), no-patch, quiet (exit 1), output, relative, no-index files (in-repo).
Named-gap (loud Unsupported): minimal/patience/histogram, -W, binary, exit-code, color-moved.
Deviations: no-index exits 0 with output (oracle: 1); out-of-repo --no-index blocked by mandatory discovery; quiet-dirty adds a stderr line for exit 1.
