# samples/

This directory holds the raw PE binaries and zipped malware samples used as
input to [`tools/extract_features.py`](../tools/extract_features.py).

**Sample files themselves are intentionally not committed to this repo** —
publishing live malware to a public GitHub repository risks a ToS/malware
flag on the repo and puts anyone who clones it at risk. See
[`../reports/`](../reports/) for the write-ups produced from analyzing
these samples, and [`../data/binaries.json`](../data/binaries.json) for
the already-extracted structural features the agent actually consumes at
runtime.

If you have your own samples to analyze, drop them here (as `.exe` files)
and list their filenames in `target_files` in
[`tools/extract_features.py`](../tools/extract_features.py), then run it
to regenerate `data/binaries.json`. Handle any real malware you add here
in an isolated VM/sandbox — this project only performs static byte-level
analysis (see `tools/extract_features.py`), it never executes samples.
