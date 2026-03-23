# LN Gossip Visualizer

Standalone dashboard and preprocessing pipeline for Lightning Network gossip replay analysis.

## Repository layout

- Python preprocessing scripts at the repo root
- Static dashboard assets in `static/`
- Raw input data in `data/raw/`
- Generated frontend JSON in `static/data/`
- Manual community analysis notes in `data/notes.md`

## Expected data layout

```text
.
├── data/
│   ├── notes.md
│   └── raw/
│       ├── node_lists/
│       │   └── full_node_list.txt
│       └── gossip_archives/
│           └── dump_0926T195046/
│               ├── timings.parquet/
│               ├── metadata.parquet/
│               └── messages.parquet/
├── static/
│   └── data/
├── preprocess.py
├── inspect_raw.py
├── geolocate.py
└── server.py
```

`full_node_list.txt` is JSON despite the `.txt` extension.

## Quick start

1. Install dependencies from `pyproject.toml`.
2. Place the raw exports in `data/raw/` using the layout above.
3. Run `preprocess.py` to regenerate `static/data/*.json`.
4. Run `server.py` and open the local dashboard.

## Scripts

- `preprocess.py` — builds the dashboard JSON from parquet + node list data
- `inspect_raw.py` — inspects raw gossip payloads for feature fingerprints
- `geolocate.py` — enriches `peers.json` with GeoIP metadata
- `server.py` — serves the static dashboard locally

## Current note

The node list and community notes are already included in this standalone repo. The parquet export still needs to be restored into `data/raw/gossip_archives/dump_0926T195046/` before preprocessing can be run end-to-end.