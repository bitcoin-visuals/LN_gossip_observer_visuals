#!/usr/bin/env python3
"""
LN Gossip Visualizer — Data Preprocessor

Reads the exported parquet data + node list, computes:
1. Per-peer "first responder" scores (how early they typically relay gossip)
2. Per-message propagation sequences (arrival order for animation)
3. Peer → IP → GeoIP enrichment
4. Community assignments from SBM analysis

Outputs static JSON files consumed by the browser frontend.
"""

import json
import os
import time
import urllib.request
from ipaddress import ip_address
from pathlib import Path

import polars as pl

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PARQUET_DIR = RAW_DATA_DIR / "gossip_archives" / "dump_0926T195046"
NODE_LIST_FILE = RAW_DATA_DIR / "node_lists" / "full_node_list.txt"
NOTES_FILE = DATA_DIR / "notes.md"
OUTPUT_DIR = BASE_DIR / "static" / "data"
PEERS_OUTPUT_FILE = OUTPUT_DIR / "peers.json"
WAVEFRONTS_DIR = OUTPUT_DIR / "wavefronts"

# Message types
MSG_TYPES = {1: "channel_announcement", 2: "node_announcement", 3: "channel_update"}

# Community assignments from SBM analysis (Level 1, weighted)
# Extracted from data/notes.md manual analysis
COMMUNITY_LABELS = {
    "downtown_core": {
        "label": "Downtown / Core",
        "color": "#e63946",
        "description": "ACINQ, Bitrefill, Block, Kraken, bfx, LNBiG, Strike, OpenNode, okx",
    },
    "midtown": {
        "label": "Midtown",
        "color": "#457b9d",
        "description": "1ML, CoinGate, WalletOfSatoshi, Mullvad, Blocktank, jb55",
    },
    "brooklyn": {
        "label": "Brooklyn",
        "color": "#2a9d8f",
        "description": "LOOP, IBEX, BCash_Is_Trash, Noones, Bipa, El Salvador",
    },
    "les_voltage": {
        "label": "Lower East Side",
        "color": "#e9c46a",
        "description": "Voltage, nerdminerstore, coinos",
    },
    "lic_mempool": {
        "label": "Long Island City",
        "color": "#f4a261",
        "description": "lnrouter, mempool.space, Einundzwanzig",
    },
    "suburbs": {
        "label": "Suburbs",
        "color": "#8d99ae",
        "description": "Low-degree nodes, Start9, Alby Hub",
    },
    "lnt_periphery": {
        "label": "LNT Periphery",
        "color": "#6d6875",
        "description": "BTCLNT project (~2000 nodes), LNT.chengdu, LNT.Thailand",
    },
    "jersey_business": {
        "label": "Jersey City / Business",
        "color": "#b5838d",
        "description": "Team Corn (Korean), River, Zap, Bitnob, Binance",
    },
    "unknown": {
        "label": "Unknown",
        "color": "#adb5bd",
        "description": "Not classified",
    },
}

# Known hub nodes → community mapping (from notes.md manual analysis)
KNOWN_HUBS = {
    # Downtown Core
    "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f": "downtown_core",  # ACINQ
    "030c3f19d742ca294a55c00376b3b355c3c90d61c6b6b39554dbc7ac19b141c14f": "downtown_core",  # Bitrefill
    "027100442c3b79f606f80f322d98d499eefcb060599efc5d4ecb00209c2cb54190": "downtown_core",  # block-iad-1
    "02f1a8c87607f415c8f22c00593002775941dea48869ce23096af27b0cfdcc0b69": "downtown_core",  # Kraken
    "033d8656219478701227199cbd6f670335c8d408a92ae88b962c49d4dc0e83e025": "downtown_core",  # bfx-lnd0
    "034ea80f8b148c750463546bd999bf7321a0e6dfc60aaf84bd0400a2e8d376c0d5": "downtown_core",  # LNBiG
    "03abf6f44c355dec0d5aa155bdbdd6e0c8fefe318eff402de65c6eb2e1be55dc3e": "downtown_core",  # OpenNode
    # Midtown
    "0217890e3aad8d35bc054f43acc00084b25229ecff0ab68debd82883ad65ee8266": "midtown",  # 1ML
    "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3": "midtown",  # CoinGate
    "035e4ff418fc8b5554c5d9eea66396c227bd429a3251c8cbc711002ba215bfc226": "midtown",  # WalletOfSatoshi
    # Brooklyn
    "021c97a90a411ff2b10dc2a8e32de2f29d2fa49d41bfbb52bd416e460db0747d0d": "brooklyn",  # LOOP
    "0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f": "brooklyn",  # BCash_Is_Trash
    # LES / Voltage
    # LIC / Mempool
    # LNT Periphery
    "03ccc570ec6aaff08d5435b3413f4b4af8175728a1ed244e4710121c8f5af6ea07": "lnt_periphery",  # LNT.Thailand
    # Jersey / Business
    "03a1f3afd646d77bdaf545cceaf079bab6057eae52c6319b63b5803d0989d6a72f": "jersey_business",  # Binance
}


def is_clearnet(addr: str) -> bool:
    """Check if address is a clearnet IP."""
    try:
        if addr.startswith("["):
            idx = addr.rfind("]")
            if idx != -1:
                addr = addr[1:idx]
        else:
            idx = addr.rfind(":")
            if idx != -1:
                addr = addr[:idx]
        ip_address(addr)
        return True
    except ValueError:
        return False


def extract_ip(addr: str) -> str | None:
    """Extract IP from address:port string."""
    try:
        if addr.startswith("["):
            idx = addr.rfind("]")
            if idx != -1:
                return addr[1:idx]
        else:
            idx = addr.rfind(":")
            if idx != -1:
                return addr[:idx]
    except Exception:
        pass
    return None


def load_nodes() -> dict:
    """Load node list and build pubkey → node info map."""
    with open(NODE_LIST_FILE) as f:
        nodes = json.load(f)

    node_map = {}
    for n in nodes:
        pubkey = n["pubkey"]
        info = n.get("info", {})
        addresses = info.get("addresses", []) if info else []
        alias = info.get("alias", "") if info else ""

        clearnet_ip = None
        for addr in addresses:
            if is_clearnet(addr):
                clearnet_ip = extract_ip(addr)
                break

        node_map[pubkey] = {
            "alias": alias,
            "addresses": addresses,
            "clearnet_ip": clearnet_ip,
            "is_tor_only": all("onion" in a for a in addresses) if addresses else True,
        }
    return node_map


def geolocate_ips(ips: list[str], batch_size: int = 100, pause_seconds: float = 1.5) -> dict[str, dict]:
    """Resolve clearnet IPs via ip-api batch endpoint.

    Returns {ip: {lat, lon, country, city, isp, as_info}}.
    """
    if not ips:
        return {}

    url = "http://ip-api.com/batch"
    results: dict[str, dict] = {}
    for start in range(0, len(ips), batch_size):
        batch = ips[start:start + batch_size]
        payload = json.dumps([
            {"query": ip, "fields": "query,status,lat,lon,country,city,isp,as"}
            for ip in batch
        ]).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                batch_results = json.loads(resp.read())
        except Exception as exc:
            print(f"    Geolocation batch failed for {len(batch)} IPs: {exc}")
            batch_results = []

        for row in batch_results:
            if row.get("status") != "success":
                continue
            results[row["query"]] = {
                "lat": row.get("lat"),
                "lon": row.get("lon"),
                "country": row.get("country", ""),
                "city": row.get("city", ""),
                "isp": row.get("isp", ""),
                "as_info": row.get("as", ""),
            }

        if start + batch_size < len(ips):
            time.sleep(pause_seconds)

    return results


def load_existing_geo_cache() -> tuple[dict[str, dict], dict[str, dict]]:
    """Load reusable geo data from the current/generated peers output if present.

    Returns:
    - pubkey_geo: {pubkey: geo_fields}
    - ip_geo: {ip: geo_fields}
    """
    if not PEERS_OUTPUT_FILE.exists():
        return {}, {}

    try:
        existing = json.loads(PEERS_OUTPUT_FILE.read_text())
    except Exception as exc:
        print(f"  Warning: unable to read existing peers cache: {exc}")
        return {}, {}

    pubkey_geo: dict[str, dict] = {}
    ip_geo: dict[str, dict] = {}
    geo_fields = ("lat", "lon", "country", "city", "isp", "as_info")

    for pubkey, row in existing.items():
        geo = {field: row.get(field) for field in geo_fields}
        has_coords = isinstance(geo.get("lat"), (int, float)) and isinstance(geo.get("lon"), (int, float))
        if not has_coords:
            continue
        pubkey_geo[pubkey] = geo
        ip = row.get("ip")
        if ip:
            ip_geo[ip] = geo

    return pubkey_geo, ip_geo


def validate_inputs() -> None:
    """Fail fast with a clear message when the standalone data layout is incomplete."""
    required_paths = [
        (PARQUET_DIR / "timings.parquet", "timings parquet dataset"),
        (PARQUET_DIR / "metadata.parquet", "metadata parquet dataset"),
        (NODE_LIST_FILE, "full node list export"),
    ]

    missing = [f"- {label}: {path}" for path, label in required_paths if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing required standalone tomography inputs:\n"
            + "\n".join(missing)
            + "\n\nExpected layout under gossip_tomography/data/raw/."
        )


def compute_first_responder_scores(timings: pl.LazyFrame) -> pl.DataFrame:
    """
    For each message, compute each peer's arrival percentile (0.0 = first, 1.0 = last).
    Then average across all messages to get a per-peer "first responder" score.

    Lower score = consistently early = topologically central or well-connected.
    """
    print("  Computing per-message arrival ranks...")
    t0 = time.time()

    # For each message: compute rank of each peer by recv_timestamp
    ranked = timings.with_columns(
        pl.col("recv_timestamp")
        .rank("ordinal")
        .over("hash")
        .alias("arrival_rank"),
        pl.col("recv_timestamp")
        .count()
        .over("hash")
        .alias("total_peers_for_msg"),
    ).with_columns(
        ((pl.col("arrival_rank") - 1) / (pl.col("total_peers_for_msg") - 1).clip(lower_bound=1))
        .alias("arrival_percentile")
    )

    # Average percentile per peer across all messages
    print("  Aggregating per-peer scores...")
    t0 = time.time()
    scores = ranked.group_by("recv_peer").agg(
        pl.col("arrival_percentile").mean().alias("avg_arrival_pct"),
        pl.col("arrival_percentile").median().alias("median_arrival_pct"),
        pl.col("arrival_percentile").std().alias("std_arrival_pct"),
        pl.len().alias("messages_seen"),
        # How often was this peer in the top 5%?
        (pl.col("arrival_percentile") < 0.05).sum().alias("top5_count"),
        # How often was this peer literally first?
        (pl.col("arrival_rank") == 1).sum().alias("first_count"),
    ).with_columns(
        (pl.col("top5_count") / pl.col("messages_seen") * 100).alias("top5_pct"),
        (pl.col("first_count") / pl.col("messages_seen") * 100).alias("first_pct"),
    ).sort("avg_arrival_pct").collect()

    print(f"    Aggregated {len(scores)} peers in {time.time()-t0:.1f}s")
    return scores


def select_interesting_messages(timings: pl.LazyFrame, metadata: pl.DataFrame, n: int = 200) -> list[int]:
    """
    Select a diverse set of interesting messages for the wavefront viewer.
    Pick messages with high peer count (well-propagated) across all types.
    """
    # Count peers per message
    msg_peer_counts = timings.group_by("hash").agg(
        pl.len().alias("peer_count"),
        pl.col("recv_timestamp").min().alias("first_seen"),
        pl.col("recv_timestamp").max().alias("last_seen"),
    ).join(
        metadata.lazy().select("hash", "type", "orig_node", "scid"),
        on="hash",
        how="left",
    ).with_columns(
        (pl.col("last_seen") - pl.col("first_seen")).dt.total_milliseconds().alias("spread_ms")
    ).filter(
        pl.col("peer_count") >= 50  # Only well-propagated messages
    ).sort("peer_count", descending=True).collect()

    selected = []
    # Take top messages per type
    per_type = n // 3
    for msg_type in [1, 2, 3]:
        type_msgs = msg_peer_counts.filter(pl.col("type") == msg_type)
        # Mix: some with highest peer count, some with widest time spread
        by_peers = type_msgs.sort("peer_count", descending=True).head(per_type // 2)
        by_spread = type_msgs.sort("spread_ms", descending=True).head(per_type // 2)
        combined = pl.concat([by_peers, by_spread]).unique(subset=["hash"])
        selected.extend(combined["hash"].head(per_type).to_list())

    return selected[:n]


def build_wavefront_data(timings: pl.LazyFrame, message_hashes: list[int]) -> dict:
    """
    For each selected message, build the arrival sequence for animation.
    """
    print(f"  Building wavefront data for {len(message_hashes)} messages...")
    t0 = time.time()

    subset = timings.filter(pl.col("hash").is_in(message_hashes)).collect()

    wavefronts = {}
    for msg_hash in message_hashes:
        msg_data = subset.filter(pl.col("hash") == msg_hash).sort("recv_timestamp")
        if len(msg_data) < 10:
            continue

        first_ts = msg_data["recv_timestamp"].min()
        arrivals = []
        for row in msg_data.iter_rows(named=True):
            delay_ms = (row["recv_timestamp"] - first_ts).total_seconds() * 1000
            arrivals.append({
                "peer": row["recv_peer"],
                "delay_ms": round(delay_ms, 2),
            })

        wavefronts[str(msg_hash)] = {
            "arrivals": arrivals,
            "total_peers": len(arrivals),
            "spread_ms": arrivals[-1]["delay_ms"] if arrivals else 0,
        }

    print(f"    Built {len(wavefronts)} wavefronts in {time.time()-t0:.1f}s")
    return wavefronts


def write_wavefront_shards(wavefronts: dict[str, dict]) -> int:
    """Write per-message wavefront detail files for on-demand frontend loading."""
    os.makedirs(WAVEFRONTS_DIR, exist_ok=True)

    for existing in WAVEFRONTS_DIR.glob("*.json"):
        existing.unlink()

    written = 0
    for msg_hash, payload in wavefronts.items():
        with open(WAVEFRONTS_DIR / f"{msg_hash}.json", "w") as f:
            json.dump(payload, f)
        written += 1

    return written


def build_peer_data(
    scores: pl.DataFrame,
    node_map: dict,
    geo_by_ip: dict[str, dict] | None = None,
    geo_by_pubkey: dict[str, dict] | None = None,
) -> dict:
    """Build the per-peer JSON data for the frontend."""
    peers = {}
    geo_by_ip = geo_by_ip or {}
    geo_by_pubkey = geo_by_pubkey or {}
    for row in scores.iter_rows(named=True):
        pubkey = row["recv_peer"]
        node_info = node_map.get(pubkey, {})
        alias = node_info.get("alias", "")
        clearnet_ip = node_info.get("clearnet_ip")
        is_tor = node_info.get("is_tor_only", True)
        geo = geo_by_ip.get(clearnet_ip or "", {}) or geo_by_pubkey.get(pubkey, {})

        # Determine community
        community = KNOWN_HUBS.get(pubkey, "unknown")

        # LNT detection by alias
        if community == "unknown" and alias:
            alias_lower = alias.lower()
            if "lnt." in alias_lower or "btclnt" in alias_lower:
                community = "lnt_periphery"

        peers[pubkey] = {
            "alias": alias or pubkey[:16] + "…",
            "ip": clearnet_ip,
            "is_tor": is_tor,
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "country": geo.get("country", ""),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", ""),
            "as_info": geo.get("as_info", ""),
            "community": community,
            "avg_arrival_pct": round(row["avg_arrival_pct"], 4),
            "median_arrival_pct": round(row["median_arrival_pct"], 4),
            "messages_seen": row["messages_seen"],
            "top5_pct": round(row["top5_pct"], 2),
            "first_pct": round(row["first_pct"], 2),
        }

    return peers


def build_message_index(metadata: pl.DataFrame, message_hashes: list[int]) -> dict:
    """Build message metadata index for the frontend."""
    subset = metadata.filter(pl.col("hash").is_in(message_hashes))
    index = {}
    for row in subset.iter_rows(named=True):
        h = str(row["hash"])
        index[h] = {
            "type": MSG_TYPES.get(row["type"], "unknown"),
            "type_id": row["type"],
            "size": row["size"],
            "orig_node": row["orig_node"],
            "scid": str(row["scid"]) if row["scid"] else None,
        }
    return index


def build_message_catalog(metadata: pl.DataFrame, timings: pl.LazyFrame, message_hashes: list[int], limit_per_type: int | None = None) -> list[dict]:
    """Build a lightweight full-scope message catalog for browsing and future message-driven context."""
    scoped = metadata.filter(pl.col("hash").is_in(message_hashes)).with_columns(
        pl.col("scid").cast(pl.Utf8).alias("scid_str")
    )

    timing_counts = timings.group_by("hash").agg(pl.len().alias("timing_rows")).collect()
    catalog = (
        scoped.lazy()
        .join(timing_counts.lazy(), on="hash", how="left")
        .with_columns(pl.col("timing_rows").fill_null(0))
        .select([
            pl.col("hash"),
            pl.col("type"),
            pl.col("size"),
            pl.col("orig_node"),
            pl.col("scid_str"),
            pl.col("timing_rows"),
        ])
        .collect()
    )

    items: list[dict] = []
    for row in catalog.iter_rows(named=True):
        items.append({
            "hash": str(row["hash"]),
            "type": MSG_TYPES.get(row["type"], "unknown"),
            "type_id": int(row["type"]),
            "size": int(row["size"] or 0),
            "orig_node": row["orig_node"],
            "scid": row["scid_str"],
            "timing_rows": int(row["timing_rows"] or 0),
            "activity_score": int((row["timing_rows"] or 0) + (row["size"] or 0)),
        })

    items.sort(key=lambda item: (item["activity_score"], item["timing_rows"], item["size"]), reverse=True)
    return items


def build_channel_scope_summary(channels: list, node_channels: dict, peers: dict, message_scope: dict) -> dict:
    """Build a compact frontend-safe summary for visible global and per-node scope counts."""
    global_visible = channels[:30]
    global_peer_keys = set()
    for item in global_visible:
        global_peer_keys.update(item.get("origin_nodes") or [])

    summary = {
        "global": {
            "message_count": int(message_scope.get("global", {}).get("message_count") or 0),
            "peer_count": int(message_scope.get("global", {}).get("peer_count") or len([pk for pk in global_peer_keys if pk in peers]) or len(peers)),
            "mapped_peer_count": int(message_scope.get("global", {}).get("mapped_peer_count") or sum(1 for pk in global_peer_keys if pk in peers and isinstance(peers[pk].get("lat"), (int, float)) and isinstance(peers[pk].get("lon"), (int, float))) or sum(1 for p in peers.values() if isinstance(p.get("lat"), (int, float)) and isinstance(p.get("lon"), (int, float)))),
            "channel_count": len(global_visible),
        },
        "nodes": {},
    }

    for pk, items in node_channels.items():
        node_scope = message_scope.get("nodes", {}).get(pk, {})
        summary["nodes"][pk] = {
            "message_count": int(node_scope.get("message_count") or 0),
            "peer_count": int(node_scope.get("peer_count") or 0),
            "mapped_peer_count": int(node_scope.get("mapped_peer_count") or 0),
            "channel_count": len(items),
        }

    return summary


def build_channel_views(metadata: pl.DataFrame, timings: pl.LazyFrame, peers: dict, limit: int = 250) -> tuple[list, dict, dict, dict]:
    """Build channel traffic summaries and node→channel associations for the frontend.

    Phase 1 association rules:
    - A channel is identified by non-null `scid`.
    - Traffic is approximated from message count and timing row count.
    - A node is associated to a channel if it originated a message for that `scid`
      or if it relayed a message tied to that `scid`.
    """
    print("  Building channel traffic views...")
    t0 = time.time()

    meta_scid = metadata.filter(pl.col("scid").is_not_null()).with_columns(
        pl.col("scid").cast(pl.Utf8).alias("scid_str")
    )

    timing_counts = timings.group_by("hash").agg(pl.len().alias("timing_rows"))
    channel_msg_stats = (
        meta_scid.lazy().join(timing_counts, on="hash", how="left")
        .with_columns(pl.col("timing_rows").fill_null(0))
        .group_by("scid_str")
        .agg(
            pl.len().alias("message_count"),
            pl.col("timing_rows").sum().alias("timing_rows"),
            pl.col("size").sum().alias("total_bytes"),
            pl.col("hash").n_unique().alias("unique_hashes"),
            pl.col("type").n_unique().alias("message_types"),
            (pl.col("type") == 1).sum().alias("channel_announcement_count"),
            (pl.col("type") == 2).sum().alias("node_announcement_count"),
            (pl.col("type") == 3).sum().alias("channel_update_count"),
            pl.col("orig_node").drop_nulls().n_unique().alias("origin_peer_count"),
            pl.col("orig_node").drop_nulls().unique().sort().alias("origin_nodes"),
        )
        .with_columns(
            (pl.col("message_count") + pl.col("timing_rows") / 1000).alias("traffic_score")
        )
        .sort(["timing_rows", "message_count", "total_bytes"], descending=[True, True, True])
    ).collect()

    top_channels = channel_msg_stats.head(limit)
    visible_scids = set(top_channels["scid_str"].to_list())

    relay_links = (
        meta_scid.lazy().select(["hash", "scid_str"])
        .join(timings.select(["hash", "recv_peer"]), on="hash", how="inner")
        .filter(pl.col("scid_str").is_in(visible_scids))
        .group_by(["recv_peer", "scid_str"])
        .agg(
            pl.len().alias("relay_events"),
            pl.col("hash").n_unique().alias("relay_messages"),
            pl.col("hash").unique().sort().alias("relay_hashes"),
        )
    ).collect()

    relay_totals = (
        meta_scid.lazy().select(["hash", "scid_str"])
        .join(timings.select(["hash", "recv_peer"]), on="hash", how="inner")
        .filter(pl.col("scid_str").is_in(visible_scids))
        .group_by("recv_peer")
        .agg(
            pl.col("hash").n_unique().alias("node_total_messages")
        )
    ).collect()

    origin_links = (
        meta_scid.lazy().filter(pl.col("orig_node").is_not_null() & pl.col("scid_str").is_in(visible_scids))
        .group_by(["orig_node", "scid_str"])
        .agg(
            pl.len().alias("origin_messages"),
            pl.col("hash").unique().sort().alias("origin_hashes"),
        )
    ).collect()

    origin_totals = (
        meta_scid.lazy().filter(pl.col("orig_node").is_not_null() & pl.col("scid_str").is_in(visible_scids))
        .group_by("orig_node")
        .agg(
            pl.col("hash").n_unique().alias("node_total_origin_messages")
        )
    ).collect()

    channel_lookup = {}
    channel_hashes_by_scid: dict[str, list[int]] = {}
    for row in top_channels.iter_rows(named=True):
        origin_nodes = [pk for pk in (row["origin_nodes"] or []) if pk]
        aliases = []
        for pk in origin_nodes[:4]:
            alias = peers.get(pk, {}).get("alias")
            aliases.append(alias or pk[:12] + "…")
        scoped_hashes = meta_scid.filter(pl.col("scid_str") == row["scid_str"])["hash"].unique().sort().to_list()
        channel_hashes_by_scid[row["scid_str"]] = scoped_hashes
        channel_lookup[row["scid_str"]] = {
            "scid": row["scid_str"],
            "message_count": int(row["message_count"] or 0),
            "timing_rows": int(row["timing_rows"] or 0),
            "traffic_score": round(float(row["traffic_score"] or 0), 2),
            "total_bytes": int(row["total_bytes"] or 0),
            "unique_hashes": int(row["unique_hashes"] or 0),
            "message_types": int(row["message_types"] or 0),
            "channel_announcement_count": int(row["channel_announcement_count"] or 0),
            "node_announcement_count": int(row["node_announcement_count"] or 0),
            "channel_update_count": int(row["channel_update_count"] or 0),
            "origin_peer_count": int(row["origin_peer_count"] or 0),
            "origin_nodes": origin_nodes,
            "origin_aliases": aliases,
        }

    node_channels: dict[str, list] = {}
    node_summary: dict[str, dict] = {}
    node_hashes: dict[str, set[int]] = {}
    message_scope = {
        "global": {
            "message_count": 0,
            "peer_count": 0,
            "mapped_peer_count": 0,
            "channel_count": 0,
            "message_hashes": [],
        },
        "nodes": {},
    }

    for row in relay_totals.iter_rows(named=True):
        pk = row["recv_peer"]
        if pk in peers:
            node_summary.setdefault(pk, {})["node_total_messages"] = int(row["node_total_messages"] or 0)

    for row in origin_totals.iter_rows(named=True):
        pk = row["orig_node"]
        if pk in peers:
            node_summary.setdefault(pk, {})["node_total_origin_messages"] = int(row["node_total_origin_messages"] or 0)

    global_message_hashes = set()
    global_peer_keys = set()
    node_peer_sets: dict[str, set[str]] = {}

    for row in relay_links.iter_rows(named=True):
        pk = row["recv_peer"]
        scid = row["scid_str"]
        if pk not in peers or scid not in channel_lookup:
            continue
        entry = {
            "scid": scid,
            "association": "relay",
            "relay_events": int(row["relay_events"] or 0),
            "relay_messages": int(row["relay_messages"] or 0),
            **node_summary.get(pk, {}),
            **channel_lookup[scid],
        }
        node_channels.setdefault(pk, []).append(entry)
        node_hashes.setdefault(pk, set()).update(row["relay_hashes"] or [])
        node_peer_sets.setdefault(pk, set()).add(pk)
        global_peer_keys.add(pk)
        global_message_hashes.update(channel_hashes_by_scid.get(scid, []))

    for row in origin_links.iter_rows(named=True):
        pk = row["orig_node"]
        scid = row["scid_str"]
        if pk not in peers or scid not in channel_lookup:
            continue
        bucket = node_channels.setdefault(pk, [])
        existing = next((item for item in bucket if item["scid"] == scid), None)
        if existing:
            existing["association"] = "origin+relay" if existing["association"] == "relay" else "origin"
            existing["origin_messages"] = int(row["origin_messages"] or 0)
        else:
            bucket.append({
                "scid": scid,
                "association": "origin",
                "origin_messages": int(row["origin_messages"] or 0),
                **node_summary.get(pk, {}),
                **channel_lookup[scid],
            })
        node_hashes.setdefault(pk, set()).update(row["origin_hashes"] or [])
        node_peer_sets.setdefault(pk, set()).add(pk)
        global_peer_keys.add(pk)
        global_message_hashes.update(channel_hashes_by_scid.get(scid, []))

    for pk, items in node_channels.items():
        items.sort(
            key=lambda item: (
                item.get("timing_rows", 0),
                item.get("message_count", 0),
                item.get("origin_messages", 0),
                item.get("relay_messages", 0),
                item.get("total_bytes", 0),
            ),
            reverse=True,
        )
        node_channels[pk] = items[:100]

    for pk, items in node_channels.items():
        scoped_hashes = sorted(node_hashes.get(pk, set()))
        message_scope["nodes"][pk] = {
            "message_count": len(scoped_hashes),
            "peer_count": len(node_peer_sets.get(pk, set())),
            "mapped_peer_count": sum(1 for node_pk in node_peer_sets.get(pk, set()) if isinstance(peers.get(node_pk, {}).get("lat"), (int, float)) and isinstance(peers.get(node_pk, {}).get("lon"), (int, float))),
            "channel_count": len(items),
        }

    top_channel_list = list(channel_lookup.values())
    message_scope["global"] = {
        "message_count": len(global_message_hashes),
        "peer_count": len(global_peer_keys),
        "mapped_peer_count": sum(1 for pk in global_peer_keys if pk in peers and isinstance(peers[pk].get("lat"), (int, float)) and isinstance(peers[pk].get("lon"), (int, float))),
        "channel_count": len(top_channel_list),
    }

    print(f"    Built {len(top_channel_list)} channel summaries and {len(node_channels)} node-channel views in {time.time()-t0:.1f}s")
    return top_channel_list, node_channels, {
        "total_channels_indexed": len(top_channel_list),
        "nodes_with_channels": len(node_channels),
    }, message_scope, sorted(global_message_hashes)


def build_colocation_suspects(peers: dict) -> list:
    """
    Build co-location signal groups using shared IPv4 /24 prefixes.

    This is a coarse signal only: shared /24 can indicate common hosting or
    operator infrastructure, but it is not proof of common control.
    """
    suspects = []

    # Group by IP /24 prefix
    ip_groups: dict[str, list] = {}
    for pubkey, info in peers.items():
        ip = info.get("ip")
        if ip:
            prefix = ".".join(ip.split(".")[:3])
            ip_groups.setdefault(prefix, []).append(pubkey)

    for prefix, group in ip_groups.items():
        if len(group) >= 2:
            suspects.append({
                "type": "same_subnet",
                "prefix": prefix + ".0/24",
                "peers": [
                    {
                        "pubkey": p,
                        "alias": peers[p]["alias"],
                        "ip": peers[p]["ip"],
                        "avg_arrival_pct": peers[p]["avg_arrival_pct"],
                    }
                    for p in group[:10]
                ],
                "count": len(group),
            })

    # Sort by group size
    suspects.sort(key=lambda x: x["count"], reverse=True)
    return suspects[:50]


def build_first_responder_leaks(peers: dict) -> list:
    """
    Identify fast-relay heuristics using fixed thresholds.

    Criteria: top5_pct > 30 and messages_seen > 10,000.
    This flags consistently early relays but does not prove surveillance.
    """
    leaks = []
    for pubkey, info in peers.items():
        if info["top5_pct"] > 30 and info["messages_seen"] > 10000:
            leaks.append({
                "pubkey": pubkey,
                "alias": info["alias"],
                "ip": info["ip"],
                "is_tor": info["is_tor"],
                "community": info["community"],
                "avg_arrival_pct": info["avg_arrival_pct"],
                "top5_pct": info["top5_pct"],
                "first_pct": info["first_pct"],
                "messages_seen": info["messages_seen"],
            })

    leaks.sort(key=lambda x: x["avg_arrival_pct"])
    return leaks


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    validate_inputs()

    print("=" * 60)
    print("  LN GOSSIP VISUALIZER — Data Preprocessor")
    print("=" * 60)

    # 1. Load raw data
    print("\n[1/8] Loading parquet data...")
    t0 = time.time()
    timings = pl.scan_parquet(str(PARQUET_DIR / "timings.parquet/"))
    metadata = pl.read_parquet(str(PARQUET_DIR / "metadata.parquet/"))
    timing_rows = timings.select(pl.len()).collect().item()
    print(f"  Loaded {timing_rows:,} timing rows, {len(metadata):,} messages in {time.time()-t0:.1f}s")

    # Filter to inbound gossip only (types 1,2,3)
    gossip_hashes = set(metadata.filter(pl.col("type").is_in([1, 2, 3]))["hash"].to_list())
    timings = timings.filter(pl.col("hash").is_in(gossip_hashes))
    filtered_rows = timings.select(pl.len()).collect().item()
    print(f"  Filtered to {filtered_rows:,} gossip timing rows")

    # 2. Load node data
    print("\n[2/7] Loading node data...")
    node_map = load_nodes()
    print(f"  Loaded {len(node_map)} nodes")

    # 3. Compute first responder scores
    print("\n[3/7] Computing first responder scores...")
    scores = compute_first_responder_scores(timings)
    print("  Top 5 fastest peers:")
    for row in scores.head(5).iter_rows(named=True):
        pubkey = row["recv_peer"]
        alias = node_map.get(pubkey, {}).get("alias", "?")
        print(f"    {alias[:30]:30s}  avg={row['avg_arrival_pct']:.3f}  top5%={row['top5_pct']:.1f}%  first={row['first_pct']:.1f}%  msgs={row['messages_seen']:,}")

    # 4. Build peer data
    print("\n[4/7] Building peer data...")
    cached_geo_by_pubkey, cached_geo_by_ip = load_existing_geo_cache()
    unique_ips = sorted({info["clearnet_ip"] for info in node_map.values() if info.get("clearnet_ip")})
    print(f"  Geolocating {len(unique_ips)} unique clearnet IPs...")
    geo_by_ip = geolocate_ips(unique_ips)
    recovered_from_cache = 0
    for ip, geo in cached_geo_by_ip.items():
        if ip not in geo_by_ip:
            geo_by_ip[ip] = geo
            recovered_from_cache += 1
    print(f"  Geolocated {len(geo_by_ip) - recovered_from_cache} IPs live, recovered {recovered_from_cache} from cache")
    peers = build_peer_data(scores, node_map, geo_by_ip, cached_geo_by_pubkey)

    # 5. Select interesting messages and build wavefronts
    print("\n[5/7] Selecting interesting messages...")
    interesting = select_interesting_messages(timings, metadata, n=200)
    print(f"  Selected {len(interesting)} messages")

    msg_index = build_message_index(metadata, interesting)
    wavefronts = build_wavefront_data(timings, interesting)

    # 6. Build channel views
    print("\n[6/8] Building channel views...")
    channels, node_channels, channel_summary, message_scope, global_message_hashes = build_channel_views(metadata, timings, peers)
    channel_scope_summary = build_channel_scope_summary(channels, node_channels, peers, message_scope)
    message_catalog = build_message_catalog(metadata, timings, global_message_hashes)

    # 7. Detect privacy leaks
    print("\n[7/8] Detecting privacy leaks...")
    colocation = build_colocation_suspects(peers)
    first_responders = build_first_responder_leaks(peers)
    print(f"  Found {len(colocation)} co-location signal groups (/24)")
    print(f"  Found {len(first_responders)} fast-relay heuristic peers")

    # 8. Write output
    print("\n[8/8] Writing output files...")

    with open(OUTPUT_DIR / "peers.json", "w") as f:
        json.dump(peers, f)
    print(f"  peers.json ({len(peers)} peers)")

    with open(OUTPUT_DIR / "wavefronts.json", "w") as f:
        json.dump(wavefronts, f)
    print(f"  wavefronts.json ({len(wavefronts)} messages)")

    shard_count = write_wavefront_shards(wavefronts)
    print(f"  wavefronts/ ({shard_count} message detail files)")

    with open(OUTPUT_DIR / "messages.json", "w") as f:
        json.dump(msg_index, f)
    print(f"  messages.json ({len(msg_index)} messages)")

    with open(OUTPUT_DIR / "message_catalog.json", "w") as f:
        json.dump(message_catalog, f)
    print(f"  message_catalog.json ({len(message_catalog)} messages)")

    with open(OUTPUT_DIR / "communities.json", "w") as f:
        json.dump(COMMUNITY_LABELS, f, indent=2)
    print("  communities.json")

    with open(OUTPUT_DIR / "channels.json", "w") as f:
        json.dump(channels, f)
    print(f"  channels.json ({len(channels)} channels)")

    with open(OUTPUT_DIR / "node_channels.json", "w") as f:
        json.dump(node_channels, f)
    print(f"  node_channels.json ({len(node_channels)} nodes with channel views)")

    with open(OUTPUT_DIR / "message_scope.json", "w") as f:
        json.dump(message_scope, f)
    print("  message_scope.json")

    with open(OUTPUT_DIR / "channel_scope_summary.json", "w") as f:
        json.dump(channel_scope_summary, f)
    print("  channel_scope_summary.json")

    with open(OUTPUT_DIR / "leaks.json", "w") as f:
        json.dump({
            "colocation": colocation,
            "first_responders": first_responders,
        }, f)
    print(f"  leaks.json ({len(colocation)} co-location signals (/24), {len(first_responders)} fast-relay heuristics)")

    # Summary stats for the frontend
    summary = {
        "total_messages": len(metadata),
    "total_timing_rows": filtered_rows,
        "total_peers": len(peers),
        "peers_with_ip": sum(1 for p in peers.values() if p["ip"]),
        "peers_tor_only": sum(1 for p in peers.values() if p["is_tor"]),
        "collection_duration_hours": 23.5,
        "total_channels_indexed": channel_summary["total_channels_indexed"],
        "nodes_with_channels": channel_summary["nodes_with_channels"],
    "global_scoped_messages": message_scope["global"]["message_count"],
    "global_scoped_peers": message_scope["global"]["peer_count"],
        "msg_types": {str(k): v for k, v in MSG_TYPES.items()},
        "msg_type_counts": {
            MSG_TYPES[row["type"]]: row["len"]
            for row in metadata.group_by("type").len().sort("type").iter_rows(named=True)
        },
    }
    with open(OUTPUT_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("  summary.json")

    print("\n" + "=" * 60)
    print("  Done! Output in:", OUTPUT_DIR)
    print("=" * 60)


if __name__ == "__main__":
    main()
