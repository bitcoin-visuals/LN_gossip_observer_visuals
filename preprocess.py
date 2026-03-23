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


def compute_first_responder_scores(timings: pl.DataFrame) -> pl.DataFrame:
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

    print(f"    Ranked {len(ranked):,} rows in {time.time()-t0:.1f}s")

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
    ).sort("avg_arrival_pct")

    print(f"    Aggregated {len(scores)} peers in {time.time()-t0:.1f}s")
    return scores


def select_interesting_messages(timings: pl.DataFrame, metadata: pl.DataFrame, n: int = 200) -> list[int]:
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
        metadata.select("hash", "type", "orig_node", "scid"),
        on="hash",
        how="left",
    ).with_columns(
        (pl.col("last_seen") - pl.col("first_seen")).dt.total_milliseconds().alias("spread_ms")
    ).filter(
        pl.col("peer_count") >= 50  # Only well-propagated messages
    ).sort("peer_count", descending=True)

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


def build_wavefront_data(timings: pl.DataFrame, message_hashes: list[int]) -> dict:
    """
    For each selected message, build the arrival sequence for animation.
    """
    print(f"  Building wavefront data for {len(message_hashes)} messages...")
    t0 = time.time()

    subset = timings.filter(pl.col("hash").is_in(message_hashes))

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


def build_peer_data(
    scores: pl.DataFrame,
    node_map: dict,
) -> dict:
    """Build the per-peer JSON data for the frontend."""
    peers = {}
    for row in scores.iter_rows(named=True):
        pubkey = row["recv_peer"]
        node_info = node_map.get(pubkey, {})
        alias = node_info.get("alias", "")
        clearnet_ip = node_info.get("clearnet_ip")
        is_tor = node_info.get("is_tor_only", True)

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
    print("\n[1/7] Loading parquet data...")
    t0 = time.time()
    timings = pl.read_parquet(str(PARQUET_DIR / "timings.parquet/"))
    metadata = pl.read_parquet(str(PARQUET_DIR / "metadata.parquet/"))
    print(f"  Loaded {len(timings):,} timing rows, {len(metadata):,} messages in {time.time()-t0:.1f}s")

    # Filter to inbound gossip only (types 1,2,3)
    gossip_hashes = set(metadata.filter(pl.col("type").is_in([1, 2, 3]))["hash"].to_list())
    timings = timings.filter(pl.col("hash").is_in(gossip_hashes))
    print(f"  Filtered to {len(timings):,} gossip timing rows")

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
    peers = build_peer_data(scores, node_map)

    # 5. Select interesting messages and build wavefronts
    print("\n[5/7] Selecting interesting messages...")
    interesting = select_interesting_messages(timings, metadata, n=200)
    print(f"  Selected {len(interesting)} messages")

    msg_index = build_message_index(metadata, interesting)
    wavefronts = build_wavefront_data(timings, interesting)

    # 6. Detect privacy leaks
    print("\n[6/7] Detecting privacy leaks...")
    colocation = build_colocation_suspects(peers)
    first_responders = build_first_responder_leaks(peers)
    print(f"  Found {len(colocation)} co-location signal groups (/24)")
    print(f"  Found {len(first_responders)} fast-relay heuristic peers")

    # 7. Write output
    print("\n[7/7] Writing output files...")

    with open(OUTPUT_DIR / "peers.json", "w") as f:
        json.dump(peers, f)
    print(f"  peers.json ({len(peers)} peers)")

    with open(OUTPUT_DIR / "wavefronts.json", "w") as f:
        json.dump(wavefronts, f)
    print(f"  wavefronts.json ({len(wavefronts)} messages)")

    with open(OUTPUT_DIR / "messages.json", "w") as f:
        json.dump(msg_index, f)
    print(f"  messages.json ({len(msg_index)} messages)")

    with open(OUTPUT_DIR / "communities.json", "w") as f:
        json.dump(COMMUNITY_LABELS, f, indent=2)
    print("  communities.json")

    with open(OUTPUT_DIR / "leaks.json", "w") as f:
        json.dump({
            "colocation": colocation,
            "first_responders": first_responders,
        }, f)
    print(f"  leaks.json ({len(colocation)} co-location signals (/24), {len(first_responders)} fast-relay heuristics)")

    # Summary stats for the frontend
    summary = {
        "total_messages": len(metadata),
        "total_timing_rows": len(timings),
        "total_peers": len(peers),
        "peers_with_ip": sum(1 for p in peers.values() if p["ip"]),
        "peers_tor_only": sum(1 for p in peers.values() if p["is_tor"]),
        "collection_duration_hours": 23.5,
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
