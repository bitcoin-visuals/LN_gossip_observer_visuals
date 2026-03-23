#!/usr/bin/env python3
"""
Inspect raw gossip messages to extract feature bits and fingerprinting signals.

BOLT 7 node_announcement wire format (after zeroed 64-byte sig):
  sig(64, zeroed) + flen(2) + features(flen) + timestamp(4) + node_id(33)
  + rgb_color(3) + alias(32) + addrlen(2) + addresses(addrlen)

BOLT 7 channel_announcement wire format (after zeroed sigs):
  node1_sig(64) + node2_sig(64) + bitcoin1_sig(64) + bitcoin2_sig(64)
  + flen(2) + features(flen) + chain_hash(32) + scid(8) + node1(33) + node2(33)
  + bitcoin1(33) + bitcoin2(33)

The raw column stores the full message with signatures zeroed out.
"""
import json
import base64
from collections import Counter
from pathlib import Path

import polars as pl

BASE_DIR = Path(__file__).resolve().parent
PARQUET_DIR = BASE_DIR / "data" / "raw" / "gossip_archives" / "dump_0926T195046"

# BOLT 9 feature bit definitions
FEATURE_BITS = {
    0: "data_loss_protect",
    1: "data_loss_protect",
    4: "upfront_shutdown_script",
    5: "upfront_shutdown_script",
    6: "gossip_queries",
    7: "gossip_queries",
    8: "tlv_onion",
    9: "tlv_onion",
    10: "gossip_queries_ex",
    11: "gossip_queries_ex",
    12: "static_remote_key",
    13: "static_remote_key",
    14: "payment_secret",
    15: "payment_secret",
    16: "basic_mpp",
    17: "basic_mpp",
    18: "large_channels",
    19: "large_channels",
    20: "anchor_outputs",
    21: "anchor_outputs",
    22: "anchors_zero_fee_htlc_tx",
    23: "anchors_zero_fee_htlc_tx",
    24: "route_blinding",
    25: "route_blinding",
    26: "shutdown_anysegwit",
    27: "shutdown_anysegwit",
    28: "dual_fund",
    29: "dual_fund",
    44: "channel_type",
    45: "channel_type",
    46: "scid_alias",
    47: "scid_alias",
    48: "payment_metadata",
    49: "payment_metadata",
    50: "zero_conf",
    51: "zero_conf",
}


def decode_raw(raw_str: str) -> bytes:
    padding = (4 - len(raw_str) % 4) % 4
    return base64.urlsafe_b64decode(raw_str + "=" * padding)


def decode_features(feat_bytes: bytes) -> dict:
    """Decode feature bit vector into named features."""
    feat_int = int.from_bytes(feat_bytes, "big") if feat_bytes else 0
    features = {}
    bit = 0
    val = feat_int
    while val > 0:
        if val & 1:
            name = FEATURE_BITS.get(bit, f"unknown_bit_{bit}")
            kind = "compulsory" if bit % 2 == 0 else "optional"
            features[name] = kind
        val >>= 1
        bit += 1
    return features


def parse_node_announcement(raw: bytes) -> dict | None:
    """Parse a node_announcement from raw bytes (sig STRIPPED, not zeroed).
    
    Stored format: flen(2) + features(flen) + timestamp(4) + node_id(33)
                   + rgb(3) + alias(32) + addrlen(2) + addresses(addrlen)
    """
    if len(raw) < 2 + 4 + 33 + 3 + 32 + 2:
        return None

    off = 0  # sig is NOT in the stored bytes
    flen = int.from_bytes(raw[off:off+2], "big")
    off += 2
    if off + flen + 4 + 33 + 3 + 32 + 2 > len(raw):
        return None

    features = raw[off:off+flen]
    off += flen
    timestamp = int.from_bytes(raw[off:off+4], "big")
    off += 4
    node_id = raw[off:off+33].hex()
    off += 33
    rgb = raw[off:off+3].hex()
    off += 3
    alias = raw[off:off+32].rstrip(b"\x00").decode("utf-8", errors="replace")
    off += 32
    addrlen = int.from_bytes(raw[off:off+2], "big")
    off += 2
    addr_bytes = raw[off:off+addrlen]

    # Parse addresses
    addresses = parse_addresses(addr_bytes)

    return {
        "node_id": node_id,
        "alias": alias,
        "rgb": f"#{rgb}",
        "timestamp": timestamp,
        "flen": flen,
        "features_hex": features.hex() if features else "",
        "features": decode_features(features),
        "addresses": addresses,
        "addr_types": [a["type"] for a in addresses],
    }


def parse_addresses(data: bytes) -> list:
    """Parse BOLT 7 address descriptors."""
    addrs = []
    off = 0
    while off < len(data):
        addr_type = data[off]
        off += 1
        if addr_type == 1:  # IPv4
            if off + 6 > len(data):
                break
            ip = ".".join(str(b) for b in data[off:off+4])
            port = int.from_bytes(data[off+4:off+6], "big")
            addrs.append({"type": "ipv4", "addr": f"{ip}:{port}"})
            off += 6
        elif addr_type == 2:  # IPv6
            if off + 18 > len(data):
                break
            ip = ":".join(f"{data[off+i]:02x}{data[off+i+1]:02x}" for i in range(0, 16, 2))
            port = int.from_bytes(data[off+16:off+18], "big")
            addrs.append({"type": "ipv6", "addr": f"[{ip}]:{port}"})
            off += 18
        elif addr_type == 3:  # Tor v2 (deprecated)
            if off + 12 > len(data):
                break
            addrs.append({"type": "torv2", "addr": "torv2"})
            off += 12
        elif addr_type == 4:  # Tor v3
            if off + 37 > len(data):
                break
            addrs.append({"type": "torv3", "addr": "torv3_onion"})
            off += 37
        elif addr_type == 5:  # DNS hostname
            if off + 1 > len(data):
                break
            hlen = data[off]
            off += 1
            if off + hlen + 2 > len(data):
                break
            hostname = data[off:off+hlen].decode("utf-8", errors="replace")
            port = int.from_bytes(data[off+hlen:off+hlen+2], "big")
            addrs.append({"type": "dns", "addr": f"{hostname}:{port}"})
            off += hlen + 2
        else:
            break  # unknown type, stop
    return addrs


def parse_channel_announcement(raw: bytes) -> dict | None:
    """Parse a channel_announcement from raw bytes (4 sigs STRIPPED).
    
    Stored format: flen(2) + features(flen) + chain_hash(32) + scid(8)
                   + node1(33) + node2(33) + bitcoin1(33) + bitcoin2(33)
    """
    if len(raw) < 2 + 32 + 8 + 33*4:
        return None
    off = 0  # sigs are stripped
    flen = int.from_bytes(raw[off:off+2], "big")
    off += 2
    features = raw[off:off+flen]
    off += flen
    off += 32
    scid = int.from_bytes(raw[off:off+8], "big")
    off += 8
    node1 = raw[off:off+33].hex()
    off += 33
    node2 = raw[off:off+33].hex()

    return {
        "scid": scid,
        "node1": node1,
        "node2": node2,
        "flen": flen,
        "features_hex": features.hex() if features else "",
        "features": decode_features(features),
    }


def main():
    print("=" * 60)
    print("  GOSSIP MESSAGE RAW DECODER — Feature Fingerprinting")
    print("=" * 60)

    msgs = pl.read_parquet(str(PARQUET_DIR / "messages.parquet/"))
    meta = pl.read_parquet(str(PARQUET_DIR / "metadata.parquet/"))
    joined = msgs.join(meta.select("hash", "type", "orig_node", "size"), on="hash", how="inner")

    # ── NODE ANNOUNCEMENTS ──────────────────────────────────────
    node_anns = joined.filter(pl.col("type") == 2)
    print(f"\n[1] Node announcements: {len(node_anns):,}")

    parsed_nodes = {}
    parse_errors = 0
    for row in node_anns.iter_rows(named=True):
        raw = decode_raw(row["raw"])
        result = parse_node_announcement(raw)
        if result:
            # Keep latest per node (highest timestamp)
            nid = result["node_id"]
            if nid not in parsed_nodes or result["timestamp"] > parsed_nodes[nid]["timestamp"]:
                parsed_nodes[nid] = result
        else:
            parse_errors += 1

    print(f"  Parsed: {len(parsed_nodes)} unique nodes, {parse_errors} errors")

    # Feature statistics
    feat_counter = Counter()
    flen_counter = Counter()
    addr_type_counter = Counter()
    for n in parsed_nodes.values():
        for feat_name in n["features"]:
            feat_counter[feat_name] += 1
        flen_counter[n["flen"]] += 1
        for at in n["addr_types"]:
            addr_type_counter[at] += 1

    print(f"\n  Feature bit prevalence (across {len(parsed_nodes)} nodes):")
    for feat, count in feat_counter.most_common(30):
        pct = count / len(parsed_nodes) * 100
        print(f"    {feat:35s}  {count:5d}  ({pct:.1f}%)")

    print("\n  Feature vector lengths (flen):")
    for flen, count in flen_counter.most_common(10):
        print(f"    flen={flen:3d} bytes  →  {count:5d} nodes")

    print("\n  Address types:")
    for at, count in addr_type_counter.most_common():
        print(f"    {at:10s}  {count:5d}")

    # ── CHANNEL ANNOUNCEMENTS ───────────────────────────────────
    chan_anns = joined.filter(pl.col("type") == 1)
    print(f"\n[2] Channel announcements: {len(chan_anns):,}")

    chan_feat_counter = Counter()
    chan_parse_ok = 0
    for row in chan_anns.head(10000).iter_rows(named=True):
        raw = decode_raw(row["raw"])
        result = parse_channel_announcement(raw)
        if result:
            chan_parse_ok += 1
            for feat_name in result["features"]:
                chan_feat_counter[feat_name] += 1

    print(f"  Parsed: {chan_parse_ok}")
    if chan_feat_counter:
        print("  Channel feature prevalence:")
        for feat, count in chan_feat_counter.most_common(15):
            print(f"    {feat:35s}  {count:5d}")
    else:
        print("  No channel-level features found (expected — usually empty)")

    # ── FINGERPRINT GROUPS ──────────────────────────────────────
    print("\n[3] Implementation fingerprinting...")

    # Group by feature vector
    fprint_groups = {}
    for nid, n in parsed_nodes.items():
        key = n["features_hex"]
        fprint_groups.setdefault(key, []).append(nid)

    print(f"  Unique feature fingerprints: {len(fprint_groups)}")
    print("  Top 15 fingerprint groups:")
    for fhex, nodes in sorted(fprint_groups.items(), key=lambda x: -len(x[1]))[:15]:
        feats = decode_features(bytes.fromhex(fhex)) if fhex else {}
        feat_names = sorted(set(feats.keys()))
        sample_aliases = [parsed_nodes[n]["alias"] for n in nodes[:3]]
        print(f"    [{len(nodes):4d} nodes]  flen={len(fhex)//2:3d}  features: {', '.join(feat_names[:6]) or '(none)'}")
        print(f"              samples: {', '.join(sample_aliases)}")

    # ── SAVE FOR DASHBOARD ──────────────────────────────────────
    output = {
        "feature_prevalence": {k: v for k, v in feat_counter.most_common()},
        "fingerprint_groups": [
            {
                "features_hex": fhex,
                "feature_names": sorted(set(decode_features(bytes.fromhex(fhex)).keys())) if fhex else [],
                "node_count": len(nodes),
                "sample_nodes": nodes[:5],
                "all_nodes": nodes,
            }
            for fhex, nodes in sorted(fprint_groups.items(), key=lambda x: -len(x[1]))
        ],
        "total_unique_fingerprints": len(fprint_groups),
        "total_nodes_parsed": len(parsed_nodes),
    }

    out_path = Path(__file__).resolve().parent / "static" / "data" / "fingerprints.json"
    with open(out_path, "w") as f:
        json.dump(output, f)
    print(f"\n  Saved fingerprints.json ({len(fprint_groups)} groups)")


if __name__ == "__main__":
    main()
