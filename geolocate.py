#!/usr/bin/env python3
"""
Add lat/lon to peers.json by geolocating IPs via ip-api.com batch API.
Free tier: 15 req/min for single, but batch endpoint handles 100 IPs per request.
"""

import json
import time
import urllib.request
from pathlib import Path

PEERS_PATH = Path(__file__).parent / "static" / "data" / "peers.json"
BATCH_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100  # max per request
RATE_LIMIT_PAUSE = 1.5  # seconds between batch requests


def geolocate_batch(ips: list[str]) -> dict[str, dict]:
    """Send batch of IPs to ip-api.com, return {ip: {lat, lon, country, city, isp}}."""
    payload = json.dumps([
        {"query": ip, "fields": "query,status,lat,lon,country,city,isp,as"}
        for ip in ips
    ]).encode()

    req = urllib.request.Request(
        BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read())
    except Exception as e:
        print(f"    Batch request failed: {e}")
        return {}

    out = {}
    for r in results:
        if r.get("status") == "success":
            out[r["query"]] = {
                "lat": r["lat"],
                "lon": r["lon"],
                "country": r.get("country", ""),
                "city": r.get("city", ""),
                "isp": r.get("isp", ""),
                "as": r.get("as", ""),
            }
    return out


def main():
    print("Loading peers.json...")
    with open(PEERS_PATH) as f:
        peers = json.load(f)

    # Collect unique IPs
    ip_to_peers = {}
    for pubkey, p in peers.items():
        ip = p.get("ip")
        if ip:
            ip_to_peers.setdefault(ip, []).append(pubkey)

    unique_ips = list(ip_to_peers.keys())
    print(f"  {len(unique_ips)} unique IPs to geolocate")

    # Batch geolocate
    geo_cache = {}
    batches = [unique_ips[i:i + BATCH_SIZE] for i in range(0, len(unique_ips), BATCH_SIZE)]

    for i, batch in enumerate(batches):
        print(f"  Batch {i + 1}/{len(batches)} ({len(batch)} IPs)...")
        results = geolocate_batch(batch)
        geo_cache.update(results)
        if i < len(batches) - 1:
            time.sleep(RATE_LIMIT_PAUSE)

    print(f"  Geolocated {len(geo_cache)}/{len(unique_ips)} IPs")

    # Enrich peers
    enriched = 0
    for pubkey, p in peers.items():
        ip = p.get("ip")
        if ip and ip in geo_cache:
            geo = geo_cache[ip]
            p["lat"] = geo["lat"]
            p["lon"] = geo["lon"]
            p["country"] = geo["country"]
            p["city"] = geo["city"]
            p["isp"] = geo["isp"]
            p["as_info"] = geo["as"]
            enriched += 1

    print(f"  Enriched {enriched} peers with geolocation")

    # Write back
    with open(PEERS_PATH, "w") as f:
        json.dump(peers, f)
    print(f"  Written to {PEERS_PATH}")


if __name__ == "__main__":
    main()
