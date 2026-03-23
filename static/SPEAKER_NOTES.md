# Gossip Tomography — Speaker Notes
**BTC++ Hackathon 2026**

Press **S** during the presentation to open Reveal.js speaker view (shows notes + next slide).

---

## Slide 1: Title
Gossip Tomography — we analyze Lightning Network gossip propagation to detect privacy leaks and surveillance risks. Built for the BTC++ Hackathon 2026.

---

## Slide 2: The Problem
Lightning gossip propagates asynchronously. Who receives a message first reveals network topology. Peers that consistently arrive in the top 5% may be surveillance nodes. Nodes sharing the same IP subnet likely share an operator. And feature bits in node_announcement expose implementation fingerprint and attack surface.

---

## Slide 3: Our Approach
We use exported 24-hour data from the gossip observer project — we don't run a node. We build wavefronts: per-message arrival times. Identify first responders: peers in top 5%. Detect co-location from IPs in node_announcement. Parse feature bits for threat exposure.

---

## Slide 4: 4-Quadrant Dashboard
Four quadrants: top-left is propagation replay with radial viz and wavefront animation. Top-right is a world map with peer locations. Bottom-left lists surveillance suspects — first responders. Bottom-right shows co-located peers by subnet. Click any peer and it highlights across all panels.

---

## Slide 5: Feature Exploit Report
From node_announcement feature bits: Zero-conf allows double-spend. Anchor channels vulnerable to replacement cycling. Missing data_loss_protect means revocation risk. Gossip queries enable bandwidth amplification. No scid_alias exposes unannounced channels. Wumbo = higher-value target.

---

## Slide 6: Dataset
24-hour exported snapshot: 416K messages, 978 peers connected to the observer, 758 with clearnet IPs. 5,736 nodes fingerprinted from node_announcements. 30 surveillance suspects, 47 co-location groups.

---

## Slide 7: Live Demo
Open the dashboard, show the propagation replay, click a message and play the wavefront. Click a suspect to highlight across map and panels. Show the threat bar.

---

## Slide 8: Title (closing)
Thanks. Gossip Tomography — questions?
