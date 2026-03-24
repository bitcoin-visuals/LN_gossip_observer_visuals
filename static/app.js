// ═══════════════════════════════════════════════════════════════
//  LN Gossip Visualizer — Interactive LN Gossip Propagation Analyzer
//  BTC++ Hackathon 2026
//
//  4-quadrant dashboard with cross-highlighting:
//    Q1  Propagation Replay (radial canvas)
//    Q2  World Map (Leaflet)
//    Q3  Future Features / Placeholder
//    Q4  Node Details
// ═══════════════════════════════════════════════════════════════

const DATA_BASE = "data";

// ─── Data ───────────────────────────────────────────────────────
let peers = {};
let wavefronts = {};
let messages = [];
let communities = {};
let leaks = {};
let summary = {};
let fingerprints = {};        // raw fingerprints.json
let fpByPubkey = {};          // pubkey → { features_hex, feature_names, group_size }
let channels = [];
let nodeChannels = {};
let messageScope = { global: {}, nodes: {} };
let channelScopeSummary = { global: {}, nodes: {} };
let messageCatalog = [];
let messageIntel = [];
let replayRenderLimit = 100;
let replayFilterType = "all";
let replaySearchText = "";
let replaySelectionToken = 0;
let messageDetailMode = "replay";

const replayWavefrontCache = new Map();

function getGlobalVisibleChannels() {
    return Array.isArray(channels) ? channels.slice(0, 30) : [];
}

function getActiveMessageUniverse(active = getActiveChannelList(), visibleChannelItems = null) {
    if (!selectedNodePubkey) {
        return {
            mode: "global",
            messageCount: channelScopeSummary.global?.message_count || 11317,
            peerCount: channelScopeSummary.global?.peer_count || messageScope.global?.peer_count || summary.global_scoped_peers || Object.keys(peers).length || 0,
            mappedPeerCount: channelScopeSummary.global?.mapped_peer_count || messageScope.global?.mapped_peer_count || Object.values(peers).filter(p => Number.isFinite(p.lat) && Number.isFinite(p.lon)).length || 0,
            channelCount: getGlobalVisibleChannels().length,
        };
    }

    const nodeScope = channelScopeSummary.nodes?.[selectedNodePubkey] || messageScope.nodes?.[selectedNodePubkey] || {};
    const nodeItems = Array.isArray(visibleChannelItems) ? visibleChannelItems : (Array.isArray(active.items) ? active.items : []);
    const visibleNodeChannelCount = nodeItems.length;

    return {
        mode: "node",
        messageCount: nodeScope.message_count || 0,
        peerCount: nodeScope.peer_count || 1,
        mappedPeerCount: nodeScope.mapped_peer_count || 0,
        channelCount: visibleNodeChannelCount,
    };
}

// ─── Threat indicator definitions ───────────────────────────────
// Each entry: feature to check, whether presence or absence is the threat,
// severity, icon, short label, attack description, source references.
const THREAT_DEFS = [
    {
        id: "zero_conf",
        feature: "zero_conf",
        mode: "present",       // threat when the feature IS advertised
        severity: "high",
        icon: "⏱️",
        label: "Zero-Conf Theft",
        shortLabel: "Zero-Conf",
        attack: "Accepts unconfirmed channels — funder can double-spend the funding tx, stealing all routed funds before confirmation.",
        source: "BOLTs #910"
    },
    {
        id: "anchors_exploit",
        feature: "anchors_zero_fee_htlc_tx",
        mode: "present",
        severity: "high",
        icon: "⚓",
        label: "Anchor Replacement Cycling",
        shortLabel: "Anchor Exploit",
        attack: "Anchor-format channels are vulnerable to replacement cycling attacks — counterparty can repeatedly evict HTLC claims from the mempool to steal funds before timelocks expire.",
        source: "Riard 2023, Optech #272"
    },
    {
        id: "no_data_loss",
        feature: "data_loss_protect",
        mode: "absent",        // threat when feature is MISSING
        severity: "high",
        icon: "💾",
        label: "No Backup Protection",
        shortLabel: "No Backup",
        attack: "Node lacks data_loss_protect — if it loses its channel database, it cannot safely recover. Peer could broadcast revoked state and steal all channel funds.",
        source: "BOLT 9 bit 0/1"
    },
    {
        id: "gossip_dos",
        feature: "gossip_queries",
        mode: "present",
        severity: "medium",
        icon: "📡",
        label: "Gossip Bandwidth DoS",
        shortLabel: "Gossip DoS",
        attack: "Supports gossip_queries — can be abused for bandwidth amplification: small request triggers full graph dump. Repeated queries can overwhelm CPU and bandwidth.",
        source: "BOLT 7"
    },
    {
        id: "large_target",
        feature: "large_channels",
        mode: "present",
        severity: "medium",
        icon: "🐋",
        label: "High-Value Target",
        shortLabel: "Wumbo Target",
        attack: "Advertises wumbo/large channels (>0.168 BTC). More capital at risk in hot wallets — higher-value target for force-close griefing and replacement cycling.",
        source: "BOLT 11"
    },
    {
        id: "no_scid_alias",
        feature: "scid_alias",
        mode: "absent",
        severity: "medium",
        icon: "🔗",
        label: "No UTXO Hiding",
        shortLabel: "UTXO Exposed",
        attack: "Lacks scid_alias — unannounced channels expose their on-chain UTXO to any routing peer. Enables channel probing and on-chain surveillance linkage.",
        source: "BOLTs #910"
    },
    {
        id: "no_chan_type",
        feature: "channel_type",
        mode: "absent",
        severity: "low",
        icon: "🔄",
        label: "Channel Downgrade Risk",
        shortLabel: "Downgrade",
        attack: "Missing explicit channel_type negotiation — peer could trick this node into opening a legacy (non-anchor) channel with weaker security properties.",
        source: "BOLTs #880"
    },
];

// ─── Selection state ────────────────────────────────────────────
let highlightedPeers = new Set();   // pubkeys currently highlighted across all panels
let currentMsg = null;
let currentWavefront = [];

// ─── Animation ──────────────────────────────────────────────────
let animFrame = null;
let animStart = null;
let animPlaying = false;
let animSpeed = 1;

// ─── Canvas ─────────────────────────────────────────────────────
let canvas, ctx, W, H;
let peerPositions = {};
let peerStates = {};

// ─── Map ────────────────────────────────────────────────────────
let leafletMap = null;
let mapMarkers = {};          // pubkey → L.circleMarker
let mapHighlightLayer = null;
let selectedNodePubkey = null;
const DEFAULT_MAP_VIEW = {
    center: [25, 0],
    zoom: 2,
};

// ═══════════════════════════════════════════════════════════════
//  BOOT
// ═══════════════════════════════════════════════════════════════

window.addEventListener("load", async () => {
    await loadData();
    initMap();
    setupUI();

    window.addEventListener("resize", () => {
        leafletMap?.invalidateSize();
    });

    // Auto-select first scoped message from the all-message intelligence browser
    const initialMessage = messageIntel[0] || messageCatalog[0];
    if (initialMessage) selectMessage(initialMessage);
});

// ═══════════════════════════════════════════════════════════════
//  DATA
// ═══════════════════════════════════════════════════════════════

async function loadData() {
    const [p, w, m, c, l, s, fp, ch, nch, ms, css, mc, mi] = await Promise.all([
        fetchJSON(`${DATA_BASE}/peers.json`),
        fetchJSON(`${DATA_BASE}/wavefronts.json`),
        fetchJSON(`${DATA_BASE}/messages.json`),
        fetchJSON(`${DATA_BASE}/communities.json`),
        fetchJSON(`${DATA_BASE}/leaks.json`),
        fetchJSON(`${DATA_BASE}/summary.json`),
        fetchJSON(`${DATA_BASE}/fingerprints.json`),
        fetchJSON(`${DATA_BASE}/channels.json`),
        fetchJSON(`${DATA_BASE}/node_channels.json`),
        fetchJSON(`${DATA_BASE}/message_scope.json`),
        fetchJSON(`${DATA_BASE}/channel_scope_summary.json`),
        fetchJSON(`${DATA_BASE}/message_catalog.json`),
        fetchJSON(`${DATA_BASE}/message_intel.json`),
    ]);
    peers = p; wavefronts = w; communities = c; leaks = l; summary = s; fingerprints = fp;
    channels = Array.isArray(ch) ? ch : [];
    nodeChannels = nch && typeof nch === "object" ? nch : {};
    messageScope = ms && typeof ms === "object" ? ms : { global: {}, nodes: {} };
    channelScopeSummary = css && typeof css === "object" ? css : { global: {}, nodes: {} };
    messageCatalog = Array.isArray(mc) ? mc : [];
    messageIntel = Array.isArray(mi) ? mi : [];

    // Build pubkey → fingerprint lookup
    fpByPubkey = {};
    if (fp.fingerprint_groups) {
        for (const grp of fp.fingerprint_groups) {
            const nodeList = grp.all_nodes || grp.sample_nodes || [];
            for (const pk of nodeList) {
                fpByPubkey[pk] = {
                    features_hex: grp.features_hex,
                    feature_names: grp.feature_names || [],
                    group_size: grp.node_count || 0,
                };
            }
        }
    }

    // ── Compute threat indicators from fingerprints ──
    computeAndRenderThreats();

    // Normalize messages dict → array, enrich from wavefronts
    if (!Array.isArray(m)) {
        messages = Object.entries(m).map(([hash, meta]) => {
            const wf = wavefronts[hash] || {};
            return {
                hash, ...meta,
                peer_count: wf.total_peers || (wf.arrivals ? wf.arrivals.length : 0),
                time_spread_ms: wf.spread_ms || 0,
            };
        });
    } else {
        messages = m;
    }

    const replayHashes = new Set(messages.map(msg => String(msg.hash)));
    const enrichScopedMessage = (item) => {
        const replayMeta = replayHashes.has(String(item.hash)) ? (wavefronts[item.hash] || wavefronts[String(item.hash)] || {}) : null;
        const peerCount = replayMeta?.total_peers || item.summary_peer_count || item.peer_count || 0;
        return {
            ...item,
            replay_available: replayHashes.has(String(item.hash)),
            summary_available: item.summary_available || peerCount > 1,
            peer_count: peerCount,
            time_spread_ms: replayMeta?.spread_ms || item.summary_spread_ms || item.time_spread_ms || 0,
        };
    };
    messageCatalog = messageCatalog.map(enrichScopedMessage);
    messageIntel = (messageIntel.length ? messageIntel : messageCatalog).map(enrichScopedMessage);

    // Header stats
    const mapLocatedCount = Object.values(peers).filter(p => Number.isFinite(p.lat) && Number.isFinite(p.lon)).length;
    document.getElementById("stat-peers").textContent = (messageScope.global.peer_count || summary.global_scoped_peers || summary.total_peers || Object.keys(peers).length).toLocaleString();
    document.getElementById("stat-msgs").textContent = (messageScope.global.message_count || channelScopeSummary.global.message_count || summary.global_scoped_messages || 0).toLocaleString();
    document.getElementById("stat-ips").textContent = (messageScope.global.mapped_peer_count || mapLocatedCount).toLocaleString();
    // Badges
    document.getElementById("replay-badge").textContent = `${messageIntel.length.toLocaleString()} scoped msgs`;
    document.getElementById("map-badge").textContent = mapLocatedCount + " mapped";
    document.getElementById("suspect-badge").textContent = `${(summary.total_channels_indexed || channels.length || 0).toLocaleString()} tracked`;
    const nodeDetailsBadge = document.getElementById("node-details-badge");
    if (nodeDetailsBadge && !selectedNodePubkey) {
        nodeDetailsBadge.textContent = "Select a node";
    }
    renderChannelsPanel();
}

async function fetchJSON(url) {
    try {
        const r = await fetch(url);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return await r.json();
    } catch (e) { console.warn(`Failed: ${url}`, e); return {}; }
}

async function fetchJSONOrNull(url) {
    try {
        const r = await fetch(url);
        if (!r.ok) return null;
        return await r.json();
    } catch (e) {
        console.warn(`Optional fetch failed: ${url}`, e);
        return null;
    }
}

function getCachedWavefront(msgHash) {
    const key = String(msgHash);
    return replayWavefrontCache.get(key) || wavefronts[key] || wavefronts[msgHash] || null;
}

function findMessageMeta(msgHash) {
    const key = String(msgHash);
    return messages.find(msg => String(msg.hash) === key)
        || messageIntel.find(msg => String(msg.hash) === key)
        || messageCatalog.find(msg => String(msg.hash) === key)
        || null;
}

function setMessageDetailMode(mode) {
    messageDetailMode = "intel";
    const intelWrap = document.getElementById("msg-intel-wrap");
    if (intelWrap) intelWrap.hidden = false;
    renderMessageIntel(currentMsg);
}

function formatMessageType(type) {
    if (type === "channel_announcement") return "Channel announcement";
    if (type === "node_announcement") return "Node announcement";
    if (type === "channel_update") return "Channel update";
    return type || "Unknown message";
}

function getSpreadProfile(msg) {
    const peerCount = Number(msg?.peer_count || 0);
    const spreadMs = Number(msg?.time_spread_ms || 0);
    const timingRows = Number(msg?.timing_rows || 0);
    if (!peerCount && !spreadMs && !timingRows) return "catalog-only";
    if (spreadMs && peerCount >= 700) return "broad + sustained";
    if (spreadMs && spreadMs < 60_000) return "fast burst";
    if (peerCount >= 250) return "broad reach";
    if (timingRows >= 5_000) return "relay-heavy";
    return "narrow / sparse";
}

function buildMessageNarrative(msg) {
    if (!msg) return "Select a scoped message to inspect its identity, relay footprint, and available timing summary.";
    const parts = [];
    parts.push(`${formatMessageType(msg.type)} message`);
    if (msg.scid) parts.push(`channel SCID ${msg.scid}`);
    if (msg.orig_node) parts.push(`originating from ${msg.orig_node.slice(0, 20)}…`);
    return parts.join(" · ") + ".";
}

function renderMessageIntel(msg) {
    const intelWrap = document.getElementById("msg-intel-wrap");
    if (!intelWrap) return;
    if (!msg) {
        intelWrap.innerHTML = '<div class="msg-intel-empty">Select a message to inspect its metadata footprint.</div>';
        return;
    }

    const messageMeta = findMessageMeta(msg.hash) || {};
    const replayMeta = wavefronts[String(msg.hash)] || {};
    const peerCount = Number(msg.peer_count || replayMeta.total_peers || 0);
    const spreadMs = Number(msg.time_spread_ms || replayMeta.spread_ms || 0);
    const timingRows = Number(msg.timing_rows || 0);
    const activityScore = Number(msg.activity_score || 0);
    const intensityMax = Math.max(peerCount, timingRows, 1);
    const reachPct = Math.min(100, (peerCount / Math.max(summary.global_scoped_peers || 1, 1)) * 100);
    const relayPct = Math.min(100, (timingRows / Math.max(summary.total_timing_rows || 1, 1)) * 100000);
    const fingerprint = messageMeta.orig_node ? fpByPubkey[messageMeta.orig_node] : null;
    const scopeStats = messageMeta.orig_node ? (messageScope.nodes?.[messageMeta.orig_node] || {}) : {};
    const profile = getSpreadProfile({ ...messageMeta, ...msg, peer_count: peerCount, timing_rows: timingRows, time_spread_ms: spreadMs });
    const hasSummary = msg.summary_available || msg.replay_available || peerCount > 1;
    const replayState = hasSummary ? "timing summary available" : "metadata-only";

    intelWrap.innerHTML = `
        <div class="msg-card">
            <div class="msg-card-header">
                <div class="msg-card-title">
                    <div class="msg-card-subtitle">${escHtml(formatMessageType(messageMeta.type || msg.type))}</div>
                    <div class="msg-card-hash">${escHtml(String(msg.hash))}</div>
                </div>
                <div class="msg-chip-row">
                    <span class="msg-chip accent">${escHtml(profile)}</span>
                    <span class="msg-chip ${hasSummary ? "good" : ""}">${escHtml(replayState)}</span>
                </div>
            </div>

            <div class="msg-profile-text">${escHtml(buildMessageNarrative({ ...messageMeta, ...msg, peer_count: peerCount, timing_rows: timingRows, time_spread_ms: spreadMs }))}</div>

            <div class="msg-card-grid">
                <div class="msg-stat">
                    <div class="msg-stat-label">Message size</div>
                    <div class="msg-stat-value">${Number(messageMeta.size || 0).toLocaleString()} B</div>
                </div>
                <div class="msg-stat">
                    <div class="msg-stat-label">Observed peer reach</div>
                    <div class="msg-stat-value">${peerCount.toLocaleString()}</div>
                </div>
                <div class="msg-stat">
                    <div class="msg-stat-label">Timing span</div>
                    <div class="msg-stat-value">${spreadMs ? `${(spreadMs / 1000).toFixed(2)} s` : "not available"}</div>
                </div>
                <div class="msg-stat">
                    <div class="msg-stat-label">Origin node</div>
                    <div class="msg-stat-value">${messageMeta.orig_node ? escHtml(messageMeta.orig_node) : "not encoded"}</div>
                </div>
                <div class="msg-stat">
                    <div class="msg-stat-label">Channel / SCID</div>
                    <div class="msg-stat-value">${messageMeta.scid ? escHtml(messageMeta.scid) : "not channel-linked"}</div>
                </div>
            </div>

            <div>
                <div class="msg-section-title">Footprint bars</div>
                <div class="msg-bar-track"><div class="msg-bar-fill" style="width:${reachPct.toFixed(1)}%"></div></div>
                <div class="msg-bar-meta"><span>Scoped peer reach</span><span>${reachPct.toFixed(1)}%</span></div>
                <div class="msg-bar-track" style="margin-top:8px;"><div class="msg-bar-fill" style="width:${Math.max(4, Math.min(100, relayPct))}%"></div></div>
                <div class="msg-bar-meta"><span>Relay activity index</span><span>${timingRows.toLocaleString()} relays</span></div>
            </div>

            <div>
                <div class="msg-section-title">Context drivers</div>
                <div class="msg-chip-row" style="margin-top:6px;">
                    <span class="msg-chip">type_id ${Number(messageMeta.type_id || 0)}</span>
                    <span class="msg-chip">activity ${activityScore.toFixed(1)}</span>
                    ${scopeStats.message_count ? `<span class="msg-chip">origin scope msgs ${Number(scopeStats.message_count).toLocaleString()}</span>` : ""}
                    ${scopeStats.channel_count ? `<span class="msg-chip">origin channels ${Number(scopeStats.channel_count).toLocaleString()}</span>` : ""}
                    ${scopeStats.mapped_peer_count ? `<span class="msg-chip">mapped peers ${Number(scopeStats.mapped_peer_count).toLocaleString()}</span>` : ""}
                    ${fingerprint?.group_size ? `<span class="msg-chip">fingerprint cluster ${Number(fingerprint.group_size).toLocaleString()}</span>` : ""}
                    ${fingerprint?.feature_names?.length ? `<span class="msg-chip">features ${escHtml(fingerprint.feature_names.slice(0, 3).join(", "))}</span>` : ""}
                </div>
            </div>

                <div class="msg-hint">
                Compare identity, origin, channel context, reach, and timing span without loading the old propagation spiral or player controls.
            </div>
        </div>
    `;
}

async function ensureWavefrontLoaded(msgHash) {
    const key = String(msgHash);
    const cached = getCachedWavefront(key);
    if (cached) {
        replayWavefrontCache.set(key, cached);
        return cached;
    }

    const shard = await fetchJSONOrNull(`${DATA_BASE}/wavefronts/${key}.json`);
    if (shard) {
        replayWavefrontCache.set(key, shard);
        return shard;
    }

    return null;
}

function computeLayout() {
    const byCommunity = {};
    for (const [ph, p] of Object.entries(peers)) {
        const c = p.community || "unknown";
        (byCommunity[c] ??= []).push(ph);
    }
    const cKeys = Object.keys(byCommunity).sort();
    const total = Object.keys(peers).length;
    if (!total) return;

    const cx = W / 2, cy = H / 2;
    const maxR = Math.min(W, H) * 0.42;
    let aOff = 0;

    for (const ck of cKeys) {
        const cp = byCommunity[ck];
        const sector = (cp.length / total) * Math.PI * 2;
        for (let i = 0; i < cp.length; i++) {
            const frac = cp.length > 1 ? i / (cp.length - 1) : 0.5;
            const angle = aOff + frac * sector;
            const avgPct = peers[cp[i]]?.avg_arrival_pct ?? 0.5;
            const r = maxR * (0.15 + 0.85 * avgPct);
            peerPositions[cp[i]] = {
                x: cx + Math.cos(angle) * r,
                y: cy + Math.sin(angle) * r,
                angle, r,
            };
        }
        aOff += sector + 0.04;
    }
}

// ═══════════════════════════════════════════════════════════════
//  UI SETUP
// ═══════════════════════════════════════════════════════════════

function setupUI() {
    // Message filter
    document.querySelectorAll(".msg-filter button").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".msg-filter button").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            replayRenderLimit = 100;
            renderMessageList(btn.dataset.type);
        });
    });

    const msgSearch = document.getElementById("msg-search");
    const loadMoreBtn = document.getElementById("msg-load-more");
    if (msgSearch) {
        msgSearch.addEventListener("input", (e) => {
            replaySearchText = (e.target.value || "").trim().toLowerCase();
            replayRenderLimit = 100;
            renderMessageList(replayFilterType);
        });
    }
    if (loadMoreBtn) {
        loadMoreBtn.addEventListener("click", () => {
            replayRenderLimit += 100;
            renderMessageList(replayFilterType);
        });
    }

    renderMessageList("all");
    setMessageDetailMode();
    renderAllMapMarkers();
}

// ═══════════════════════════════════════════════════════════════
//  Q1 — MESSAGE LIST
// ═══════════════════════════════════════════════════════════════

function renderMessageList(filterType) {
    const list = document.getElementById("msg-list");
    const resultsMeta = document.getElementById("msg-results-meta");
    const loadMoreBtn = document.getElementById("msg-load-more");
    const normalizedFilterType = filterType || "all";
    list.innerHTML = "";
    replayFilterType = normalizedFilterType;
    const universe = messageIntel.length ? messageIntel : messageCatalog;
    const filtered = (normalizedFilterType === "all" ? universe : universe.filter(m => m.type === normalizedFilterType))
        .filter(m => {
            if (!replaySearchText) return true;
            return [m.hash, m.scid, m.orig_node, m.type]
                .filter(Boolean)
                .some(value => String(value).toLowerCase().includes(replaySearchText));
        });
    const sorted = [...filtered]
        .sort((a, b) => (b.activity_score || 0) - (a.activity_score || 0))
        .slice(0, replayRenderLimit);

    if (resultsMeta) {
        resultsMeta.textContent = `${sorted.length.toLocaleString()} / ${filtered.length.toLocaleString()} shown`;
    }
    if (loadMoreBtn) {
        loadMoreBtn.style.display = filtered.length > sorted.length ? "inline-block" : "none";
    }

    for (const msg of sorted) {
        const el = document.createElement("div");
        el.className = "msg-item" + (currentMsg?.hash === msg.hash ? " active" : "");
        const ts = msg.type === "channel_announcement" ? "chan_ann"
            : msg.type === "node_announcement" ? "node_ann" : "chan_upd";
        const spanMs = msg.time_spread_ms || msg.summary_spread_ms || 0;
        const peerCt = msg.summary_peer_count || msg.peer_count || 0;
        const hasSummaryItem = msg.summary_available || msg.replay_available || peerCt > 1;
        el.innerHTML = `
            <span class="type-badge type-${ts}">${ts}</span>
            <span class="peers-count">${hasSummaryItem
                ? `${peerCt}p · ${(spanMs / 1000).toFixed(1)}s`
                : `${(msg.timing_rows || 0).toLocaleString()} relays${spanMs ? ` · ${(spanMs / 1000).toFixed(1)}s span` : " · intel"}`
            }</span>`;
        el.addEventListener("click", () => selectMessage(msg));
        list.appendChild(el);
    }
}

// ═══════════════════════════════════════════════════════════════
//  FAST RELAY HEURISTICS
// ═══════════════════════════════════════════════════════════════

function buildSuspectsHtml() {
    const frList = (leaks.first_responders || [])
        .sort((a, b) => (a.avg_arrival_pct || 0) - (b.avg_arrival_pct || 0));

    return frList.map(fr => {
        const pk = fr.pubkey || "";
        const pct = (fr.top5_pct || 0).toFixed(0);
        const isTor = fr.is_tor;
        return `
        <div class="suspect-card" data-pubkey="${pk}">
            <div class="alias">${escHtml(fr.alias || pk.slice(0, 16) + "…")}</div>
            <div class="meta">
                <span class="tag ${isTor ? "tag-tor" : "tag-clearnet"}">${isTor ? "🧅 TOR" : "🌐 CLEARNET"}</span>
                ${fr.ip ? `<span style="color:#555">${fr.ip}</span>` : ""}
                · <strong>${(fr.messages_seen || 0).toLocaleString()}</strong> msgs seen
            </div>
            <div class="score-bar">
                <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
                <span class="bar-label">top-5: ${pct}%</span>
            </div>
        </div>`;
    }).join("");
}

function wireSuspectCardInteractions(scope = document) {
    scope.querySelectorAll(".suspect-card").forEach(card => {
        if (card.dataset.wired === "1") return;
        card.dataset.wired = "1";
        const pk = card.dataset.pubkey;
        card.addEventListener("click", () => openNodeCard(pk));
        card.addEventListener("mouseenter", () => showPeerTooltip(pk, card));
        card.addEventListener("mouseleave", () => hideTooltip());
    });
}

// ═══════════════════════════════════════════════════════════════
//  CO-LOCATION SIGNALS
// ═══════════════════════════════════════════════════════════════

function buildColocationCardsHtml() {
    const clList = (leaks.colocation || []).sort((a, b) => (b.count || 0) - (a.count || 0));
    return clList.map(cl => {
        const peerList = cl.peers || [];
        const pubkeys = peerList.map(p => typeof p === "string" ? p : p.pubkey);
        const chipHtml = peerList.map(p => {
            const pk = typeof p === "string" ? p : p.pubkey;
            const alias = typeof p === "object" ? (p.alias || pk.slice(0, 10)) : (peers[pk]?.alias || pk.slice(0, 10));
            return `<span class="chip" data-pubkey="${pk}">${escHtml(alias)}</span>`;
        }).join("");

        return `
            <div class="coloc-card" data-pubkeys='${JSON.stringify(pubkeys)}'>
                <div class="subnet">${cl.prefix || "?"} <span class="count-badge">(${cl.count || pubkeys.length} nodes)</span></div>
                <div class="peer-chips">${chipHtml}</div>
            </div>`;
    }).join("");
}

function wireColocationCardInteractions(scope = document) {
    scope.querySelectorAll(".coloc-card").forEach(card => {
        if (card.dataset.wired === "1") return;
        card.dataset.wired = "1";

        card.addEventListener("click", (e) => {
            if (e.target.classList.contains("chip")) return;
            const pubkeys = JSON.parse(card.dataset.pubkeys || "[]");
            highlightPeers(pubkeys);
        });

        card.querySelectorAll(".chip").forEach(chip => {
            chip.addEventListener("click", (e) => {
                e.stopPropagation();
                openNodeCard(chip.dataset.pubkey);
            });
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  CROSS-HIGHLIGHTING ENGINE
// ═══════════════════════════════════════════════════════════════

function highlightPeer(pubkey) {
    highlightPeers([pubkey]);
}

function highlightPeers(pubkeys) {
    highlightedPeers = new Set(pubkeys);
    updateAllHighlights();
}

function clearHighlight() {
    highlightedPeers.clear();
    selectedNodePubkey = null;
    updateAllHighlights();
}

function clearPeerHighlight({ preserveSelectedNode = false } = {}) {
    highlightedPeers.clear();
    if (!preserveSelectedNode) selectedNodePubkey = null;
    updateAllHighlights();
}

function updateAllHighlights() {
    // Q2 — Map: highlight markers
    updateMapHighlights();

    // Q3 — Suspects: highlight matching cards
    document.querySelectorAll(".suspect-card").forEach(card => {
        card.classList.toggle("highlighted", highlightedPeers.has(card.dataset.pubkey));
    });
    // Scroll to first highlighted
    const highlightedSuspect = document.querySelector(".suspect-card.highlighted");
    if (highlightedSuspect) highlightedSuspect.scrollIntoView({ block: "nearest", behavior: "smooth" });

    // Q4 — Co-location: highlight cards/chips that contain highlighted peers
    document.querySelectorAll(".coloc-card").forEach(card => {
        const pks = JSON.parse(card.dataset.pubkeys || "[]");
        const hasMatch = pks.some(pk => highlightedPeers.has(pk));
        card.classList.toggle("highlighted", hasMatch);
        card.querySelectorAll(".chip").forEach(chip => {
            chip.classList.toggle("highlighted", highlightedPeers.has(chip.dataset.pubkey));
        });
    });
    const highlightedColoc = document.querySelector(".coloc-card.highlighted");
    if (highlightedColoc) highlightedColoc.scrollIntoView({ block: "nearest", behavior: "smooth" });

    renderNodeDetailsPlaceholder();
    renderChannelsPanel();
}

// ═══════════════════════════════════════════════════════════════
//  Q3 — CHANNELS VIEW
// ═══════════════════════════════════════════════════════════════

function getActiveChannelList() {
    if (selectedNodePubkey && nodeChannels[selectedNodePubkey]?.length) {
        return {
            title: peers[selectedNodePubkey]?.alias || selectedNodePubkey.slice(0, 12) + "…",
            mode: "node",
            items: nodeChannels[selectedNodePubkey],
        };
    }
    return {
        title: "Network-wide",
        mode: "global",
        items: channels,
    };
}

function buildChannelCardHtml(item, index, maxTraffic) {
    const nodeScoped = Object.prototype.hasOwnProperty.call(item || {}, "relay_messages") || Object.prototype.hasOwnProperty.call(item || {}, "origin_messages");
    const trafficValue = nodeScoped
        ? (item.relay_messages || item.origin_messages || 0)
        : (item.timing_rows || item.message_count || 0);
    const pct = maxTraffic > 0 ? Math.max(4, (trafficValue / maxTraffic) * 100) : 4;
    const origins = (item.origin_aliases || []).slice(0, 3);
    const assoc = item.association === "origin+relay"
        ? "node: origin + relay"
        : item.association === "origin"
            ? "node: origin"
            : item.association === "relay"
                ? "node: relay"
                : null;
        const channelMeta = `${(item.message_count || 0).toLocaleString()} channel msgs · ${((((item.total_bytes || 0) / 1024) || 0).toFixed(1))} channel KB`;
    const nodeTags = [
            assoc ? `<span class="channel-tag node-tag">${assoc}</span>` : "",
            item.origin_messages ? `<span class="channel-tag node-tag">node origin msgs ${item.origin_messages.toLocaleString()}</span>` : "",
            item.relay_messages ? `<span class="channel-tag node-tag">node relay msgs ${item.relay_messages.toLocaleString()}</span>` : "",
        ].filter(Boolean).join("");
    const nodeDetailsBlock = nodeScoped
        ? `
                <div class="channel-subsection-label">Selected node activity</div>
                <div class="channel-bars">
                    <div class="channel-bar-track"><div class="channel-bar-fill" style="width:${pct}%"></div></div>
                    <span class="channel-bar-label">${(item.relay_messages || 0).toLocaleString()} node relays</span>
                </div>
                <div class="channel-tags node-tags">${nodeTags || '<span class="channel-tag node-tag">node activity in scope</span>'}</div>
            `
        : `
                <div class="channel-bars">
                    <div class="channel-bar-track"><div class="channel-bar-fill" style="width:${pct}%"></div></div>
                    <span class="channel-bar-label">${(item.timing_rows || 0).toLocaleString()} channel relays</span>
                </div>
            `;

    return `
    <div class="channel-card${highlightedPeers.size && selectedNodePubkey && nodeChannels[selectedNodePubkey]?.some(ch => ch.scid === item.scid) ? " highlighted" : ""}" data-scid="${item.scid}">
            <div class="channel-card-header">
                <div class="channel-scid">${escHtml(item.scid)}</div>
                <div class="channel-rank">#${index + 1}</div>
            </div>
            <div class="channel-meta">
                    <strong>${channelMeta}</strong>
            </div>
            ${origins.length ? `<div class="channel-origins">Origins: ${origins.map(escHtml).join(", ")}</div>` : ""}
                <div class="channel-tags">
                    <span class="channel-tag">channel CA ${(item.channel_announcement_count || 0).toLocaleString()}</span>
                    <span class="channel-tag">channel NA ${(item.node_announcement_count || 0).toLocaleString()}</span>
                    <span class="channel-tag">channel CU ${(item.channel_update_count || 0).toLocaleString()}</span>
                </div>
                ${nodeDetailsBlock}
        </div>
    `;
}

function renderChannelsPanel() {
    const root = document.getElementById("channels-panel-root");
    const badge = document.getElementById("suspect-badge");
    if (!root || !badge) return;

    const active = getActiveChannelList();
    const availableItems = Array.isArray(active.items) ? active.items : [];
    const displayLimit = active.mode === "node" ? availableItems.length : 30;
    let items = availableItems.slice(0, displayLimit);

    if (active.mode === "node") {
        items = items.filter(item => item && item.scid);
    }

    const isTruncated = availableItems.length > items.length;

    if (!items.length) {
        badge.textContent = selectedNodePubkey ? "0 linked" : `${(summary.total_channels_indexed || channels.length || 0).toLocaleString()} tracked`;
        root.innerHTML = `<div class="channel-empty">${selectedNodePubkey ? "No channel activity indexed yet for this node." : "No channel data loaded."}</div>`;
        return;
    }

    const maxTraffic = Math.max(
        ...items.map(item => selectedNodePubkey ? (item.relay_messages || item.origin_messages || 0) : (item.timing_rows || item.message_count || 0)),
        1,
    );
    badge.textContent = selectedNodePubkey
        ? `${items.length.toLocaleString()} linked`
        : `${items.length.toLocaleString()} shown`;
    root.innerHTML = `
        <div class="channel-panel">
            <div class="channel-summary">
                ${active.mode === "node"
                    ? `<strong>${escHtml(active.title)}</strong> — showing ${items.length.toLocaleString()} node-associated channels whose messages intersect with the current global visible channel universe. Top metadata and channel tags are channel-wide aggregates; the orange bar and lower tags are filtered to the selected node.`
                    : `<strong>${escHtml(active.title)}</strong> — showing the top ${items.length.toLocaleString()} channels ranked by observed relay footprint, then message count, then gossip payload size.${isTruncated ? ` (${availableItems.length.toLocaleString()} tracked total)` : ""}`}
            </div>
            <div class="channel-list">
                ${items.map((item, index) => buildChannelCardHtml(item, index, maxTraffic)).join("")}
            </div>
        </div>
    `;

    updateHeaderStats(active, items);
}

function updateHeaderStats(active = getActiveChannelList(), visibleChannelItems = null) {
    const statPeers = document.getElementById("stat-peers");
    const statMsgs = document.getElementById("stat-msgs");
    const statIps = document.getElementById("stat-ips");
    if (!statPeers || !statMsgs || !statIps) return;

    const universe = getActiveMessageUniverse(active, visibleChannelItems);

    const scopedMappedCount = universe.mappedPeerCount;
    const scopedMessageCount = universe.messageCount;
    const scopedPeerCount = universe.peerCount;

    statPeers.textContent = scopedPeerCount.toLocaleString();
    statMsgs.textContent = scopedMessageCount.toLocaleString();
    statIps.textContent = scopedMappedCount.toLocaleString();
}

// ═══════════════════════════════════════════════════════════════
//  Q2 — MAP
// ═══════════════════════════════════════════════════════════════

function initMap() {
    leafletMap = L.map("map-container", {
        center: DEFAULT_MAP_VIEW.center,
        zoom: DEFAULT_MAP_VIEW.zoom,
        zoomControl: false,
        attributionControl: false,
    });
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        maxZoom: 18,
    }).addTo(leafletMap);
    L.control.zoom({ position: "bottomright" }).addTo(leafletMap);
    leafletMap.on("click", () => clearHighlight());
    setTimeout(() => leafletMap.invalidateSize(), 200);
}

function renderAllMapMarkers() {
    if (!leafletMap) return;
    for (const [pk, peer] of Object.entries(peers)) {
        if (!Number.isFinite(peer.lat) || !Number.isFinite(peer.lon)) continue;
        const color = getCommunityColor(peer.community);
        const marker = L.circleMarker([peer.lat, peer.lon], {
            radius: 4,
            fillColor: color,
            color: "#0a0a0f",
            fillOpacity: 0.7,
            weight: 1,
        });
        marker.bindTooltip(
            `<b>${escHtml(peer.alias || "?")}</b><br>${peer.ip || "tor"}<br>${peer.city || ""}, ${peer.country || ""}`,
        );
        marker.on("click", (e) => {
            L.DomEvent.stopPropagation(e);
            if (highlightedPeers.size === 1 && highlightedPeers.has(pk)) {
                clearHighlight();
                closeNodeCard();
                return;
            }
            openNodeCard(pk);
        });
        marker.addTo(leafletMap);
        mapMarkers[pk] = marker;
    }
}

function updateMapHighlights() {
    for (const [pk, marker] of Object.entries(mapMarkers)) {
        const isHL = highlightedPeers.has(pk);
        const peer = peers[pk];
        const baseColor = getCommunityColor(peer?.community);
        marker.setStyle({
            radius: isHL ? 8 : 4,
            fillColor: isHL ? "#ff6b35" : baseColor,
            color: isHL ? "#ff6b35" : "#0a0a0f",
            fillOpacity: highlightedPeers.size === 0 ? 0.7 : (isHL ? 1 : 0.15),
            weight: isHL ? 2 : 1,
        });
        if (isHL) marker.bringToFront();
    }
    // If single peer highlighted with coords, pan to it
    if (highlightedPeers.size === 1) {
        const pk = [...highlightedPeers][0];
        const peer = peers[pk];
        if (Number.isFinite(peer?.lat) && Number.isFinite(peer?.lon)) {
            leafletMap.flyTo([peer.lat, peer.lon], 5, { duration: 0.5 });
        }
    } else if (highlightedPeers.size > 1) {
        // Fit bounds to all highlighted peers with coords
        const coords = [...highlightedPeers]
            .map(pk => peers[pk])
            .filter(p => Number.isFinite(p?.lat) && Number.isFinite(p?.lon))
            .map(p => [p.lat, p.lon]);
        if (coords.length > 1) {
            leafletMap.flyToBounds(L.latLngBounds(coords).pad(0.3), { duration: 0.5 });
        } else if (coords.length === 1) {
            leafletMap.flyTo(coords[0], 5, { duration: 0.5 });
        }
    } else if (leafletMap) {
        leafletMap.flyTo(DEFAULT_MAP_VIEW.center, DEFAULT_MAP_VIEW.zoom, { duration: 0.5 });
    }
}

// Update map colors based on current wavefront arrival
function updateMapForWavefront() {
    if (!currentWavefront.length) return;
    const maxDelay = currentMsg?.time_spread_ms || 5000;

    for (const [pk, marker] of Object.entries(mapMarkers)) {
        const state = peerStates[pk];
        if (!state || state.delay === Infinity) {
            marker.setStyle({ fillOpacity: 0.1, radius: 3 });
        } else {
            const frac = Math.min(1, state.delay / maxDelay);
            const color = lerpColor("#ff6b35", "#457b9d", frac);
            marker.setStyle({
                fillColor: color,
                fillOpacity: 0.8,
                radius: 5,
            });
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  MESSAGE SELECTION & ANIMATION
// ═══════════════════════════════════════════════════════════════

async function selectMessage(msg) {
    currentMsg = msg;

    // Highlight active in list
    document.querySelectorAll(".msg-item").forEach(el => el.classList.remove("active"));
    renderMessageList(replayFilterType);
    renderMessageIntel(msg);
    setMessageDetailMode(messageDetailMode);
}

// ═══════════════════════════════════════════════════════════════
//  CANVAS DRAWING
// ═══════════════════════════════════════════════════════════════

function drawFrame(elapsedMs) {
    ctx.clearRect(0, 0, W, H);
    if (!W || !H) return;

    const cx = W / 2, cy = H / 2;
    const maxR = Math.min(W, H) * 0.42;
    const hasHL = highlightedPeers.size > 0;

    // Concentric rings
    for (let i = 1; i <= 4; i++) {
        ctx.beginPath();
        ctx.arc(cx, cy, maxR * i / 4, 0, Math.PI * 2);
        ctx.strokeStyle = "#1a1a2e";
        ctx.lineWidth = 0.5;
        ctx.stroke();
    }

    // Observer dot
    ctx.beginPath();
    ctx.arc(cx, cy, 4, 0, Math.PI * 2);
    ctx.fillStyle = "#ff6b35";
    ctx.fill();

    // Wavefront ring
    if (currentWavefront.length > 0 && elapsedMs > 0) {
        const maxD = currentMsg?.time_spread_ms || 5000;
        const frac = Math.min(1, elapsedMs / maxD);
        ctx.beginPath();
        ctx.arc(cx, cy, frac * maxR, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255,107,53,${0.25 * (1 - frac)})`;
        ctx.lineWidth = 2;
        ctx.stroke();
    }

    // Peers
    for (const [ph, pos] of Object.entries(peerPositions)) {
        const state = peerStates[ph];
        const peer = peers[ph];
        if (!pos) continue;

        const isLit = state && state.delay <= elapsedMs;
        const isHL = highlightedPeers.has(ph);
        const dimmed = hasHL && !isHL;
        const color = getCommunityColor(peer?.community);

        if (isLit) {
            const freshness = Math.max(0, 1 - (elapsedMs - state.delay) / 2000);

            // Glow
            if (freshness > 0 && !dimmed) {
                ctx.beginPath();
                ctx.arc(pos.x, pos.y, 3 + freshness * 6, 0, Math.PI * 2);
                ctx.fillStyle = (isHL ? "#ff6b35" : color) + "25";
                ctx.fill();
            }

            // Dot
            ctx.beginPath();
            const r = isHL ? 5 : 3;
            ctx.arc(pos.x, pos.y, r, 0, Math.PI * 2);
            ctx.fillStyle = dimmed ? "#2a2a3e" : (isHL ? "#ff6b35" : color);
            ctx.globalAlpha = dimmed ? 0.3 : 1;
            ctx.fill();
            ctx.globalAlpha = 1;

            // Highlight ring
            if (isHL) {
                ctx.beginPath();
                ctx.arc(pos.x, pos.y, 7, 0, Math.PI * 2);
                ctx.strokeStyle = "#ff6b35";
                ctx.lineWidth = 1.5;
                ctx.stroke();
            }

            // Label for highlighted peers
            if (isHL && peer) {
                ctx.font = "bold 9px monospace";
                ctx.fillStyle = "#ff6b35";
                ctx.textAlign = "left";
                ctx.fillText(peer.alias || ph.slice(0, 8), pos.x + 10, pos.y + 3);
            }
        } else {
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, isHL ? 4 : 1.5, 0, Math.PI * 2);
            ctx.fillStyle = isHL ? "#ff6b3580" : (dimmed ? "#151520" : "#1e1e2e");
            ctx.fill();
            if (isHL) {
                ctx.beginPath();
                ctx.arc(pos.x, pos.y, 6, 0, Math.PI * 2);
                ctx.strokeStyle = "#ff6b3550";
                ctx.lineWidth = 1;
                ctx.stroke();
            }
        }
    }

}

// ═══════════════════════════════════════════════════════════════
//  CANVAS INTERACTION
// ═══════════════════════════════════════════════════════════════

function findClosestPeer(mx, my, threshold = 15) {
    let closest = null, closestDist = threshold;
    for (const [ph, pos] of Object.entries(peerPositions)) {
        const d = Math.hypot(pos.x - mx, pos.y - my);
        if (d < closestDist) { closest = ph; closestDist = d; }
    }
    return closest;
}

function handleCanvasHover(e) {
    const rect = canvas.getBoundingClientRect();
    const pk = findClosestPeer(e.clientX - rect.left, e.clientY - rect.top);
    if (pk) {
        const peer = peers[pk] || {};
        const state = peerStates[pk] || {};
        const isSuspect = (leaks.first_responders || []).some(fr => (fr.pubkey || "") === pk);
        const tt = document.getElementById("tooltip");
        tt.innerHTML = `
            <div class="t-alias">${escHtml(peer.alias || "Unknown")} ${isSuspect ? "⚠️" : ""}</div>
            <div class="t-pubkey">${pk}</div>
            ${peer.ip ? `<div class="t-ip">🌐 ${peer.ip} · ${peer.city || ""} ${peer.country || ""}</div>` : '<div style="color:#555">🧅 Tor-only</div>'}
            <div class="t-score">
                Avg arrival: ${((peer.avg_arrival_pct || 0) * 100).toFixed(1)}th pct<br>
                ${state.delay < Infinity ? `This msg: +${state.delay.toFixed(0)}ms` : "Not in this message"}
            </div>
            ${isSuspect ? '<div class="t-warn">⚠ Heuristic signal: consistently fast relay (not attribution proof)</div>' : ""}`;
        tt.style.display = "block";
        tt.style.left = (e.clientX + 12) + "px";
        tt.style.top = (e.clientY - 10) + "px";
    } else {
        hideTooltip();
    }
}

function handleCanvasClick(e) {
    const rect = canvas.getBoundingClientRect();
    const pk = findClosestPeer(e.clientX - rect.left, e.clientY - rect.top);
    if (pk) {
        openNodeCard(pk);
    } else {
        clearHighlight();
    }
}

// ═══════════════════════════════════════════════════════════════
//  TOOLTIP
// ═══════════════════════════════════════════════════════════════

function showPeerTooltip(pk, refEl) {
    const peer = peers[pk] || {};
    const tt = document.getElementById("tooltip");
    const isSuspect = (leaks.first_responders || []).some(fr => (fr.pubkey || "") === pk);
    tt.innerHTML = `
        <div class="t-alias">${escHtml(peer.alias || pk.slice(0, 16))}</div>
        <div class="t-pubkey">${pk}</div>
        ${peer.ip ? `<div class="t-ip">🌐 ${peer.ip} · ${peer.city || ""} ${peer.country || ""}</div>` : '<div style="color:#555">🧅 Tor-only</div>'}
        <div class="t-score">
            Avg arrival: ${((peer.avg_arrival_pct || 0) * 100).toFixed(1)}th pct ·
            Msgs: ${(peer.messages_seen || 0).toLocaleString()}
        </div>
        ${isSuspect ? '<div class="t-warn">⚠ Consistently fast relay</div>' : ""}`;
    tt.style.display = "block";
    const rect = refEl.getBoundingClientRect();
    tt.style.left = (rect.right + 8) + "px";
    tt.style.top = rect.top + "px";
}

function hideTooltip() {
    document.getElementById("tooltip").style.display = "none";
}

// ═══════════════════════════════════════════════════════════════
//  THREAT INDICATOR BAR
// ═══════════════════════════════════════════════════════════════

function computeAndRenderThreats() {
    const totalFp = Object.keys(fpByPubkey).length;
    const observedPeerCount = Object.keys(peers).length;
    const observedPeerSet = new Set(Object.keys(peers));
    // For each threat, collect the set of affected pubkeys
    const threatData = THREAT_DEFS.map(def => {
        const affected = [];
        for (const [pk, fpInfo] of Object.entries(fpByPubkey)) {
            const has = fpInfo.feature_names.includes(def.feature);
            if ((def.mode === "present" && has) || (def.mode === "absent" && !has)) {
                affected.push(pk);
            }
        }
        const observedCount = affected.filter(pk => observedPeerSet.has(pk)).length;
        return {
            ...def,
            affected,
            count: affected.length,
            pct: totalFp ? ((affected.length / totalFp) * 100).toFixed(1) : "0",
            observed_count: observedCount,
            observed_pct: observedPeerCount ? ((observedCount / observedPeerCount) * 100).toFixed(1) : "0",
        };
    });

    // Sort descending by count
    threatData.sort((a, b) => b.count - a.count);

    const bar = document.getElementById("threat-bar");
    if (!bar) return;
    bar.innerHTML = "";

    // ── Slot 1: Feature risk signals → opens the big card ──
    const totalAffected = new Set(threatData.flatMap(td => td.affected)).size;
    const slot1 = document.createElement("div");
    slot1.className = "threat-slot";
    slot1.innerHTML = `
        <span class="ts-icon">🛡️</span>
        <span class="ts-count" style="color:#e63946">${totalAffected.toLocaleString()}</span>
        <span class="ts-label">Feature Risk Signals</span>
        <span class="ts-sev sev-high">${threatData.length}</span>
    `;
    slot1.addEventListener("click", (e) => {
        e.stopPropagation();
        openThreatCard(threatData, totalFp);
    });
    bar.appendChild(slot1);

    // ── Slot 2: Peer Profiling (Infrastructure & AS Concentration) ──
    const infraStats = computeInfraStats();
    const slot2 = document.createElement("div");
    slot2.className = "threat-slot";
    slot2.innerHTML = `
        <span class="ts-icon">🕵️</span>
        <span class="ts-count" style="color:#e9c46a">${infraStats.sameOpNodes}</span>
        <span class="ts-label">Peer Profiling</span>
        <span class="ts-sev sev-medium">${infraStats.clusterCount}</span>
    `;
    slot2.addEventListener("click", (e) => {
        e.stopPropagation();
        openPeerProfilingCard(infraStats);
    });
    bar.appendChild(slot2);

    // ── Slot 3: Co-location signals popup ──
    const colocGroups = leaks.colocation || [];
    const slot3 = document.createElement("div");
    slot3.className = "threat-slot";
    slot3.innerHTML = `
        <span class="ts-icon">📍</span>
        <span class="ts-count" style="color:#e9c46a">${colocGroups.length}</span>
        <span class="ts-label">Co-Location Signals</span>
        <span class="ts-sev sev-medium">/24</span>
    `;
    slot3.addEventListener("click", (e) => {
        e.stopPropagation();
        openColocationCard();
    });
    bar.appendChild(slot3);

    // ── Slot 4: Fast relay heuristics popup ──
    const fastRelayers = leaks.first_responders || [];
    const slot4 = document.createElement("div");
    slot4.className = "threat-slot";
    slot4.innerHTML = `
        <span class="ts-icon">🔍</span>
        <span class="ts-count" style="color:#e63946">${fastRelayers.length}</span>
        <span class="ts-label">Fast Relay Heuristics</span>
        <span class="ts-sev sev-high">timing</span>
    `;
    slot4.addEventListener("click", (e) => {
        e.stopPropagation();
        openFastRelayCard();
    });
    bar.appendChild(slot4);

    // ── Slots 5-7: Placeholders ──
    const placeholders = [
        { icon: "🔐", label: "Privacy Leaks" },
        { icon: "⏱️", label: "Timing Attacks" },
        { icon: "🗺️", label: "Geo Clustering" },
    ];
    placeholders.forEach(ph => {
        const slot = document.createElement("div");
        slot.className = "threat-slot placeholder";
        slot.innerHTML = `
            <span class="ts-icon">${ph.icon}</span>
            <span class="ts-count" style="color:#333">—</span>
            <span class="ts-label">${ph.label}</span>
            <span class="ts-sev" style="background:#1a1a2e;color:#333">soon</span>
        `;
        bar.appendChild(slot);
    });
}

// ═══════════════════════════════════════════════════════════════
//  PEER PROFILING — Infrastructure & AS Concentration
// ═══════════════════════════════════════════════════════════════

function computeInfraStats() {
    const totalPeers = Object.keys(peers).length;
    const clearnet = {}, torPeers = {};
    for (const [pk, v] of Object.entries(peers)) {
        if (v.is_tor) torPeers[pk] = v; else clearnet[pk] = v;
    }
    const totalClearnet = Object.keys(clearnet).length;
    const totalTor = Object.keys(torPeers).length;

    // --- AS Concentration ---
    const asCounter = {};
    const ispCounter = {};
    for (const v of Object.values(clearnet)) {
        const ai = v.as_info || "";
        const isp = v.isp || "";
        if (ai) asCounter[ai] = (asCounter[ai] || 0) + 1;
        if (isp) ispCounter[isp] = (ispCounter[isp] || 0) + 1;
    }
    const asSorted = Object.entries(asCounter).sort((a, b) => b[1] - a[1]);
    const ispSorted = Object.entries(ispCounter).sort((a, b) => b[1] - a[1]);

    // Top N
    const top3AS = asSorted.slice(0, 3);
    const top5AS = asSorted.slice(0, 5);
    const top10AS = asSorted.slice(0, 10);
    const top3Pct = totalClearnet ? top3AS.reduce((s, [, c]) => s + c, 0) / totalClearnet * 100 : 0;
    const top5Pct = totalClearnet ? top5AS.reduce((s, [, c]) => s + c, 0) / totalClearnet * 100 : 0;
    const top10Pct = totalClearnet ? top10AS.reduce((s, [, c]) => s + c, 0) / totalClearnet * 100 : 0;

    // HHI
    const shares = Object.values(asCounter).map(c => c / (totalClearnet || 1));
    const hhi = shares.reduce((s, sh) => s + sh * sh, 0);

    // Combined providers
    const amazonTotal = Object.entries(asCounter).filter(([k]) => k.toLowerCase().includes("amazon")).reduce((s, [, c]) => s + c, 0);
    const hetznerTotal = Object.entries(asCounter).filter(([k]) => k.toLowerCase().includes("hetzner")).reduce((s, [, c]) => s + c, 0);
    const contaboTotal = Object.entries(asCounter).filter(([k]) => k.toLowerCase().includes("contabo")).reduce((s, [, c]) => s + c, 0);

    // --- Country Concentration ---
    const countryCounter = {};
    for (const v of Object.values(clearnet)) {
        const c = v.country || "";
        if (c) countryCounter[c] = (countryCounter[c] || 0) + 1;
    }
    const countrySorted = Object.entries(countryCounter).sort((a, b) => b[1] - a[1]);

    // --- Same-Operator Clusters (AS + fingerprint) ---
    const clusters = {};
    for (const pk of Object.keys(clearnet)) {
        const asInfo = clearnet[pk].as_info || "";
        const fpHex = fpByPubkey[pk]?.features_hex || "";
        if (asInfo && fpHex) {
            const key = asInfo + "|||" + fpHex;
            if (!clusters[key]) clusters[key] = { as: asInfo, fp: fpHex, nodes: [] };
            clusters[key].nodes.push(pk);
        }
    }
    const bigClusters = Object.values(clusters).filter(c => c.nodes.length >= 3)
        .sort((a, b) => b.nodes.length - a.nodes.length);

    const sameOpNodes = bigClusters.reduce((s, c) => s + c.nodes.length, 0);

    return {
        totalPeers, totalClearnet, totalTor,
        asSorted, ispSorted, top3AS, top5AS, top10AS,
        top3Pct, top5Pct, top10Pct,
        hhi, uniqueASes: asSorted.length,
        amazonTotal, hetznerTotal, contaboTotal,
        countrySorted,
        bigClusters, sameOpNodes, clusterCount: bigClusters.length,
    };
}

function openPeerProfilingCard(stats) {
    const overlay = document.getElementById("threat-card-overlay");
    const card = document.getElementById("threat-card");

    // ── Section 1: AS Concentration ──
    const asBarItems = stats.top10AS.map(([name, cnt], i) => {
        const palette = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f", "#a855f7", "#f97316", "#06b6d4", "#84cc16", "#f472b6", "#555"];
        return { label: name.replace(/^AS\d+\s*/, "").slice(0, 20), value: cnt, color: palette[i % palette.length] };
    });
    const asViz = svgHBars(asBarItems, 200, 13);

    const combinedViz = svgHBars([
        { label: "Amazon (all ASes)", value: stats.amazonTotal, color: "#e63946" },
        { label: "Hetzner (all ASes)", value: stats.hetznerTotal, color: "#e9c46a" },
        { label: "Contabo (all ASes)", value: stats.contaboTotal, color: "#457b9d" },
    ], 200, 13);

    const asDonut = svgDonut([
        { value: stats.top3AS.reduce((s, [, c]) => s + c, 0), color: "#e63946", label: "Top 3 ASes" },
        { value: stats.top5AS.reduce((s, [, c]) => s + c, 0) - stats.top3AS.reduce((s, [, c]) => s + c, 0), color: "#e9c46a", label: "4th–5th" },
        { value: stats.totalClearnet - stats.top5AS.reduce((s, [, c]) => s + c, 0), color: "#457b9d", label: "Other" },
    ], 56);

    // ── Section 2: Same-Operator Clusters ──
    const clusterItems = stats.bigClusters.slice(0, 12).map((c, i) => {
        const asShort = c.as.replace(/^AS\d+\s*/, "").slice(0, 16);
        const aliases = c.nodes.slice(0, 2).map(pk => (peers[pk]?.alias || pk.slice(0, 8)).slice(0, 12));
        const palette = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f", "#a855f7", "#f97316", "#06b6d4", "#84cc16", "#f472b6", "#64748b", "#555", "#ec4899"];
        return { label: `${asShort} (${aliases.join(", ")})`, value: c.nodes.length, color: palette[i % palette.length] };
    });
    const clusterViz = svgHBars(clusterItems, 200, 13);

    // ── Section 3: Single Points of Failure ──
    const spofItems = stats.top5AS.map(([name, cnt], i) => {
        const palette = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f", "#a855f7"];
        return { label: name.replace(/^AS\d+\s*/, "").slice(0, 20), value: cnt, color: palette[i] };
    });
    const spofViz = svgHBars(spofItems, 200, 13);

    const torDonut = svgDonut([
        { value: stats.totalClearnet, color: "#e63946", label: "Clearnet" },
        { value: stats.totalTor, color: "#2a9d8f", label: "Tor" },
    ], 56);

    // ── Section 4: Country Concentration ──
    const countryItems = stats.countrySorted.slice(0, 8).map(([name, cnt], i) => {
        const palette = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f", "#a855f7", "#f97316", "#06b6d4", "#84cc16"];
        return { label: name, value: cnt, color: palette[i % palette.length] };
    });
    const countryViz = svgHBars(countryItems, 200, 13);

    // ── Sections definition ──
    const sections = [
        {
            icon: "🏢", name: "AS Concentration", severity: "high",
            stat: `Top 3 → ${stats.top3Pct.toFixed(1)}% · HHI ${stats.hhi.toFixed(3)}`,
            attack: `${stats.uniqueASes} unique ASes host ${stats.totalClearnet} clearnet peers. The top 3 ASes alone control ${stats.top3Pct.toFixed(1)}% of observable nodes — Amazon (${stats.amazonTotal}), Cogent, Hetzner dominate. A single BGP hijack or legal subpoena to one AS could surveil or disrupt a significant fraction of the Lightning Network. HHI of ${stats.hhi.toFixed(3)} indicates moderate concentration.`,
            source: "peers.json AS data via ip-api.com · gossip_observer",
            viz: `<div style="font-size:9px;color:#666;margin-bottom:4px">Top 10 ASes by node count</div>${asViz}
                  <div style="margin-top:8px;font-size:9px;color:#666;margin-bottom:4px">Combined provider footprint</div>${combinedViz}
                  <div style="margin-top:8px;font-size:9px;color:#666;margin-bottom:4px">AS share distribution</div>${asDonut}`,
        },
        {
            icon: "👥", name: "Same-Operator Clusters", severity: "medium",
            stat: `${stats.clusterCount} clusters · ${stats.sameOpNodes} nodes`,
            attack: `Nodes sharing the same AS <em>and</em> the same feature fingerprint likely belong to the same operator. ${stats.clusterCount} clusters of ≥3 nodes were detected, comprising ${stats.sameOpNodes} nodes. The largest cluster has ${stats.bigClusters[0]?.nodes.length || 0} nodes in a single AS with identical software. This creates correlated failure risk and reduces effective network decentralization.`,
            source: "peers.json AS data + fingerprints.json · gossip_observer",
            viz: `<div style="font-size:9px;color:#666;margin-bottom:4px">Largest same-operator clusters (AS + fingerprint, ≥3 nodes)</div>${clusterViz}`,
        },
        {
            icon: "💥", name: "Single Points of Failure", severity: "high",
            stat: `Top AS down → ${stats.top5AS[0]?.[1] || 0} lost (${((stats.top5AS[0]?.[1] || 0) / (stats.totalClearnet || 1) * 100).toFixed(1)}%)`,
            attack: `If the top hosting provider (${stats.top5AS[0]?.[0]?.replace(/^AS\d+\s*/, "") || "?"}) suffers an outage, ${stats.top5AS[0]?.[1] || 0} clearnet peers (${((stats.top5AS[0]?.[1] || 0) / (stats.totalClearnet || 1) * 100).toFixed(1)}%) go offline simultaneously. Combined Amazon ASes host ${stats.amazonTotal} nodes (${(stats.amazonTotal / (stats.totalClearnet || 1) * 100).toFixed(1)}%). ${stats.totalTor} Tor peers (${(stats.totalTor / (stats.totalPeers || 1) * 100).toFixed(1)}% of network) have no geo/AS data — invisible to infrastructure analysis but also represent a hidden concentration risk if most route through the same exit nodes.`,
            source: "peers.json AS/ISP data · gossip_observer",
            viz: `<div style="font-size:9px;color:#666;margin-bottom:4px">Impact of top-5 AS outages on clearnet</div>${spofViz}
                  <div style="margin-top:8px;font-size:9px;color:#666;margin-bottom:4px">Network transport split</div>${torDonut}`,
        },
        {
            icon: "🌍", name: "Geographic Jurisdiction Risk", severity: "medium",
            stat: `${stats.countrySorted[0]?.[0] || "?"}: ${((stats.countrySorted[0]?.[1] || 0) / (stats.totalClearnet || 1) * 100).toFixed(1)}%`,
            attack: `${stats.countrySorted[0]?.[0] || "?"} hosts ${stats.countrySorted[0]?.[1] || 0} clearnet peers (${((stats.countrySorted[0]?.[1] || 0) / (stats.totalClearnet || 1) * 100).toFixed(1)}%). The top 3 countries cover ${((stats.countrySorted.slice(0, 3).reduce((s, [, c]) => s + c, 0)) / (stats.totalClearnet || 1) * 100).toFixed(1)}%. A coordinated regulatory action across just 2–3 jurisdictions could impact a majority of observable Lightning nodes. Geographic concentration also correlates with latency clustering, making timing attacks easier within the same jurisdiction.`,
            source: "peers.json geo data via ip-api.com · gossip_observer",
            viz: `<div style="font-size:9px;color:#666;margin-bottom:4px">Clearnet peers by country</div>${countryViz}`,
        },
    ];

    // ── Render card ──
    const sectionsHtml = sections.map((sec, idx) => {
        const sevColor = sec.severity === "high" ? "#e63946" : sec.severity === "medium" ? "#e9c46a" : "#457b9d";
        return `
        <div class="tc-section${idx === 0 ? ' open' : ''}" data-tc-idx="${idx}">
            <div class="tc-section-header">
                <div class="tc-section-left">
                    <span class="tc-section-icon">${sec.icon}</span>
                    <span class="tc-section-name" style="color:${sevColor}">${sec.name}</span>
                    <span class="ts-sev sev-${sec.severity}" style="font-size:8px;margin-left:4px">${sec.severity}</span>
                </div>
                <div class="tc-section-right">
                    <span class="tc-section-count" style="color:${sevColor};font-size:9px">${sec.stat}</span>
                    <span class="tc-section-chevron">▶</span>
                </div>
            </div>
            <div class="tc-section-body">
                <div class="tc-attack-desc">${sec.attack}</div>
                <div class="tc-source">Source: ${sec.source}</div>
                <div style="margin-top:8px;padding-top:6px;border-top:1px solid #1a1a2e">
                    ${sec.viz}
                </div>
            </div>
        </div>`;
    }).join("");

    card.innerHTML = `
        <div class="tc-header">
            <div class="tc-title">🕵️ Peer Profiling — Infrastructure & AS Concentration</div>
            <button class="tc-close" id="tc-close-btn">✕</button>
        </div>
        <div class="tc-summary">
            ${stats.totalPeers} peers observed · ${stats.totalClearnet} clearnet · ${stats.totalTor} Tor · ${stats.uniqueASes} unique ASes · ${stats.clusterCount} same-operator clusters
        </div>
        ${sectionsHtml}
    `;

    overlay.classList.add("open");

    document.getElementById("tc-close-btn").addEventListener("click", (e) => {
        e.stopPropagation();
        overlay.classList.remove("open");
    });
    overlay.addEventListener("click", (e) => {
        if (e.target === overlay) overlay.classList.remove("open");
    });
    card.querySelectorAll(".tc-section-header").forEach(header => {
        header.addEventListener("click", (e) => {
            e.stopPropagation();
            header.closest(".tc-section").classList.toggle("open");
        });
    });
}

function openColocationCard() {
    const overlay = document.getElementById("threat-card-overlay");
    const card = document.getElementById("threat-card");
    const colocGroups = (leaks.colocation || []).sort((a, b) => (b.count || 0) - (a.count || 0));

    card.innerHTML = `
        <div class="tc-header">
            <div class="tc-title">📍 Co-Location Signals (/24)</div>
            <button class="tc-close" id="tc-close-btn">✕</button>
        </div>
        <div class="tc-summary">
            ${colocGroups.length} groups detected · shared IPv4 /24 prefixes are a hosting/co-location signal, not proof of common control.
        </div>
        <div style="padding:10px 12px;max-height:70vh;overflow-y:auto;">
            <div style="font-size:10px;color:#999;line-height:1.5;margin-bottom:10px;">
                Click a card to highlight the whole group across the dashboard, or click an individual node chip to open its node card.
            </div>
            <div class="coloc-list" id="coloc-popup-list">${buildColocationCardsHtml()}</div>
        </div>
    `;

    overlay.classList.add("open");
    document.getElementById("tc-close-btn").addEventListener("click", (e) => {
        e.stopPropagation();
        overlay.classList.remove("open");
    });
    wireColocationCardInteractions(card);
}

function openFastRelayCard() {
    const overlay = document.getElementById("threat-card-overlay");
    const card = document.getElementById("threat-card");
    const frList = (leaks.first_responders || [])
        .sort((a, b) => (a.avg_arrival_pct || 0) - (b.avg_arrival_pct || 0));

    card.innerHTML = `
        <div class="tc-header">
            <div class="tc-title">🔍 Fast Relay Heuristics</div>
            <button class="tc-close" id="tc-close-btn">✕</button>
        </div>
        <div class="tc-summary">
            ${frList.length} peers flagged by fixed timing heuristics. These are strong relay-timing signals, not proof of surveillance.
        </div>
        <div style="padding:10px 12px;max-height:70vh;overflow-y:auto;">
            <div style="font-size:10px;color:#999;line-height:1.5;margin-bottom:10px;">
                Click a peer card to open its node details. Hover a card to inspect key relay metrics quickly.
            </div>
            <div class="suspect-list" id="suspect-popup-list">${buildSuspectsHtml()}</div>
        </div>
    `;

    overlay.classList.add("open");
    document.getElementById("tc-close-btn").addEventListener("click", (e) => {
        e.stopPropagation();
        overlay.classList.remove("open");
    });
    wireSuspectCardInteractions(card);
}

// ── Threat Report Card (full overlay) ──

// ── SVG chart helpers ──

function svgDonut(slices, size = 64) {
    // slices: [{value, color, label}]
    const total = slices.reduce((s, d) => s + d.value, 0);
    if (!total) return '<div style="font-size:9px;color:#555">No data</div>';
    const cx = size / 2, cy = size / 2, r = size * 0.36, r2 = size * 0.22;
    let cumAngle = -Math.PI / 2;
    let paths = "";
    slices.forEach(sl => {
        if (!sl.value) return;
        const frac = sl.value / total;
        const angle = frac * 2 * Math.PI;
        const large = angle > Math.PI ? 1 : 0;
        const x1 = cx + r * Math.cos(cumAngle), y1 = cy + r * Math.sin(cumAngle);
        const x2 = cx + r * Math.cos(cumAngle + angle), y2 = cy + r * Math.sin(cumAngle + angle);
        const x3 = cx + r2 * Math.cos(cumAngle + angle), y3 = cy + r2 * Math.sin(cumAngle + angle);
        const x4 = cx + r2 * Math.cos(cumAngle), y4 = cy + r2 * Math.sin(cumAngle);
        paths += `<path d="M${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2} L${x3},${y3} A${r2},${r2} 0 ${large} 0 ${x4},${y4}Z" fill="${sl.color}"><title>${sl.label}: ${sl.value} (${(frac*100).toFixed(0)}%)</title></path>`;
        cumAngle += angle;
    });
    const legend = slices.filter(s => s.value).map(s =>
        `<span style="display:inline-flex;align-items:center;gap:3px;margin-right:8px"><span style="width:7px;height:7px;border-radius:50%;background:${s.color};display:inline-block"></span>${s.label} ${s.value}</span>`
    ).join("");
    return `<div style="display:flex;align-items:center;gap:10px">
        <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${paths}</svg>
        <div style="font-size:8px;color:#aaa;line-height:1.6">${legend}</div>
    </div>`;
}

function svgHBars(items, maxW = 220, barH = 14) {
    // items: [{label, value, color}] — sqrt scale for perceptible differences
    if (!items.length) return '<div style="font-size:9px;color:#555">No data</div>';
    const maxSqrt = Math.sqrt(Math.max(...items.map(it => it.value)) || 1);
    // Compute label column width: measure longest label, clamp to [80, 150]
    const labelW = Math.min(150, Math.max(80, Math.max(...items.map(it => it.label.length)) * 5.5));
    return items.map(it => {
        const w = it.value ? Math.max(8, (Math.sqrt(it.value) / maxSqrt) * maxW) : 0;
        const numOutside = w < 30;
        return `<div style="display:flex;align-items:center;gap:6px;margin-bottom:2px">
            <span style="font-size:8px;color:#888;width:${labelW}px;flex-shrink:0;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(it.label)}">${escHtml(it.label)}</span>
            <div style="display:flex;align-items:center;gap:4px">
                <div style="height:${barH}px;width:${w}px;background:${it.color};border-radius:2px;position:relative;flex-shrink:0">
                    ${!numOutside ? `<span style="position:absolute;right:4px;top:0;font-size:8px;color:#000;line-height:${barH}px;font-weight:bold">${it.value.toLocaleString()}</span>` : ""}
                </div>
                ${numOutside && it.value ? `<span style="font-size:8px;color:${it.color};font-weight:bold">${it.value.toLocaleString()}</span>` : ""}
            </div>
        </div>`;
    }).join("");
}

function buildThreatViz(td) {
    // Classify affected nodes along a dimension relevant to each threat type
    const affected = td.affected;
    if (!affected.length) return '<div style="font-size:9px;color:#555">No affected nodes</div>';

    switch (td.id) {
        case "zero_conf": {
            // Fingerprint group size → impl clustering
            const groups = {};
            affected.forEach(pk => {
                const fp = fpByPubkey[pk];
                const gs = fp ? fp.group_size : 0;
                const bucket = gs >= 1000 ? "1000+" : gs >= 100 ? "100–999" : gs >= 10 ? "10–99" : gs >= 2 ? "2–9" : "unique";
                groups[bucket] = (groups[bucket] || 0) + 1;
            });
            const order = ["1000+", "100–999", "10–99", "2–9", "unique"];
            const colors = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f", "#555"];
            const items = order.map((b, i) => ({ label: b + " nodes", value: groups[b] || 0, color: colors[i] })).filter(x => x.value);
            return `<div style="font-size:9px;color:#666;margin-bottom:4px">By fingerprint group size (impl clustering)</div>` + svgHBars(items);
        }
        case "anchors_exploit": {
            // Tor vs clearnet
            let tor = 0, clear = 0;
            affected.forEach(pk => { (peers[pk]?.is_tor) ? tor++ : clear++; });
            return `<div style="font-size:9px;color:#666;margin-bottom:4px">Network exposure</div>` +
                svgDonut([
                    { value: clear, color: "#e63946", label: "Clearnet" },
                    { value: tor, color: "#457b9d", label: "Tor" },
                ]);
        }
        case "no_data_loss": {
            // Top countries
            const countries = {};
            affected.forEach(pk => {
                const c = peers[pk]?.country || "Unknown";
                countries[c] = (countries[c] || 0) + 1;
            });
            const sorted = Object.entries(countries).sort((a, b) => b[1] - a[1]).slice(0, 6);
            const palette = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f", "#a855f7", "#555"];
            const items = sorted.map(([c, v], i) => ({ label: c, value: v, color: palette[i % palette.length] }));
            return `<div style="font-size:9px;color:#666;margin-bottom:4px">Geographic concentration</div>` + svgHBars(items);
        }
        case "gossip_dos": {
            // Relay speed tiers
            const tiers = { "Fast (<20%)": 0, "Medium (20–50%)": 0, "Slow (50–80%)": 0, "Very slow (>80%)": 0 };
            affected.forEach(pk => {
                const p = peers[pk]?.avg_arrival_pct || 0.5;
                if (p < 0.2) tiers["Fast (<20%)"]++;
                else if (p < 0.5) tiers["Medium (20–50%)"]++;
                else if (p < 0.8) tiers["Slow (50–80%)"]++;
                else tiers["Very slow (>80%)"]++;
            });
            const colors = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f"];
            const items = Object.entries(tiers).map(([k, v], i) => ({ label: k, value: v, color: colors[i] }));
            return `<div style="font-size:9px;color:#666;margin-bottom:4px">Targetable nodes by relay centrality (faster = more central, higher impact)</div>` + svgHBars(items);
        }
        case "large_target": {
            // Activity tiers as proxy for capital exposure (more msgs seen = more connections = more BTC at risk)
            const tiers = { "> 100k msgs": 0, "10k – 100k": 0, "1k – 10k": 0, "100 – 1k": 0, "< 100 msgs": 0 };
            affected.forEach(pk => {
                const m = peers[pk]?.messages_seen || 0;
                if (m >= 100000) tiers["> 100k msgs"]++;
                else if (m >= 10000) tiers["10k – 100k"]++;
                else if (m >= 1000) tiers["1k – 10k"]++;
                else if (m >= 100) tiers["100 – 1k"]++;
                else tiers["< 100 msgs"]++;
            });
            const colors = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f", "#555"];
            const items = Object.entries(tiers).map(([k, v], i) => ({ label: k, value: v, color: colors[i] }));
            return `<div style="font-size:9px;color:#666;margin-bottom:4px">Gossip activity (proxy for connectivity & capital exposure)</div>` + svgHBars(items);
        }
        case "no_scid_alias": {
            // Tor vs clearnet — clearnet = fully deanonymized UTXOs
            let tor = 0, clear = 0;
            affected.forEach(pk => { (peers[pk]?.is_tor) ? tor++ : clear++; });
            return `<div style="font-size:9px;color:#666;margin-bottom:4px">Privacy exposure (clearnet = UTXO fully linkable)</div>` +
                svgDonut([
                    { value: clear, color: "#e63946", label: "Clearnet exposed" },
                    { value: tor, color: "#2a9d8f", label: "Tor (partial cover)" },
                ]);
        }
        case "no_chan_type": {
            // Feature count ranges → impl maturity
            const ranges = { "1–5 features": 0, "6–10 features": 0, "11–15 features": 0, "16+ features": 0 };
            affected.forEach(pk => {
                const n = fpByPubkey[pk]?.feature_names?.length || 0;
                if (n <= 5) ranges["1–5 features"]++;
                else if (n <= 10) ranges["6–10 features"]++;
                else if (n <= 15) ranges["11–15 features"]++;
                else ranges["16+ features"]++;
            });
            const colors = ["#e63946", "#e9c46a", "#457b9d", "#2a9d8f"];
            const items = Object.entries(ranges).map(([k, v], i) => ({ label: k, value: v, color: colors[i] }));
            return `<div style="font-size:9px;color:#666;margin-bottom:4px">Implementation maturity (feature count)</div>` + svgHBars(items);
        }
        default:
            return '<div style="font-size:9px;color:#555">No visualization available</div>';
    }
}

function openThreatCard(threatData, totalFp) {
    const overlay = document.getElementById("threat-card-overlay");
    const card = document.getElementById("threat-card");

    const totalAffected = new Set(threatData.flatMap(td => td.affected)).size;
    const observedPeerCount = Object.keys(peers).length;
    const totalAffectedObserved = new Set(
        threatData.flatMap(td => td.affected.filter(pk => peers[pk]))
    ).size;

    let sectionsHtml = threatData.map((td, idx) => {
        const sevColor = td.severity === "high" ? "#e63946" : td.severity === "medium" ? "#e9c46a" : "#457b9d";
        const vizHtml = buildThreatViz(td);
        return `
        <div class="tc-section${idx === 0 ? ' open' : ''}" data-tc-idx="${idx}">
            <div class="tc-section-header">
                <div class="tc-section-left">
                    <span class="tc-section-icon">${td.icon}</span>
                    <span class="tc-section-name" style="color:${sevColor}">${td.label}</span>
                    <span class="ts-sev sev-${td.severity}" style="font-size:8px;margin-left:4px">${td.severity}</span>
                </div>
                <div class="tc-section-right">
                    <span class="tc-section-count" style="color:${sevColor}">${td.count.toLocaleString()}</span>
                    <span class="tc-section-chevron">▶</span>
                </div>
            </div>
            <div class="tc-section-body">
                <div class="tc-attack-desc">
                    <span class="tc-attack-label">${td.mode === "present" ? "Feature present" : "Feature MISSING"}: ${td.feature}</span><br>
                    ${td.attack}
                </div>
                <div class="tc-source">Source: ${td.source}</div>
                <div class="tc-stat-row">
                    <span class="tc-stat-label">Affected nodes</span>
                    <span class="tc-stat-val" style="color:${sevColor}">${td.count.toLocaleString()} / ${totalFp.toLocaleString()} (${td.pct}%)</span>
                </div>
                <div class="tc-stat-row">
                    <span class="tc-stat-label">Affected in observed peers</span>
                    <span class="tc-stat-val" style="color:${sevColor}">${td.observed_count.toLocaleString()} / ${observedPeerCount.toLocaleString()} (${td.observed_pct}%)</span>
                </div>
                <div style="margin-top:8px;padding-top:6px;border-top:1px solid #1a1a2e">
                    ${vizHtml}
                </div>
            </div>
        </div>`;
    }).join("");

    card.innerHTML = `
        <div class="tc-header">
            <div class="tc-title">🛡️ Feature Risk Signal Report</div>
            <button class="tc-close" id="tc-close-btn">✕</button>
        </div>
        <div class="tc-summary">
            ${threatData.length} threat categories · ${totalAffected.toLocaleString()} unique affected in fingerprint corpus (${totalFp.toLocaleString()} nodes), ${totalAffectedObserved.toLocaleString()} in current observed set (${observedPeerCount.toLocaleString()} peers)
        </div>
        ${sectionsHtml}
    `;

    overlay.classList.add("open");

    // Close button
    document.getElementById("tc-close-btn").addEventListener("click", (e) => {
        e.stopPropagation();
        overlay.classList.remove("open");
    });

    // Close on backdrop click
    overlay.addEventListener("click", (e) => {
        if (e.target === overlay) overlay.classList.remove("open");
    });

    // Accordion toggles
    card.querySelectorAll(".tc-section-header").forEach(header => {
        header.addEventListener("click", (e) => {
            e.stopPropagation();
            const section = header.closest(".tc-section");
            section.classList.toggle("open");
        });
    });
}

// ═══════════════════════════════════════════════════════════════
//  NODE INFO POPUP CARD
// ═══════════════════════════════════════════════════════════════

function openNodeCard(pubkey) {
    selectedNodePubkey = pubkey;
    const peer = peers[pubkey] || {};
    const fp = fpByPubkey[pubkey];
    const isSuspect = (leaks.first_responders || []).some(fr => (fr.pubkey || "") === pubkey);
    const suspectData = (leaks.first_responders || []).find(fr => (fr.pubkey || "") === pubkey);
    const state = peerStates[pubkey] || {};

    // Find co-location signal groups this peer belongs to (/24 heuristic)
    const colocGroups = (leaks.colocation || []).filter(cl =>
        (cl.peers || []).some(p => (typeof p === "string" ? p : p.pubkey) === pubkey)
    );

    const card = document.getElementById("node-details-panel");
    const badge = document.getElementById("node-details-badge");

    // ── Build card HTML ──
    let html = `
    <div class="nc-header">
        <div class="nc-alias">${escHtml(peer.alias || "Unknown Node")}</div>
        <button class="nc-close" id="nc-close-btn">✕</button>
    </div>
    <div class="nc-pubkey">${pubkey}</div>

    <div class="nc-section">
        <div class="nc-section-title">Network Info</div>
        <div class="nc-row">
            <span class="nc-label">IP Address</span>
            <span class="nc-val ${peer.is_tor ? '' : 'nc-good'}">${peer.ip || "🧅 Tor-only"}</span>
        </div>
        ${peer.city || peer.country ? `<div class="nc-row">
            <span class="nc-label">Location</span>
            <span class="nc-val">${[peer.city, peer.country].filter(Boolean).join(", ")}</span>
        </div>` : ""}
        ${peer.isp ? `<div class="nc-row">
            <span class="nc-label">ISP</span>
            <span class="nc-val">${escHtml(peer.isp)}</span>
        </div>` : ""}
        ${peer.as_info ? `<div class="nc-row">
            <span class="nc-label">AS</span>
            <span class="nc-val">${escHtml(peer.as_info)}</span>
        </div>` : ""}
        <div class="nc-row">
            <span class="nc-label">Community</span>
            <span class="nc-val">${escHtml(peer.community || "unknown")}</span>
        </div>
    </div>

    <div class="nc-section">
        <div class="nc-section-title">Gossip Propagation</div>
        <div class="nc-row">
            <span class="nc-label">Avg Arrival Percentile</span>
            <span class="nc-val">${((peer.avg_arrival_pct || 0) * 100).toFixed(1)}%</span>
        </div>
        <div class="nc-row">
            <span class="nc-label">Median Arrival Percentile</span>
            <span class="nc-val">${((peer.median_arrival_pct || 0) * 100).toFixed(1)}%</span>
        </div>
        <div class="nc-row">
            <span class="nc-label">Messages Seen</span>
            <span class="nc-val">${(peer.messages_seen || 0).toLocaleString()}</span>
        </div>
        ${peer.top5_pct !== undefined ? `<div class="nc-row">
            <span class="nc-label">Top-5% Arrivals</span>
            <span class="nc-val">${(peer.top5_pct || 0).toFixed(1)}%</span>
        </div>` : ""}
        ${peer.first_pct !== undefined ? `<div class="nc-row">
            <span class="nc-label">First Arrivals</span>
            <span class="nc-val">${(peer.first_pct || 0).toFixed(1)}%</span>
        </div>` : ""}
        ${state.delay !== undefined && state.delay < Infinity ? `<div class="nc-row">
            <span class="nc-label">Current Message Delay</span>
            <span class="nc-val">+${state.delay.toFixed(0)} ms</span>
        </div>` : ""}
    </div>`;

    // ── Surveillance section ──
    if (isSuspect) {
        html += `
    <div class="nc-section">
        <div class="nc-section-title" style="color:#e63946">⚠ Fast Relay Heuristic</div>
        <div class="nc-row">
            <span class="nc-label">Reason</span>
            <span class="nc-val nc-warn">Consistently early relay timing; potential privileged connectivity (not direct surveillance proof)</span>
        </div>
    </div>`;
    }

    // ── Co-location signal section (/24 heuristic) ──
    if (colocGroups.length > 0) {
        html += `
    <div class="nc-section">
        <div class="nc-section-title" style="color:#e9c46a">📍 Co-Location Signals (/24)</div>`;
        for (const cl of colocGroups) {
            const others = (cl.peers || [])
                .map(p => typeof p === "string" ? p : p.pubkey)
                .filter(pk => pk !== pubkey);
            const othersHtml = others.map(pk => {
                const a = peers[pk]?.alias || pk.slice(0, 12) + "…";
                return `<span class="nc-feat-tag" style="cursor:pointer;background:#e9c46a15;color:#e9c46a;border-color:#e9c46a30" data-card-peer="${pk}">${escHtml(a)}</span>`;
            }).join("");
            html += `
        <div style="margin-bottom:6px">
            <div style="font-size:10px;color:#e9c46a;font-weight:bold">${cl.prefix || "?"} <span style="color:#888;font-weight:normal">(${cl.count || others.length + 1} nodes)</span></div>
            <div class="nc-features" style="margin-top:3px">${othersHtml}</div>
        </div>`;
        }
        html += `</div>`;
    }

    // ── Fingerprint section ──
    if (fp) {
        const known = fp.feature_names.filter(n => !n.startsWith("unknown_bit_"));
        const unknown = fp.feature_names.filter(n => n.startsWith("unknown_bit_"));
        const totalNodes = fingerprints.total_nodes_parsed || 5736;
        const groupPct = ((fp.group_size / totalNodes) * 100).toFixed(1);

        html += `
    <div class="nc-section">
        <div class="nc-section-title" style="color:#a855f7">🔬 Implementation Fingerprint</div>
        <div class="nc-row">
            <span class="nc-label">Feature Count</span>
            <span class="nc-val">${fp.feature_names.length} features</span>
        </div>
        <div class="nc-row">
            <span class="nc-label">Fingerprint Group Size</span>
            <span class="nc-val">${fp.group_size.toLocaleString()} nodes (${groupPct}%)</span>
        </div>
        <div class="nc-fingerprint-bar">
            <div class="nc-fp-track"><div class="nc-fp-fill" style="width:${groupPct}%"></div></div>
            <div class="nc-fp-label">${fp.group_size === 1 ? "Unique fingerprint — only node with this exact set" : fp.group_size <= 10 ? "Rare fingerprint" : fp.group_size <= 100 ? "Uncommon fingerprint" : fp.group_size <= 500 ? "Common fingerprint" : "Very common fingerprint (likely shared implementation profile)"}</div>
        </div>
        <div style="margin-top:8px">
            <div style="font-size:9px;color:#666;margin-bottom:4px">Known Features (${known.length})</div>
            <div class="nc-features">${known.map(f => `<span class="nc-feat-tag known">${f.replace(/_/g, " ")}</span>`).join("")}</div>
        </div>
        ${unknown.length > 0 ? `
        <div style="margin-top:6px">
            <div style="font-size:9px;color:#666;margin-bottom:4px">Unknown/Experimental Bits (${unknown.length})</div>
            <div class="nc-features">${unknown.map(f => `<span class="nc-feat-tag unknown">${f}</span>`).join("")}</div>
        </div>` : ""}
    </div>`;
    } else {
        html += `
    <div class="nc-section">
        <div class="nc-section-title" style="color:#a855f7">🔬 Implementation Fingerprint</div>
        <div style="font-size:10px;color:#555;font-style:italic">No node_announcement fingerprint data available for this peer</div>
    </div>`;
    }

    card.style.display = "block";
    card.style.padding = "0";
    card.style.alignItems = "initial";
    card.style.justifyContent = "initial";
    card.style.color = "inherit";
    card.style.fontSize = "inherit";
    card.style.textAlign = "initial";
    card.innerHTML = html;
    if (badge) badge.textContent = peer.alias || pubkey.slice(0, 10) + "…";

    // Wire close button
    document.getElementById("nc-close-btn").addEventListener("click", closeNodeCard);

    // Click on co-location signal peer chip → open that peer's card
    card.querySelectorAll("[data-card-peer]").forEach(el => {
        el.addEventListener("click", (e) => {
            e.stopPropagation();
            openNodeCard(el.dataset.cardPeer);
        });
    });

    // Highlight this peer across all panels
    highlightPeer(pubkey);
}

function closeNodeCard() {
    selectedNodePubkey = null;
    renderNodeDetailsPlaceholder();
}

function renderNodeDetailsPlaceholder() {
    const card = document.getElementById("node-details-panel");
    const badge = document.getElementById("node-details-badge");
    if (!card) return;
    if (selectedNodePubkey && peers[selectedNodePubkey]) return;

    if (badge) badge.textContent = "Select a node";
    card.style.display = "flex";
    card.style.alignItems = "center";
    card.style.justifyContent = "center";
    card.style.padding = "24px";
    card.style.color = "#666";
    card.style.fontSize = "12px";
    card.style.textAlign = "center";
    card.innerHTML = "Select a node";
}

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeNodeCard();
});

// ═══════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════

function getCommunityColor(communityId) {
    if (!communityId) return "#555";
    const c = communities[communityId];
    if (c?.color) return c.color;
    const palette = ["#ff6b35","#2a9d8f","#e9c46a","#457b9d","#e63946","#a855f7","#06d6a0","#ef476f","#118ab2","#ffd166"];
    let h = 0;
    for (let i = 0; i < communityId.length; i++) h = ((h << 5) - h + communityId.charCodeAt(i)) | 0;
    return palette[Math.abs(h) % palette.length];
}

function lerpColor(a, b, t) {
    const ah = parseInt(a.slice(1), 16), bh = parseInt(b.slice(1), 16);
    const ar = (ah >> 16) & 0xff, ag = (ah >> 8) & 0xff, ab = ah & 0xff;
    const br = (bh >> 16) & 0xff, bg = (bh >> 8) & 0xff, bb = bh & 0xff;
    const rr = Math.round(ar + (br - ar) * t);
    const rg = Math.round(ag + (bg - ag) * t);
    const rb = Math.round(ab + (bb - ab) * t);
    return `#${((rr << 16) | (rg << 8) | rb).toString(16).padStart(6, "0")}`;
}

function escHtml(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
}
