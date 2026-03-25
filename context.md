# Context System Analysis — `app.js`

> Reference document for the `context-drivers` refactor.  
> Describes how the current system tracks and propagates "what the user is looking at" across the four quadrant panels (Q1 message list, Q2 map, Q3 channels, Q4 node details).

---

## 0. Context Driver Model (new — `context-drivers` branch)

The sub-contexts identified in §2 can all be reduced to a single simpler concept: **the active driver**.

A **driver** is the specific entity the user is currently focused on. Every sub-context is just a combination of a driver type and a driver ID:

| Driver type | Driver ID example | Enters when |
|---|---|---|
| `general` | `GENERAL` | No entity selected; default / reset state |
| `message` | `NA · 03ab12cd…` or `CU · 812345x1x1` | Any message selected in Q1 |
| `channel` | `812345x1x1` | `channel_announcement` selected **or** channel card clicked in Q3 |
| `node` | `ACINQ` or `02abc…` | `openNodeCard()` called from any entry point |

**Priority**: `node > channel > message > general`

The driver is computed by `getContextDriver()` and displayed in the status bar via `updateContextBar()`. It is a read-only derivative of the existing state variables — it doesn't replace them, it surfaces them.

### `getContextDriver()` logic
```javascript
getContextDriver()
  if selectedNodePubkey && peers[selectedNodePubkey]
    → { type: "node",    id: alias || pubkey.slice(0,12)+"…" }
  else if selectedChannelScid
    → { type: "channel", id: scid }
  else if currentMsg
    → { type: "message", id: "NA|CA|CU · scid_or_hash_prefix" }
  else
    → { type: "general", id: "GENERAL" }
```

### Status bar display
The status bar (top header) shows a persistent **CURRENT CONTEXT** indicator:

```
LN GOSSIP VISUALIZER //…        [current context]  node · ACINQ        ↳ Elements In Scope …
                                  ─────────────────────────────────────
                                  label  type-pill   driver ID
```

Element IDs:
- `#ctx-driver-wrap` — the centered container (absolutely positioned in header)
- `#ctx-driver-type` — type pill (e.g. `node`, `channel`, `message`, `general`)
- `#ctx-driver-id` — the specific driver ID string

### `updateContextBar()` call sites
Called at the end of every state-mutating function:

| Call site | When |
|---|---|
| `selectMessage(msg)` | Any Q1 message click |
| `clearHighlight()` | Map click / canvas miss / Esc — also now clears `currentMsg` |
| `openNodeCard(pk)` | Any node card / map marker / suspect card click |
| `closeNodeCard()` | Back button or Esc |
| Back button in Layer 2 | `nd-back-btn` click handler |
| Channel card click (Q3) | `renderChannelsPanel()` wire-up |
| Filter tab change | `renderMessageList()` — also now clears `currentMsg` |
| Boot reset | After `selectMessage(initialMessage)` corrects channel bleed |

---

## 1. State Variables That Constitute "Context"

These are the five mutable variables whose combined values define the current context at any moment:

| Variable | Type | Default | Meaning |
|---|---|---|---|
| `highlightedPeers` | `Set<string>` | empty | Pubkeys currently lit on map + Q4 cards |
| `currentMsg` | object \| null | `null` | The message object last selected in Q1 |
| `selectedChannelScid` | string \| null | `null` | SCID of the channel currently driving Q3 filter |
| `selectedNodePubkey` | string \| null | `null` | Pubkey driving Q4 Layer 2 (node detail view) |
| `nodeListContext` | `{pubkeys, label, source}` | `{pubkeys:[], label:"", source:"global"}` | Layer 1 node list scope for Q4 |

`nodeListContext.source` is a discriminated union:

| Source value | Meaning |
|---|---|
| `"global"` | Top 30 fastest relayers, no message/channel filter |
| `"message"` | List derived from a selected message (origin node for `node_announcement`) |
| `"channel"` | Top 30 nodes by relay activity on a specific SCID |
| `"none"` | Channel message type with no applicable node list (shows placeholder) |

---

## 2. Named Contexts

The following table describes every distinct observable state, how to enter it, and what each panel shows when in it.

| Context | How to enter | `selectedNodePubkey` | `selectedChannelScid` | `nodeListContext.source` | **Q1 (messages)** | **Q2 (map)** | **Q3 (channels)** | **Q4 Layer 1 (node list)** |
|---|---|---|---|---|---|---|---|---|
| **global** | Map click · canvas miss · `Esc` · `clearHighlight()` | `null` | `null` | `"global"` | Full message list, active filter tab | Zoom-out to default if was zoomed | Top 30 channels globally | Top 30 fastest relayers network-wide |
| **node_announcement** | Click `node_announcement` in Q1 | `null` | `null` | `"message"` | Same list, selected item highlighted | `flyTo` origin node at zoom 5 | Top 30 channels globally | Single origin node, highlighted on map |
| **channel_announcement** | Click `channel_announcement` in Q1 | `null` | SCID string | `"channel"` | Same list, selected item highlighted | No zoom change (no highlights) | Filtered to that SCID only | Top 30 nodes by relay count for that SCID |
| **channel_update** | Click `channel_update` in Q1 | `null` | SCID string | `"channel"` | Same list, selected item highlighted | No zoom change | Filtered to that SCID only | Top 30 nodes by relay count for that SCID |
| **node_selected** | `openNodeCard(pk)` from any source | pubkey | unchanged | unchanged | **Filtered to messages where `orig_node === pubkey`** | `flyTo` node at zoom 5 | Node-scoped channels (only channels that node participates in) | Layer 2 node detail card |
| **coloc_group** | Click co-location card in Q1 threat panel | `null` | `null` | `"global"` | Unchanged | `flyToBounds` if bounds tighter than default zoom | Top 30 channels globally | Top 30 fastest relayers (list not re-rendered; just highlights update on existing list) |
| **channel_selected** | Click a channel card in Q3 | `null` | unchanged | `"channel"` | Unchanged | No zoom change | Unchanged (channel card active state) | Top 30 nodes by relay count for that SCID |
| **filter_tab_change** | Click All / Channels / Nodes / Updates filter | `null` | `null` (cleared) | unchanged | New filtered list, no active selection | Unchanged | Top 30 channels globally (SCID filter cleared) | Unchanged |

### Additional entry paths

- **Suspect card click** → `openNodeCard(pk)` → enters `node_selected`
- **Map marker click (different node)** → `openNodeCard(pk)` → `node_selected`
- **Map marker click (same node)** → `clearHighlight()` + `closeNodeCard()` → `global`
- **Co-location peer chip click** → `openNodeCard(pk)` → `node_selected`
- **Node detail back button** → `renderNodeList(nodeListContext)` → returns to whatever Q4 Layer 1 context was active before
- **Fast Relay threat card (Q1 bar slot)** → `openFastRelayCard()` overlay; no context state change
- **Peer Profiling / Coloc / Feature Risk cards** → modal overlays; no context state change

---

## 3. Event → State Mutation Map

Each user action and its exact mutations:

```
selectMessage(msg)
  currentMsg = msg
  selectedChannelScid = (type === "channel_announcement" || type === "channel_update") && scid ? scid : null
  → renderMessageList(replayFilterType)        [re-renders Q1 active state only]
  → renderMessageIntel(msg)                    [Q1 detail pane]
  → setMessageDetailMode(messageDetailMode)
  → deriveNodeListFromMessage(msg) → renderNodeList(ctx)
      nodeListContext = ctx
      selectedNodePubkey = null
      highlightedPeers updated (only if source === "message")
      → updateMapHighlights()
  → renderChannelsPanel()                      [Q3, reads getActiveChannelList()]

clearHighlight()
  highlightedPeers.clear()
  selectedNodePubkey = null
  selectedChannelScid = null
  → updateAllHighlights()
      → updateMapHighlights()
      → wireSuspectCardInteractions()
      → wireColocationCardInteractions()
      → renderNodeDetailsPlaceholder()         [does NOT re-render if layer 2 is open]
      → renderChannelsPanel()
  → renderNodeList({ source: "global", pubkeys: getTopPeersByScore(30) })

openNodeCard(pk)
  selectedNodePubkey = pk
  → (renders Layer 2 HTML directly into panel)
  → highlightPeer(pk) → highlightedPeers = {pk} → updateMapHighlights()
  → renderChannelsPanel()                      [Q3 switches to node-scoped mode]

closeNodeCard()   [via back button or Esc]
  selectedNodePubkey = null
  → renderNodeList(nodeListContext)            [restores Layer 1 from preserved context]
  → renderChannelsPanel()

renderMessageList(filterType)
  if filterType !== replayFilterType:
    selectedChannelScid = null
    → renderChannelsPanel()
  replayFilterType = filterType
  [re-renders Q1 list only]

channel card click (in Q3)
  → deriveNodeListFromChannel(scid) → renderNodeList(ctx)
      nodeListContext = {source: "channel", pubkeys: top30ByRelayCount}
      selectedNodePubkey = null

highlightPeers(pubkeys)   [from coloc card click]
  highlightedPeers = new Set(pubkeys)
  → updateAllHighlights()
      → updateMapHighlights()  [flyToBounds if tight]
      → renderNodeDetailsPlaceholder()  [updates .highlighted class only if panel already rendered]
      → renderChannelsPanel()
```

---

## 4. Call Chain Sequentiality

The rendering order matters because state is read at render time, not passed as arguments. Key call chains:

### Chain A — Message selection
```
click Q1 item
  └─ selectMessage(msg)
       ├─ currentMsg = msg
       ├─ selectedChannelScid = ...
       ├─ renderMessageList()          ← reads selectedChannelScid? No. Just re-renders active state.
       ├─ renderMessageIntel()
       ├─ setMessageDetailMode()
       ├─ deriveNodeListFromMessage()
       │    └─ renderNodeList(ctx)
       │         ├─ nodeListContext = ctx
       │         ├─ selectedNodePubkey = null
       │         ├─ highlightPeers() or highlightedPeers.clear()
       │         └─ updateMapHighlights()
       └─ renderChannelsPanel()        ← reads selectedNodePubkey, selectedChannelScid
```

### Chain B — Node card open
```
click node card (Q4 Layer 1) or suspect card or map marker
  └─ openNodeCard(pk)
       ├─ selectedNodePubkey = pk
       ├─ [render Layer 2 HTML]
       ├─ highlightPeer(pk)
       │    └─ highlightedPeers = {pk}
       │         └─ updateMapHighlights()   ← flyTo zoom 5
       └─ renderChannelsPanel()             ← sees selectedNodePubkey → node mode
```

### Chain C — Clear / reset
```
map click (empty) | canvas miss | Esc
  └─ clearHighlight()
       ├─ highlightedPeers.clear()
       ├─ selectedNodePubkey = null
       ├─ selectedChannelScid = null
       ├─ updateAllHighlights()
       │    ├─ updateMapHighlights()        ← zoom out if mapWasZoomedIn
       │    ├─ wireSuspectCardInteractions()
       │    ├─ wireColocationCardInteractions()
       │    ├─ renderNodeDetailsPlaceholder()
       │    └─ renderChannelsPanel()        ← called here (global mode)
       └─ renderNodeList({ source: "global" })  ← called AFTER renderChannelsPanel
```
> ⚠ **Ordering issue**: `renderChannelsPanel()` is called inside `updateAllHighlights()`, and then `renderNodeList()` calls `updateMapHighlights()` again at the end. Q3 re-renders once; Q2 re-renders twice.

### Chain D — Boot sequence
```
DOMContentLoaded
  └─ loadData()
       ├─ [fetch all JSON in parallel]
       ├─ renderChannelsPanel()             ← early render with empty data
       ├─ computeAndRenderThreats()
       ├─ primeQ4 with getTopPeersByScore(30)
       └─ setupUI()
            ├─ renderMessageList("all")
            │    └─ [renders message items, wires selectMessage]
            ├─ setMessageDetailMode()
            ├─ renderAllMapMarkers()
            └─ initMap()
                 └─ setTimeout(200ms)
                      ├─ leafletMap.invalidateSize()
                      └─ leafletMap.setView() → captures DEFAULT_MAP_VIEW

  After loadData resolves:
    selectMessage(firstMessage)
      └─ [sets selectedChannelScid if first msg is channel_announcement]
    selectedChannelScid = null    ← explicit reset
    renderChannelsPanel()         ← corrects the Q3 state after init selectMessage
```

---

## 5. `getActiveChannelList()` — The Q3 Priority Gate

This function is the single point that decides what Q3 shows. It reads global state directly:

```javascript
getActiveChannelList()
  if selectedNodePubkey → "node" mode (channels where that node participates)
  else if selectedChannelScid → "message_channel" mode (single SCID)
  else → "global" mode (top 30 by total relay messages)
```

Priority: **node > channel > global**

This means: opening a node card while a `channel_announcement` is selected will override the SCID filter. The SCID is preserved in `selectedChannelScid` but invisible until `selectedNodePubkey` is cleared.

---

## 6. Map Zoom State (`mapWasZoomedIn`)

A boolean flag separate from the context variables above. It gates zoom-out animation:

| Condition | What triggers it | Result |
|---|---|---|
| `highlightedPeers.size === 0 && mapWasZoomedIn` | `updateMapHighlights()` | Fly back to `DEFAULT_MAP_VIEW` with snap |
| `highlightedPeers.size === 1` | `updateMapHighlights()` | `flyTo` that node at zoom 5; sets `mapWasZoomedIn = true` |
| `highlightedPeers.size > 1` | `updateMapHighlights()` | `flyToBounds` only if `getBoundsZoom > DEFAULT_MAP_VIEW.zoom` |
| `highlightedPeers.size > 1` and bounds are wide | `updateMapHighlights()` | No fly (avoids zooming out mid-context) |

`mapWasZoomedIn` is set to `true` only when a single-peer fly actually occurs. It is reset to `false` by the zoom-out fly call itself. This prevents zoom-out triggering when the user never explicitly zoomed in.

---

## 7. Q4 Layer System

Q4 has two rendering layers inside a single `#node-details-panel` element:

```
Layer 1 — Node List (nd-list-layer)
  Context bar  →  contextLabel + contextSubLabel
  Node cards   →  click → openNodeCard(pk)
                  hover → showPeerTooltip

Layer 2 — Node Detail (nd-detail-layer)
  Back button  →  renderNodeList(nodeListContext)  [or global fallback]
  Scroll area  →  buildNodeDetailHtml(pubkey)
    ├─ Network Info (IP, location, ISP, AS, community)
    ├─ Gossip Propagation (arrival pct, msgs seen, top-5%, first%)
    ├─ ⚠ Fast Relay Heuristic (if in leaks.first_responders)
    ├─ 📍 Co-Location Signals (if in leaks.colocation)
    └─ 🔬 Implementation Fingerprint (if fpByPubkey[pk] exists)
```

Layer 2 replaces Layer 1 in the DOM — there is no z-index stacking. `renderNodeDetailsPlaceholder()` guards against overwriting Layer 2 by checking `selectedNodePubkey`.

---

## 8. Identified Structural Issues

### 8.1 Double `renderChannelsPanel()` in clear path
`clearHighlight()` → `updateAllHighlights()` → `renderChannelsPanel()` AND then `renderNodeList()` → `updateMapHighlights()` (not a second renderChannelsPanel, but map renders twice). The Q3 panel re-renders once unnecessarily since the second `renderNodeList` call completes the state change that should have been done in one pass.

### 8.2 State is read at render time, not passed as arguments
Every render function reads global variables (`selectedNodePubkey`, `selectedChannelScid`, `highlightedPeers`, etc.) directly. This means:
- Rendering order determines correctness (mutation must precede render)
- There is no way to render a "hypothetical" state without changing global state first
- Race conditions are possible if any render is async or deferred

### 8.3 `currentMsg` is never cleared *(partially fixed)*
`currentMsg` was set in `selectMessage()` and never set to `null` anywhere. It is now cleared in `clearHighlight()`, in `renderMessageList()` on filter tab change, and in the boot reset after `selectMessage(initialMessage)`. This ensures `getContextDriver()` correctly returns `"general"` after a reset rather than falling through to the last-selected message.

### 8.4 Boot-time channel filter bleed
The first message in `messageIntel` is often a `channel_announcement`. The boot sequence calls `selectMessage(firstMessage)` which sets `selectedChannelScid`, then immediately resets it with `selectedChannelScid = null; renderChannelsPanel()`. This is a workaround — the underlying issue is that `selectMessage` has no "silent" or "initial load" mode.

### 8.5 `openNodeCard` has two implementations in the file
Lines ~2180–2260 contain a second partial implementation of `openNodeCard` that is dead code (never reached, below the `keydown` Esc listener). It starts with `selectedNodePubkey = pubkey` and rebuilds `html` with a slightly different structure (has `nc-close` button, no back button). This is a leftover from an earlier version and should be removed.

### 8.6 `renderChannelsPanel()` called from 6 different sites
`renderChannelsPanel` is called from: `loadData`, `selectMessage`, `clearHighlight` (via `updateAllHighlights`), `openNodeCard`, `closeNodeCard`, and explicitly after the boot-time `selectMessage` reset. Each call reads the same global gate function `getActiveChannelList()`. There is no single ownership — any function can trigger a Q3 re-render by calling it directly.

---

## 9. Data Dependencies per Context

Which JSON files are required for each context to be fully populated:

| Context | Required data | Optional enrichment |
|---|---|---|
| global | `peers.json` (node list + scores) | `fingerprints.json`, `communities.json` |
| node_announcement | `peers.json`, `message_intel.json` | — |
| channel_announcement | `peers.json`, `node_channels.json`, `channels.json` | — |
| channel_update | `peers.json`, `node_channels.json`, `channels.json` | — |
| node_selected (Layer 2) | `peers.json`, `leaks.json`, `fingerprints.json` | `communities.json` |
| channel_selected (Q3) | `channels.json`, `node_channels.json`, `peers.json` | — |
| coloc_group | `leaks.json`, `peers.json` | `communities.json` |
| threat card overlay | `fingerprints.json`, `peers.json`, `leaks.json` | — |

---

## 10. Foundation for a Context Manager Refactor

A unified context manager would own the following responsibilities that are currently scattered:

1. **Single source of truth**: Replace the 5 individual state variables with one `activeContext` object:
   ```javascript
   activeContext = {
     type: "global" | "node_announcement" | "channel_announcement" | "channel_update" | "node_selected" | "channel_selected" | "coloc_group",
     message: null | msgObject,
     scid: null | string,
     nodePubkey: null | string,
     nodeListPubkeys: [],
     nodeListLabel: "",
     nodeListSource: "global" | "message" | "channel" | "none",
     highlightedPubkeys: Set,
   }
   ```

2. **Transition function**: `setContext(type, params)` mutates `activeContext` atomically, then calls a single `renderAll()` pass. No render site reads stale partial state.

3. **Render orchestration**: One `renderAll()` function calls Q1–Q4 renders in dependency order, passing derived values as arguments rather than having each reader pull from globals.

4. **Guard for Layer 2**: `renderAll()` checks `activeContext.nodePubkey` before deciding whether to render Q4 Layer 1 or Layer 2. No need for `renderNodeDetailsPlaceholder()` as a guard.

5. **Boot mode flag**: `setContext("init", params)` skips map fly animations and suppresses channel filter bleed during the initial load pass.
