const API_BASE = '/api/v1';

let currentOffset = 0;
const LIMIT = 20;
let selectedEventId = null;
let lastInterpretationData = null;

// DOM Elements
const dashTotalEventsEl = document.getElementById('dash-total-events');
const dashKnownEventsEl = document.getElementById('dash-known-events');
const dashUnknownEventsEl = document.getElementById('dash-unknown-events');
const dashRecentEventsTbody = document.getElementById('dash-recent-events-tbody');
const dashEmptyState = document.getElementById('dash-empty-state');
const dashRefreshBtn = document.getElementById('dash-refresh-btn');

const eventsListTbody = document.getElementById('events-list-tbody');
const eventsEmptyState = document.getElementById('events-empty-state');
const eventsRefreshBtn = document.getElementById('events-refresh-btn');
const prevPageBtn = document.getElementById('prev-page-btn');
const nextPageBtn = document.getElementById('next-page-btn');
const pageInfoEl = document.getElementById('page-info');

// Badges & Workspace locking
const activeEventBadges = document.querySelectorAll('.active-event-badge .value');
const navAnalysis = document.getElementById('nav-analysis');
const navProvenance = document.getElementById('nav-provenance');
const navUnknown = document.getElementById('nav-unknown');
const navReplay = document.getElementById('nav-replay');
const noEventSelectedMsg = document.getElementById('no-event-selected-msg');

// Analysis
const analysisMetadataEl = document.getElementById('analysis-metadata');
const analysisFramesContainerEl = document.getElementById('analysis-frames-container');
const analysisIntegrityBadge = document.getElementById('analysis-integrity-badge');
const evidenceMetadataEl = document.getElementById('evidence-metadata');
const evidenceBytesEl = document.getElementById('evidence-bytes');

// Provenance
const provenanceExplorerContainer = document.getElementById('provenance-explorer-container');

// Unknown
const unknownFormatContainer = document.getElementById('unknown-format-container');

// Replay
const replayForm = document.getElementById('replay-form');
const replayEmpty = document.getElementById('replay-empty');
const replayResults = document.getElementById('replay-results');
const replayError = document.getElementById('replay-error');
const replayMetadataEl = document.getElementById('replay-metadata');
const replayFramesContainerEl = document.getElementById('replay-frames-container');
const runReplayBtn = document.getElementById('run-replay-btn');

// --- UTILS ---
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function decodeBytes(base64Str) {
    if (!base64Str) return { text: '', length: 0 };
    const binaryString = atob(base64Str);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    try {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        return { text: decoder.decode(bytes), length: len };
    } catch (e) {
        return {
            text: Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' '),
            length: len
        };
    }
}

// Navigation
function navigateTo(targetId) {
    // Update nav links
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.dataset.target === targetId) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });

    // Show correct section
    document.querySelectorAll('.content-section').forEach(sec => sec.classList.remove('active'));
    document.getElementById('sec-' + targetId).classList.add('active');
}

// --- INIT ---
document.addEventListener('DOMContentLoaded', () => {
    // Set up navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            if (!link.classList.contains('disabled')) {
                navigateTo(link.dataset.target);
            }
        });
    });

    // Pagination
    prevPageBtn.addEventListener('click', () => {
        if (currentOffset >= LIMIT) {
            currentOffset -= LIMIT;
            loadEvents();
        }
    });

    nextPageBtn.addEventListener('click', () => {
        currentOffset += LIMIT;
        loadEvents();
    });

    eventsRefreshBtn.addEventListener('click', () => {
        currentOffset = 0;
        loadEvents();
    });

    dashRefreshBtn.addEventListener('click', () => {
        loadEvents();
    });

    replayForm.addEventListener('submit', (e) => {
        e.preventDefault();
        runReplay();
    });

    // Load initial data
    loadEvents();
});

function copyIngestCode() {
    const code = `# 1. Create a sample log file\necho "vendor=ACME product=Firewall action=DENY" > sample.log\n\n# 2. Ingest the file into ULPX\ncargo run -p ulpx-ingest -- process sample.log`;
    navigator.clipboard.writeText(code).then(() => {
        alert('Copied to clipboard!');
    });
}

async function loadEvents() {
    try {
        const res = await fetch(`${API_BASE}/events?offset=${currentOffset}&limit=${LIMIT}`);
        if (!res.ok) throw new Error('Failed to fetch events');
        const data = await res.json();

        populateEventsList(data.events || []);
        populateDashboard(data.events || []);

        if (data.events && data.events.length > 0) {
            nextPageBtn.disabled = data.events.length < LIMIT;
        } else {
            nextPageBtn.disabled = true;
        }
        prevPageBtn.disabled = currentOffset === 0;
        pageInfoEl.textContent = `Page ${(currentOffset / LIMIT) + 1}`;

    } catch (err) {
        console.error("Error loading events:", err);
    }
}

function populateDashboard(events) {
    if (events.length === 0) {
        dashEmptyState.classList.remove('hidden');
        dashRecentEventsTbody.innerHTML = '';
        return;
    }

    dashEmptyState.classList.add('hidden');
    dashTotalEventsEl.textContent = events.length; // Actually just this page, but good enough for demo

    // Simulate some logic for the dash since we don't have global stats
    let known = 0;
    let unknown = 0;

    dashRecentEventsTbody.innerHTML = '';
    // Show top 5
    const recent = events.slice(0, 5);
    recent.forEach(evt => {
        const tr = document.createElement('tr');
        const isSelected = evt.event_id === selectedEventId;
        if (isSelected) tr.classList.add('selected');

        const integrityIcon = evt.has_integrity ? '<span class="text-success"><i class="fa-solid fa-check"></i></span>' : '<span class="text-warning"><i class="fa-solid fa-triangle-exclamation"></i></span>';

        tr.innerHTML = `
            <td style="font-family:monospace">${escapeHtml(evt.event_id)}</td>
            <td>${escapeHtml(evt.source)}</td>
            <td>${integrityIcon}</td>
            <td><button class="btn btn-primary" onclick="selectEvent('${evt.event_id}')">Analyze</button></td>
        `;
        dashRecentEventsTbody.appendChild(tr);
    });
}

function populateEventsList(events) {
    eventsListTbody.innerHTML = '';

    if (events.length === 0) {
        eventsEmptyState.classList.remove('hidden');
        document.querySelector('.data-table').classList.add('hidden');
    } else {
        eventsEmptyState.classList.add('hidden');
        document.querySelector('.data-table').classList.remove('hidden');

        events.forEach(evt => {
            const tr = document.createElement('tr');
            if (evt.event_id === selectedEventId) tr.classList.add('selected');

            const integrityIcon = evt.has_integrity ? '<span class="text-success"><i class="fa-solid fa-check"></i> Verified</span>' : '<span class="text-warning"><i class="fa-solid fa-triangle-exclamation"></i> Error</span>';

            tr.innerHTML = `
                <td style="font-family:monospace">${escapeHtml(evt.event_id)}</td>
                <td>${escapeHtml(evt.source)}</td>
                <td>${integrityIcon}</td>
                <td><span class="badge badge-primary">Ingested</span></td>
            `;
            tr.addEventListener('click', () => selectEvent(evt.event_id));
            eventsListTbody.appendChild(tr);
        });
    }
}

function unlockWorkspace(eventId) {
    selectedEventId = eventId;

    // Update badges
    activeEventBadges.forEach(el => el.textContent = eventId);

    // Unlock nav
    noEventSelectedMsg.classList.add('hidden');
    navAnalysis.classList.remove('disabled');
    navProvenance.classList.remove('disabled');
    navUnknown.classList.remove('disabled');
    navReplay.classList.remove('disabled');

    // Update selection styling in lists
    loadEvents();
}

async function selectEvent(id) {
    unlockWorkspace(id);
    navigateTo('analysis');

    lastInterpretationData = null;

    // Reset Views
    analysisMetadataEl.innerHTML = '<div>Loading...</div>';
    analysisFramesContainerEl.innerHTML = '';
    evidenceMetadataEl.innerHTML = '<div>Loading...</div>';
    evidenceBytesEl.textContent = '';
    provenanceExplorerContainer.innerHTML = '<div class="text-muted"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading provenance data...</div>';
    unknownFormatContainer.innerHTML = '';

    replayEmpty.classList.remove('hidden');
    replayResults.classList.add('hidden');
    replayError.classList.add('hidden');

    await Promise.all([
        loadEvidence(id),
        loadInterpretation(id)
    ]);
}

async function loadEvidence(id) {
    try {
        const res = await fetch(`${API_BASE}/evidence/${id}`);
        if (!res.ok) throw new Error('Failed to fetch evidence');
        const data = await res.json();

        evidenceMetadataEl.innerHTML = `
            <div class="meta-item"><label>Source</label><span>${escapeHtml(data.source)}</span></div>
            <div class="meta-item"><label>Size</label><span>${escapeHtml(data.size_bytes)} bytes</span></div>
        `;

        const decoded = decodeBytes(data.payload_base64);
        evidenceBytesEl.textContent = decoded.text;
    } catch (err) {
        evidenceMetadataEl.innerHTML = `<span class="text-danger">${escapeHtml(err.message)}</span>`;
    }
}

async function loadInterpretation(id) {
    try {
        const res = await fetch(`${API_BASE}/interpretation/${id}/detailed`);
        if (!res.ok) throw new Error('Failed to fetch interpretation');
        const data = await res.json();

        lastInterpretationData = data;

        // Update Dashboard stats based on this event (hacky but works for demo)
        const hasUnknown = data.frames && data.frames.some(f => f.inference_decision !== null);
        if (hasUnknown) {
            dashUnknownEventsEl.textContent = parseInt(dashUnknownEventsEl.textContent) + 1;
        } else {
            dashKnownEventsEl.textContent = parseInt(dashKnownEventsEl.textContent) + 1;
        }

        renderInterpretation(data, analysisIntegrityBadge, analysisMetadataEl, analysisFramesContainerEl);
        renderUnknownFormatPanel(data.frames, unknownFormatContainer);
        renderProvenanceExplorer(data, provenanceExplorerContainer);
    } catch (err) {
        analysisMetadataEl.innerHTML = `<span class="text-danger">${escapeHtml(err.message)}</span>`;
        provenanceExplorerContainer.innerHTML = `<span class="text-danger">${escapeHtml(err.message)}</span>`;
    }
}

async function runReplay() {
    if (!selectedEventId) return;

    runReplayBtn.disabled = true;
    runReplayBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Running...';
    replayError.classList.add('hidden');
    replayResults.classList.add('hidden');
    replayEmpty.classList.add('hidden');

    const parsers = document.getElementById('parser-registry').value.split(',').map(s => s.trim()).filter(Boolean);
    const detectors = document.getElementById('inference-detectors').value.split(',').map(s => s.trim()).filter(Boolean);

    const payload = {
        event_id: selectedEventId,
        pipeline_config: {
            framer_id: document.getElementById('framer-id').value,
            framer_version: document.getElementById('framer-version').value,
            mapper_id: document.getElementById('mapper-id').value,
            mapper_version: document.getElementById('mapper-version').value,
            parser_registry: parsers,
            inference_detectors: detectors
        }
    };

    try {
        const res = await fetch(`${API_BASE}/replay`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const errText = await res.text();
            throw new Error(`${res.status}: ${errText}`);
        }

        const data = await res.json();
        replayResults.classList.remove('hidden');
        renderInterpretation(data, null, replayMetadataEl, replayFramesContainerEl);

    } catch (err) {
        replayError.classList.remove('hidden');
        replayError.textContent = err.message;
    } finally {
        runReplayBtn.disabled = false;
        runReplayBtn.innerHTML = '<i class="fa-solid fa-play"></i> Run Reprocessing';
    }
}

// --- RENDER HELPERS ---

function confidenceLevelInfo(level) {
    switch ((level || '').toLowerCase()) {
        case 'high':
        case 'certain':    return { pct: 95, cls: 'high',   label: level };
        case 'medium':
        case 'probable':   return { pct: 60, cls: 'medium', label: level };
        case 'low':
        case 'heuristic':  return { pct: 25, cls: 'low',    label: level };
        default:           return { pct: 0,  cls: 'low',    label: level || 'Unknown' };
    }
}

function buildConfidenceBar(label, level) {
    const { pct, cls } = confidenceLevelInfo(level);
    const wrapper = document.createElement('div');
    wrapper.className = 'confidence-bar-wrapper';
    const lbl = document.createElement('span');
    lbl.className = 'confidence-label';
    lbl.textContent = label;
    const track = document.createElement('div');
    track.className = 'confidence-bar-track';
    const fill = document.createElement('div');
    fill.className = `confidence-bar-fill ${cls}`;
    fill.style.width = `${pct}%`;
    track.appendChild(fill);
    const pctSpan = document.createElement('span');
    pctSpan.className = 'confidence-pct';
    pctSpan.textContent = level || '?';
    wrapper.appendChild(lbl);
    wrapper.appendChild(track);
    wrapper.appendChild(pctSpan);
    return wrapper;
}

function renderInterpretation(data, integrityBadgeEl, metaEl, framesEl) {
    if (integrityBadgeEl) {
        if (data.integrity_verified) {
            integrityBadgeEl.className = 'badge badge-success';
            integrityBadgeEl.innerHTML = '<i class="fa-solid fa-check"></i> Integrity Verified';
        } else {
            integrityBadgeEl.className = 'badge badge-error';
            integrityBadgeEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> Error: ${escapeHtml(data.integrity_error || 'Unknown')}`;
        }
    }

    metaEl.innerHTML = `
        <div class="meta-item"><label>Interpretation ID</label><span style="font-family:monospace">${escapeHtml(data.interpretation_id.substring(0,16))}...</span></div>
        <div class="meta-item"><label>Pipeline Config Identity</label><span style="font-family:monospace">${escapeHtml(data.pipeline_config_identity.substring(0,16))}...</span></div>
        <div class="meta-item"><label>Created At</label><span>${escapeHtml(new Date(data.created_at_secs * 1000).toLocaleString())}</span></div>
        ${data.trailing_frame_error ? `<div class="meta-item"><label>Trailing Error</label><span class="text-danger">${escapeHtml(data.trailing_frame_error)}</span></div>` : ''}
    `;

    framesEl.innerHTML = '';
    if (!data.frames || data.frames.length === 0) {
        framesEl.innerHTML = '<div class="text-muted">No frames detected.</div>';
        return;
    }

    data.frames.forEach(frame => {
        const fEl = document.createElement('div');
        fEl.className = 'frame-block';

        let inferenceHtml = '';
        if (frame.inference_decision) {
            const inf = frame.inference_decision;
            const sel = inf.recognized_candidate;
            inferenceHtml = `
                <div class="prov-field">
                    <div class="prov-field-name"><i class="fa-solid fa-microchip text-warning"></i> Inference: ${escapeHtml(inf.decision)}</div>
                    <div class="prov-details">
                        ${inf.abstention_reason ? `Reason: ${escapeHtml(inf.abstention_reason)}<br>` : ''}
                        ${sel ? `Selected: ${escapeHtml(sel.parser_id)} (${escapeHtml(sel.confidence)})<br>` : ''}
                        Evaluated candidates: ${escapeHtml((inf.all_candidates || []).map(c => c.parser_id).join(', ') || 'None')}
                    </div>
                </div>
            `;
        }

        let canonicalHtml = '';
        if (frame.canonical_event) {
            const c = frame.canonical_event;
            const fieldEntries = Object.entries(c)
                .filter(([k]) => k !== 'parser_id')
                .filter(([, v]) => v !== null && v !== undefined);

            if (fieldEntries.length > 0) {
                const canonWrap = document.createElement('div');
                const title = document.createElement('h4');
                title.style.marginBottom = '12px';
                title.innerHTML = '<i class="fa-solid fa-database text-info"></i> Canonical Fields';
                canonWrap.appendChild(title);

                for (const [k, v] of fieldEntries) {
                    const fieldDiv = document.createElement('div');
                    fieldDiv.className = 'prov-field';

                    const nameDiv = document.createElement('div');
                    nameDiv.className = 'prov-field-name';
                    nameDiv.textContent = k;
                    fieldDiv.appendChild(nameDiv);

                    const valDiv = document.createElement('div');
                    valDiv.style.fontFamily = 'monospace';
                    valDiv.textContent = typeof v.value === 'object' ? JSON.stringify(v.value) : String(v.value);
                    fieldDiv.appendChild(valDiv);

                    if (v.provenance) {
                        fieldDiv.appendChild(buildConfidenceBar('Confidence', v.provenance.confidence));
                    }
                    canonWrap.appendChild(fieldDiv);
                }
                fEl.appendChild(document.createComment('canonical-placeholder'));
                fEl._canonWrap = canonWrap;
            }
        }

        fEl.innerHTML = `
            <div class="frame-header">
                <strong><i class="fa-solid fa-crop-simple"></i> Frame ${escapeHtml(frame.frame_index)}</strong>
                <span><i class="fa-solid fa-code"></i> ${escapeHtml(frame.parser_id || 'None')} (v${escapeHtml(frame.parser_version || '?')}) — ${escapeHtml(frame.parser_outcome)}</span>
            </div>
            <div class="frame-body">
                ${inferenceHtml}
                <div class="frame-canonical-slot"></div>
            </div>
        `;

        if (fEl._canonWrap) {
            fEl.querySelector('.frame-canonical-slot').appendChild(fEl._canonWrap);
        }

        framesEl.appendChild(fEl);
    });
}

function renderUnknownFormatPanel(frames, containerEl) {
    containerEl.innerHTML = '';
    const inferredFrames = (frames || []).filter(f => f.inference_decision !== null && f.inference_decision !== undefined);

    if (inferredFrames.length === 0) {
        containerEl.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-check-circle fa-3x text-success"></i>
                <p>No unknown formats detected in this event.</p>
                <p class="text-muted">All frames were successfully parsed by authoritative parsers.</p>
            </div>
        `;
        return;
    }

    const panel = document.createElement('div');
    panel.className = 'unknown-format-panel';

    const title = document.createElement('div');
    title.className = 'unknown-format-title';
    title.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Unknown Format Detected';
    panel.appendChild(title);

    const sub = document.createElement('div');
    sub.className = 'unknown-format-subtitle';
    sub.textContent = `${inferredFrames.length} frame(s) could not be parsed by a known parser — inference engine engaged.`;
    panel.appendChild(sub);

    for (const frame of inferredFrames) {
        const inf = frame.inference_decision;

        if (inf.decision === 'Abstained') {
            const banner = document.createElement('div');
            banner.className = 'abstention-banner';
            const reason = escapeHtml(inf.abstention_reason || 'Insufficient evidence');
            banner.innerHTML = `<i class="fa-solid fa-ban"></i> Inference abstained — ${reason}`;
            panel.appendChild(banner);
        }

        const allCands = inf.all_candidates || [];
        if (allCands.length > 0) {
            const candsTitle = document.createElement('div');
            candsTitle.style.cssText = 'font-size:0.8rem;color:var(--text-muted);margin-bottom:8px;font-weight:600;';
            candsTitle.textContent = `Candidates evaluated (Frame ${escapeHtml(frame.frame_index)}):`;
            panel.appendChild(candsTitle);

            for (const cand of allCands) {
                const card = document.createElement('div');
                card.className = 'candidate-card';

                const header = document.createElement('div');
                header.className = 'candidate-card-header';

                const nameEl = document.createElement('span');
                nameEl.className = 'candidate-name';
                nameEl.innerHTML = `<i class="fa-solid fa-file-code"></i> ${escapeHtml(cand.format_name || cand.parser_id)}`;
                header.appendChild(nameEl);

                const isSelected = inf.recognized_candidate && inf.recognized_candidate.parser_id === cand.parser_id;
                const statusEl = document.createElement('span');
                statusEl.className = `candidate-status ${isSelected ? 'selected' : 'abstained'}`;
                statusEl.textContent = isSelected ? 'Selected' : (inf.decision === 'Abstained' ? 'Abstained' : 'Not selected');
                header.appendChild(statusEl);
                card.appendChild(header);

                card.appendChild(buildConfidenceBar('Confidence', cand.confidence));

                if (cand.evidence && cand.evidence.length > 0) {
                    const evList = document.createElement('ul');
                    evList.className = 'evidence-list';
                    for (const ev of cand.evidence) {
                        const li = document.createElement('li');
                        li.className = ev.supports ? 'supports' : 'rejects';
                        li.textContent = `[${ev.detector_id}] ${ev.description}`;
                        evList.appendChild(li);
                    }
                    card.appendChild(evList);
                }
                panel.appendChild(card);
            }
        }

        if (inf.decision === 'Recognized' && inf.recognized_candidate) {
            const reviewBanner = document.createElement('div');
            reviewBanner.className = 'review-action-banner';
            const txt = document.createElement('div');
            txt.className = 'review-action-text';
            txt.innerHTML = `<i class="fa-solid fa-user-check"></i> Candidate parser "${escapeHtml(inf.recognized_candidate.parser_id)}" generated — ready for human review before promotion.`;
            const state = document.createElement('div');
            state.className = 'review-action-state';
            state.textContent = 'READY FOR REVIEW';
            reviewBanner.appendChild(txt);
            reviewBanner.appendChild(state);
            panel.appendChild(reviewBanner);
        }
    }
    containerEl.appendChild(panel);
}

function renderProvenanceExplorer(data, containerEl) {
    containerEl.innerHTML = '';
    const frames = data.frames || [];
    let hasAny = false;

    for (const frame of frames) {
        if (!frame.canonical_event) continue;
        const canon = frame.canonical_event;
        const fields = {
            timestamp:       canon.timestamp,
            source_ip:       canon.source_ip,
            source_hostname: canon.source_hostname,
            dest_ip:         canon.dest_ip,
            dest_hostname:   canon.dest_hostname,
            severity:        canon.severity,
            message:         canon.message,
            action:          canon.action,
        };

        const definedFields = Object.entries(fields).filter(([, v]) => v !== null && v !== undefined);
        if (definedFields.length === 0) continue;
        hasAny = true;

        const frameHeader = document.createElement('h4');
        frameHeader.style.cssText = 'color:var(--text-muted);margin:16px 0 12px;';
        frameHeader.innerHTML = `<i class="fa-solid fa-crop-simple"></i> Frame ${frame.frame_index} — Parser: ${frame.parser_id || 'None'} v${frame.parser_version || '?'}`;
        containerEl.appendChild(frameHeader);

        for (const [fieldName, fieldData] of definedFields) {
            const prov = fieldData.provenance;
            const fieldWrapper = document.createElement('div');
            fieldWrapper.className = 'prov-explorer-field';

            const fHeader = document.createElement('div');
            fHeader.className = 'prov-explorer-field-header';
            fHeader.setAttribute('role', 'button');
            fHeader.setAttribute('aria-expanded', 'false'); // Collapsed by default for cleaner look

            const headerLeft = document.createElement('span');
            headerLeft.innerHTML = `<i class="fa-solid fa-chevron-right" style="margin-right:8px;font-size:0.8rem;transition:transform 0.2s"></i>${fieldName}`;

            const headerRight = document.createElement('span');
            headerRight.style.cssText = 'font-family:monospace;font-size:0.85rem;color:var(--text-main);font-weight:400;';
            headerRight.textContent = String(fieldData.value).substring(0, 60) + (String(fieldData.value).length > 60 ? '…' : '');

            fHeader.appendChild(headerLeft);
            fHeader.appendChild(headerRight);
            fieldWrapper.appendChild(fHeader);

            const fBody = document.createElement('div');
            fBody.className = 'prov-explorer-field-body';
            fBody.style.display = 'none';

            fHeader.addEventListener('click', () => {
                const isOpen = fBody.style.display !== 'none';
                fBody.style.display = isOpen ? 'none' : '';
                fHeader.setAttribute('aria-expanded', String(!isOpen));
                fHeader.querySelector('i').style.transform = isOpen ? 'rotate(0deg)' : 'rotate(90deg)';
            });

            const chain = document.createElement('div');
            chain.className = 'prov-chain';

            function chainItem(label, value, sub, isLast) {
                const item = document.createElement('div');
                item.className = 'prov-chain-item';
                const lineCol = document.createElement('div');
                lineCol.className = 'prov-chain-line';
                const dot = document.createElement('div');
                dot.className = 'prov-chain-dot';
                lineCol.appendChild(dot);
                if (!isLast) {
                    const conn = document.createElement('div');
                    conn.className = 'prov-chain-connector';
                    lineCol.appendChild(conn);
                }
                item.appendChild(lineCol);
                const content = document.createElement('div');
                content.className = 'prov-chain-content';
                const lbl = document.createElement('div');
                lbl.className = 'prov-chain-label';
                lbl.textContent = label;
                const val = document.createElement('div');
                val.className = 'prov-chain-value';
                val.textContent = value;
                content.appendChild(lbl);
                content.appendChild(val);
                if (sub) {
                    const subEl = document.createElement('div');
                    subEl.className = 'prov-chain-sub';
                    subEl.textContent = sub;
                    content.appendChild(subEl);
                }
                item.appendChild(content);
                chain.appendChild(item);
            }

            chainItem('OCSF / Canonical field', fieldName, `Value: ${String(fieldData.value)}`, false);

            if (prov) {
                const ruleNote = `Rule: ${prov.rule_id}  |  Parser: ${frame.parser_id || 'None'}`;
                chainItem('ULPX-IR source field', prov.source_field, ruleNote, false);

                const byteInfo = prov.byte_span
                    ? `bytes [${prov.byte_span[0]}, ${prov.byte_span[1]}]  (${prov.byte_span[1] - prov.byte_span[0]} bytes)`
                    : 'Byte span not available';
                chainItem('Raw evidence byte range', byteInfo, null, true);

                const confBlock = document.createElement('div');
                confBlock.className = 'confidence-block';
                const confTitle = document.createElement('div');
                confTitle.className = 'confidence-block-title';
                confTitle.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i> Extraction Confidence';
                confBlock.appendChild(confTitle);
                confBlock.appendChild(buildConfidenceBar('Confidence', prov.confidence));

                if (prov.transformations && prov.transformations.length > 0) {
                    const trEl = document.createElement('div');
                    trEl.style.cssText = 'font-size:0.75rem;color:var(--text-muted);margin-top:8px;font-family:monospace';
                    trEl.textContent = 'Transforms: ' + prov.transformations.join(' → ');
                    confBlock.appendChild(trEl);
                }
                fBody.appendChild(chain);
                fBody.appendChild(confBlock);
            } else {
                chainItem('ULPX-IR source field', 'Provenance not available', null, true);
                fBody.appendChild(chain);
            }

            fieldWrapper.appendChild(fBody);
            containerEl.appendChild(fieldWrapper);
        }
    }

    if (!hasAny) {
        containerEl.innerHTML = `
            <div class="empty-state" style="padding: 30px;">
                <i class="fa-solid fa-code-branch fa-2x"></i>
                <p>No canonical fields with provenance data were found.</p>
            </div>
        `;
    }
}
