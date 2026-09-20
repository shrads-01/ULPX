const API_BASE = '/api/v1';

let currentOffset = 0;
const LIMIT = 20;
let selectedEventId = null;

// Cached last interpretation (shared between Interpretation and Provenance tabs)
let lastInterpretationData = null;

// Elements
const eventsListEl = document.getElementById('events-list');
const prevPageBtn = document.getElementById('prev-page-btn');
const nextPageBtn = document.getElementById('next-page-btn');
const pageInfoEl = document.getElementById('page-info');
const refreshBtn = document.getElementById('refresh-events-btn');

const emptyStateEl = document.getElementById('empty-state');
const investigationViewEl = document.getElementById('investigation-view');
const currentEventIdEl = document.getElementById('current-event-id');

const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

// Evidence View
const evidenceMetadataEl = document.getElementById('evidence-metadata');
const evidenceBytesEl = document.getElementById('evidence-bytes');

// Interpretation View
const interpretationIntegrityEl = document.getElementById('interpretation-integrity');
const interpretationMetadataEl = document.getElementById('interpretation-metadata');
const unknownFormatContainerEl = document.getElementById('unknown-format-container');
const framesContainerEl = document.getElementById('frames-container');

// Provenance Explorer
const provenanceExplorerEl = document.getElementById('provenance-explorer-container');

// Replay View
const replayForm = document.getElementById('replay-form');
const runReplayBtn = document.getElementById('run-replay-btn');
const replayResultsEl = document.getElementById('replay-results');
const replayMetadataEl = document.getElementById('replay-metadata');
const replayFramesContainerEl = document.getElementById('replay-frames-container');
const replayErrorEl = document.getElementById('replay-error');

// ── XSS Prevention ──────────────────────────────────────────────────────────
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// ── Safe Byte Decoding ──────────────────────────────────────────────────────
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

// ── Confidence Bar ──────────────────────────────────────────────────────────
// level: "High" | "Medium" | "Low" | "Certain" | "Probable" | "Heuristic"
// Returns percentage (0-100) and CSS class for fill colour
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
    // Use textContent assignment for label to avoid injection
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

// ── Unknown-Format Panel ────────────────────────────────────────────────────
// Renders the unknown-format review panel if any frame uses inference.
function renderUnknownFormatPanel(frames, containerEl) {
    containerEl.innerHTML = '';
    const inferredFrames = (frames || []).filter(f => f.inference_decision !== null && f.inference_decision !== undefined);
    if (inferredFrames.length === 0) return;

    const panel = document.createElement('div');
    panel.className = 'unknown-format-panel';

    // Title
    const title = document.createElement('div');
    title.className = 'unknown-format-title';
    title.innerHTML = '⚠ Unknown Format Detected';
    panel.appendChild(title);

    const sub = document.createElement('div');
    sub.className = 'unknown-format-subtitle';
    sub.textContent = `${inferredFrames.length} frame(s) could not be parsed by a known parser — inference engine engaged.`;
    panel.appendChild(sub);

    for (const frame of inferredFrames) {
        const inf = frame.inference_decision;

        // Abstention banner
        if (inf.decision === 'Abstained') {
            const banner = document.createElement('div');
            banner.className = 'abstention-banner';
            const reason = escapeHtml(inf.abstention_reason || 'Insufficient evidence');
            banner.innerHTML = `⊘ Inference abstained — ${reason}`;
            panel.appendChild(banner);
        }

        // Candidate cards
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
                nameEl.textContent = cand.format_name || cand.parser_id;
                header.appendChild(nameEl);

                const isSelected = inf.recognized_candidate && inf.recognized_candidate.parser_id === cand.parser_id;
                const statusEl = document.createElement('span');
                statusEl.className = `candidate-status ${isSelected ? 'selected' : 'abstained'}`;
                statusEl.textContent = isSelected ? 'Selected' : (inf.decision === 'Abstained' ? 'Abstained' : 'Not selected');
                header.appendChild(statusEl);
                card.appendChild(header);

                // Confidence bar for candidate
                card.appendChild(buildConfidenceBar('Confidence', cand.confidence));

                // Evidence list
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

        // Review action banner if a candidate was selected
        if (inf.decision === 'Recognized' && inf.recognized_candidate) {
            const reviewBanner = document.createElement('div');
            reviewBanner.className = 'review-action-banner';
            const txt = document.createElement('div');
            txt.className = 'review-action-text';
            txt.textContent = `Candidate parser "${escapeHtml(inf.recognized_candidate.parser_id)}" generated — ready for human review before promotion.`;
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

// ── Provenance Explorer ─────────────────────────────────────────────────────
// Renders the provenance explorer for all canonical fields across frames.
// Each field shows: OCSF canonical name → source field (ULPX-IR) → raw byte span
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
        frameHeader.style.cssText = 'color:var(--text-muted);margin-bottom:12px;';
        frameHeader.textContent = `Frame ${frame.frame_index} — Parser: ${frame.parser_id || 'None'} v${frame.parser_version || '?'}`;
        containerEl.appendChild(frameHeader);

        for (const [fieldName, fieldData] of definedFields) {
            const prov = fieldData.provenance;

            const fieldWrapper = document.createElement('div');
            fieldWrapper.className = 'prov-explorer-field';

            // Collapsible header
            const fHeader = document.createElement('div');
            fHeader.className = 'prov-explorer-field-header';
            fHeader.setAttribute('role', 'button');
            fHeader.setAttribute('aria-expanded', 'true');
            // All safe: fieldName is a known static key, fieldData.value is escaped
            const headerLeft = document.createElement('span');
            headerLeft.textContent = fieldName;
            const headerRight = document.createElement('span');
            headerRight.style.cssText = 'font-family:monospace;font-size:0.85rem;color:var(--text-main);font-weight:400;';
            headerRight.textContent = String(fieldData.value).substring(0, 60) + (String(fieldData.value).length > 60 ? '…' : '');
            fHeader.appendChild(headerLeft);
            fHeader.appendChild(headerRight);
            fieldWrapper.appendChild(fHeader);

            const fBody = document.createElement('div');
            fBody.className = 'prov-explorer-field-body';

            // Collapsible toggle
            fHeader.addEventListener('click', () => {
                const isOpen = fBody.style.display !== 'none';
                fBody.style.display = isOpen ? 'none' : '';
                fHeader.setAttribute('aria-expanded', String(!isOpen));
            });

            // Provenance chain: OCSF field → ULPX source field → byte range
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

            // Step 1: OCSF canonical field name
            chainItem('OCSF / Canonical field', fieldName, `Value: ${String(fieldData.value)}`, false);

            // Step 2: ULPX-IR source field
            if (prov) {
                const ruleNote = `Rule: ${prov.rule_id}  |  Parser: ${frame.parser_id || 'None'}`;
                chainItem('ULPX-IR source field', prov.source_field, ruleNote, false);

                // Step 3: Byte range in original evidence
                const byteInfo = prov.byte_span
                    ? `bytes [${prov.byte_span[0]}, ${prov.byte_span[1]}]  (${prov.byte_span[1] - prov.byte_span[0]} bytes)`
                    : 'Byte span not available';
                chainItem('Raw evidence byte range', byteInfo, null, true);

                // Confidence block
                const confBlock = document.createElement('div');
                confBlock.className = 'confidence-block';
                const confTitle = document.createElement('div');
                confTitle.className = 'confidence-block-title';
                confTitle.textContent = 'Extraction Confidence';
                confBlock.appendChild(confTitle);
                confBlock.appendChild(buildConfidenceBar('Confidence', prov.confidence));
                if (prov.transformations && prov.transformations.length > 0) {
                    const trEl = document.createElement('div');
                    trEl.style.cssText = 'font-size:0.75rem;color:var(--text-muted);margin-top:8px;';
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
        const msg = document.createElement('div');
        msg.style.cssText = 'color:var(--text-muted);padding:16px;';
        msg.textContent = 'No canonical fields with provenance data were found in this interpretation.';
        containerEl.appendChild(msg);
    }
}

// ── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadEvents();
    
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

    refreshBtn.addEventListener('click', () => {
        currentOffset = 0;
        loadEvents();
    });

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById('tab-' + btn.dataset.tab).classList.add('active');

            // Populate provenance tab lazily when it is first selected
            if (btn.dataset.tab === 'provenance' && lastInterpretationData) {
                renderProvenanceExplorer(lastInterpretationData, provenanceExplorerEl);
            }
        });
    });

    replayForm.addEventListener('submit', (e) => {
        e.preventDefault();
        runReplay();
    });
});

async function loadEvents() {
    try {
        const res = await fetch(`${API_BASE}/events?offset=${currentOffset}&limit=${LIMIT}`);
        if (!res.ok) throw new Error('Failed to fetch events');
        const data = await res.json();
        
        eventsListEl.innerHTML = '';
        if (!data || !data.events || data.events.length === 0) {
            eventsListEl.innerHTML = '<div style="padding: 20px; color: var(--text-muted);">No events found.</div>';
            nextPageBtn.disabled = true;
        } else {
            data.events.forEach(evt => {
                const el = document.createElement('div');
                el.className = 'event-item' + (evt.event_id === selectedEventId ? ' selected' : '');
                el.innerHTML = `
                    <div class="event-id">${escapeHtml(evt.event_id)}</div>
                    <div class="event-meta">
                        <span>${escapeHtml(evt.source)}</span>
                        <span>${evt.has_integrity ? '🔒' : '⚠️'}</span>
                    </div>
                `;
                el.addEventListener('click', () => selectEvent(evt.event_id, el));
                eventsListEl.appendChild(el);
            });
            nextPageBtn.disabled = data.events.length < LIMIT;
        }
        
        prevPageBtn.disabled = currentOffset === 0;
        pageInfoEl.textContent = `Page ${(currentOffset / LIMIT) + 1}`;
    } catch (err) {
        eventsListEl.innerHTML = `<div style="padding: 20px; color: var(--danger);">${escapeHtml(err.message)}</div>`;
    }
}

function selectEvent(id, element) {
    selectedEventId = id;
    lastInterpretationData = null;

    document.querySelectorAll('.event-item').forEach(el => el.classList.remove('selected'));
    if (element) element.classList.add('selected');

    emptyStateEl.classList.add('hidden');
    investigationViewEl.classList.remove('hidden');
    
    // textContent to prevent DOM injection
    currentEventIdEl.textContent = id; 
    
    // Reset Replay
    replayResultsEl.classList.add('hidden');
    replayErrorEl.classList.add('hidden');

    // Reset Provenance explorer
    provenanceExplorerEl.innerHTML = '<div style="color: var(--text-muted);">Loading interpretation…</div>';

    // Switch to Evidence tab when selecting a new event
    tabBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));
    document.querySelector('.tab-btn[data-tab="evidence"]').classList.add('active');
    document.getElementById('tab-evidence').classList.add('active');

    loadEvidence(id);
    loadInterpretation(id);
}

async function loadEvidence(id) {
    evidenceMetadataEl.textContent = 'Loading...';
    evidenceBytesEl.textContent = '';
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
        evidenceMetadataEl.innerHTML = `<span style="color: var(--danger);">${escapeHtml(err.message)}</span>`;
    }
}

async function loadInterpretation(id) {
    interpretationMetadataEl.textContent = 'Loading...';
    framesContainerEl.textContent = '';
    unknownFormatContainerEl.innerHTML = '';
    try {
        const res = await fetch(`${API_BASE}/interpretation/${id}/detailed`);
        if (!res.ok) throw new Error('Failed to fetch interpretation');
        const data = await res.json();
        
        lastInterpretationData = data;

        renderInterpretation(data, interpretationIntegrityEl, interpretationMetadataEl, framesContainerEl);
        renderUnknownFormatPanel(data.frames, unknownFormatContainerEl);

        // Pre-populate provenance tab if it's already active
        const provTab = document.querySelector('.tab-btn[data-tab="provenance"]');
        if (provTab && provTab.classList.contains('active')) {
            renderProvenanceExplorer(data, provenanceExplorerEl);
        } else {
            provenanceExplorerEl.innerHTML = '<div style="color: var(--text-muted);">Click the Provenance tab to explore field lineage.</div>';
        }
    } catch (err) {
        interpretationMetadataEl.innerHTML = `<span style="color: var(--danger);">${escapeHtml(err.message)}</span>`;
    }
}

async function runReplay() {
    if (!selectedEventId) return;
    
    runReplayBtn.disabled = true;
    runReplayBtn.textContent = 'Running...';
    replayErrorEl.classList.add('hidden');
    replayResultsEl.classList.add('hidden');
    
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
        replayResultsEl.classList.remove('hidden');
        renderInterpretation(data, null, replayMetadataEl, replayFramesContainerEl);
        
    } catch (err) {
        replayErrorEl.classList.remove('hidden');
        replayErrorEl.textContent = err.message;
    } finally {
        runReplayBtn.disabled = false;
        runReplayBtn.textContent = 'Run Reprocessing';
    }
}

function renderInterpretation(data, integrityBadgeEl, metaEl, framesEl) {
    if (integrityBadgeEl) {
        if (data.integrity_verified) {
            integrityBadgeEl.className = 'badge badge-success';
            integrityBadgeEl.textContent = 'Integrity Verified ✓';
        } else {
            integrityBadgeEl.className = 'badge badge-error';
            integrityBadgeEl.textContent = `Integrity Error: ${escapeHtml(data.integrity_error || 'Unknown')}`;
        }
    }

    metaEl.innerHTML = `
        <div class="meta-item"><label>Interpretation ID</label><span>${escapeHtml(data.interpretation_id)}</span></div>
        <div class="meta-item"><label>Pipeline Config Identity</label><span>${escapeHtml(data.pipeline_config_identity)}</span></div>
        <div class="meta-item"><label>Created At</label><span>${escapeHtml(new Date(data.created_at_secs * 1000).toLocaleString())}</span></div>
        ${data.trailing_frame_error ? `<div class="meta-item"><label>Trailing Error</label><span style="color:var(--danger);">${escapeHtml(data.trailing_frame_error)}</span></div>` : ''}
    `;

    framesEl.innerHTML = '';
    if (!data.frames || data.frames.length === 0) {
        framesEl.innerHTML = '<div style="color: var(--text-muted);">No frames detected.</div>';
        return;
    }

    data.frames.forEach(frame => {
        const fEl = document.createElement('div');
        fEl.className = 'frame-block';
        
        // ── Inference section (abbreviated — full view in Unknown-format panel)
        let inferenceHtml = '';
        if (frame.inference_decision) {
            const inf = frame.inference_decision;
            const sel = inf.recognized_candidate;
            inferenceHtml = `
                <div class="prov-field">
                    <div class="prov-field-name">Inference: ${escapeHtml(inf.decision)}</div>
                    <div class="prov-details">
                        ${inf.abstention_reason ? `Reason: ${escapeHtml(inf.abstention_reason)}<br>` : ''}
                        ${sel ? `Selected: ${escapeHtml(sel.parser_id)} (${escapeHtml(sel.confidence)})<br>` : ''}
                        Evaluated candidates: ${escapeHtml((inf.all_candidates || []).map(c => c.parser_id).join(', ') || 'None')}
                    </div>
                </div>
            `;
        }

        // ── Canonical fields with per-field confidence bars
        let canonicalHtml = '';
        if (frame.canonical_event) {
            const c = frame.canonical_event;
            const fieldEntries = Object.entries(c)
                .filter(([k]) => k !== 'parser_id')
                .filter(([, v]) => v !== null && v !== undefined);

            if (fieldEntries.length > 0) {
                // Build DOM nodes instead of innerHTML for confidence bars
                const canonWrap = document.createElement('div');
                const title = document.createElement('h4');
                title.textContent = 'Canonical Fields';
                canonWrap.appendChild(title);

                for (const [k, v] of fieldEntries) {
                    const fieldDiv = document.createElement('div');
                    fieldDiv.className = 'prov-field';

                    const nameDiv = document.createElement('div');
                    nameDiv.className = 'prov-field-name';
                    nameDiv.textContent = k;
                    fieldDiv.appendChild(nameDiv);

                    const valDiv = document.createElement('div');
                    valDiv.textContent = typeof v.value === 'object' ? JSON.stringify(v.value) : String(v.value);
                    fieldDiv.appendChild(valDiv);

                    if (v.provenance) {
                        // Confidence bar
                        fieldDiv.appendChild(buildConfidenceBar('Confidence', v.provenance.confidence));

                        const detDiv = document.createElement('div');
                        detDiv.className = 'prov-details';
                        let detText = `Source Field: ${v.provenance.source_field}\nRule: ${v.provenance.rule_id}`;
                        if (v.provenance.byte_span) {
                            detText += `\nByte Span: [${v.provenance.byte_span[0]}, ${v.provenance.byte_span[1]}]`;
                        }
                        if (v.provenance.transformations && v.provenance.transformations.length > 0) {
                            detText += `\nTransforms: ${v.provenance.transformations.join(' → ')}`;
                        }
                        detDiv.textContent = detText;
                        fieldDiv.appendChild(detDiv);
                    }

                    canonWrap.appendChild(fieldDiv);
                }

                // Serialize to string for later insertion (safe because all text is set via textContent)
                fEl.appendChild(document.createComment('canonical-placeholder'));
                // We'll append canonWrap directly after frame is in DOM
                fEl._canonWrap = canonWrap;
            }
        }

        fEl.innerHTML = `
            <div class="frame-header">
                <strong>Frame ${escapeHtml(frame.frame_index)}</strong>
                <span>${escapeHtml(frame.parser_id || 'None')} (v${escapeHtml(frame.parser_version || '?')}) — ${escapeHtml(frame.parser_outcome)}</span>
            </div>
            <div class="frame-body">
                ${inferenceHtml}
                <div class="frame-canonical-slot"></div>
                <h4>Raw Bytes (Length: <span class="byte-len"></span>)</h4>
                <pre class="raw-bytes"></pre>
            </div>
        `;
        
        // Insert canonical fields safely
        if (fEl._canonWrap) {
            fEl.querySelector('.frame-canonical-slot').appendChild(fEl._canonWrap);
        }

        // Use textContent for raw bytes
        const decodedBytes = decodeBytes(frame.frame_bytes_base64);
        fEl.querySelector('.raw-bytes').textContent = decodedBytes.text;
        fEl.querySelector('.byte-len').textContent = decodedBytes.length;
        
        framesEl.appendChild(fEl);
    });
}