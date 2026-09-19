const API_BASE = '/api/v1';

let currentOffset = 0;
const LIMIT = 20;
let selectedEventId = null;

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
const framesContainerEl = document.getElementById('frames-container');

// Replay View
const replayForm = document.getElementById('replay-form');
const runReplayBtn = document.getElementById('run-replay-btn');
const replayResultsEl = document.getElementById('replay-results');
const replayMetadataEl = document.getElementById('replay-metadata');
const replayFramesContainerEl = document.getElementById('replay-frames-container');
const replayErrorEl = document.getElementById('replay-error');

// XSS Prevention Helper
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// Safe Byte Decoding Helper
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
        // Fallback to hex representation for binary/non-UTF-8 data
        return {
            text: Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' '),
            length: len
        };
    }
}

// Init
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
                // innerHTML is safe here because evt.event_id and evt.source are strictly escaped
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
        // innerHTML is safe because err.message is strictly escaped
        eventsListEl.innerHTML = `<div style="padding: 20px; color: var(--danger);">${escapeHtml(err.message)}</div>`;
    }
}

function selectEvent(id, element) {
    selectedEventId = id;
    document.querySelectorAll('.event-item').forEach(el => el.classList.remove('selected'));
    if (element) element.classList.add('selected');

    emptyStateEl.classList.add('hidden');
    investigationViewEl.classList.remove('hidden');
    
    // textContent is used to strictly prevent DOM injection of event_id
    currentEventIdEl.textContent = id; 
    
    // Reset Replay
    replayResultsEl.classList.add('hidden');
    replayErrorEl.classList.add('hidden');

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
        
        // innerHTML is safe because data.source and data.size_bytes are strictly escaped
        evidenceMetadataEl.innerHTML = `
            <div class="meta-item"><label>Source</label><span>${escapeHtml(data.source)}</span></div>
            <div class="meta-item"><label>Size</label><span>${escapeHtml(data.size_bytes)} bytes</span></div>
        `;
        
        const decoded = decodeBytes(data.payload_base64);
        evidenceBytesEl.textContent = decoded.text;
    } catch (err) {
        // innerHTML is safe because err.message is strictly escaped
        evidenceMetadataEl.innerHTML = `<span style="color: var(--danger);">${escapeHtml(err.message)}</span>`;
    }
}

async function loadInterpretation(id) {
    interpretationMetadataEl.textContent = 'Loading...';
    framesContainerEl.textContent = '';
    try {
        const res = await fetch(`${API_BASE}/interpretation/${id}/detailed`);
        if (!res.ok) throw new Error('Failed to fetch interpretation');
        const data = await res.json();
        
        renderInterpretation(data, interpretationIntegrityEl, interpretationMetadataEl, framesContainerEl);
    } catch (err) {
        // innerHTML is safe because err.message is strictly escaped
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
        replayErrorEl.textContent = err.message; // textContent handles escaping
    } finally {
        runReplayBtn.disabled = false;
        runReplayBtn.textContent = 'Run Reprocessing';
    }
}

function renderInterpretation(data, integrityBadgeEl, metaEl, framesEl) {
    if (integrityBadgeEl) {
        if (data.integrity_verified) {
            integrityBadgeEl.className = 'badge badge-success';
            integrityBadgeEl.textContent = 'Integrity Verified';
        } else {
            integrityBadgeEl.className = 'badge badge-error';
            integrityBadgeEl.textContent = `Integrity Error: ${escapeHtml(data.integrity_error || 'Unknown')}`;
        }
    }

    // innerHTML is safe because all dynamic fields (id, identity, date, trailing_error) are strictly escaped
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
        
        let inferenceHtml = '';
        if (frame.inference_decision) {
            const inf = frame.inference_decision;
            // innerHTML is safe because all inference fields are strictly escaped
            inferenceHtml = `
                <div class="prov-field">
                    <div class="prov-field-name">Inference: ${escapeHtml(inf.decision)}</div>
                    <div class="prov-details">
                        ${inf.abstention_reason ? `Reason: ${escapeHtml(inf.abstention_reason)}<br>` : ''}
                        ${inf.recognized_candidate ? `Selected: ${escapeHtml(inf.recognized_candidate.parser_id)} (${escapeHtml(inf.recognized_candidate.confidence)})<br>` : ''}
                        Evaluated candidates: ${escapeHtml((inf.all_candidates || []).map(c => c.parser_id).join(', ') || 'None')}
                    </div>
                </div>
            `;
        }

        let canonicalHtml = '';
        if (frame.canonical_event) {
            const c = frame.canonical_event;
            const fields = Object.entries(c)
                .filter(([k,v]) => v !== null && v !== undefined)
                .map(([k, v]) => `
                    <div class="prov-field">
                        <div class="prov-field-name">${escapeHtml(k)}</div>
                        <div>${escapeHtml(typeof v.value === 'object' ? JSON.stringify(v.value) : String(v.value))}</div>
                        ${v.provenance ? `
                            <div class="prov-details">
                                Source Field: ${escapeHtml(v.provenance.source_field)}<br>
                                Rule: ${escapeHtml(v.provenance.rule_id)} (${escapeHtml(v.provenance.confidence)})<br>
                                Span: ${v.provenance.byte_span ? `[${escapeHtml(v.provenance.byte_span[0])}, ${escapeHtml(v.provenance.byte_span[1])}]` : 'N/A'}<br>
                                Transforms: ${escapeHtml((v.provenance.transformations || []).join(' -> '))}
                            </div>
                        ` : ''}
                    </div>
                `).join('');
            canonicalHtml = `<h4>Canonical Fields</h4>${fields}`;
        }

        // innerHTML is safe here because all frame fields, inferenceHtml, and canonicalHtml are escaped explicitly above
        fEl.innerHTML = `
            <div class="frame-header">
                <strong>Frame ${escapeHtml(frame.frame_index)}</strong>
                <span>${escapeHtml(frame.parser_id)} (v${escapeHtml(frame.parser_version)}) - ${escapeHtml(frame.parser_outcome)}</span>
            </div>
            <div class="frame-body">
                ${inferenceHtml}
                ${canonicalHtml}
                <h4>Raw Bytes (Length: <span class="byte-len"></span>)</h4>
                <pre class="raw-bytes"></pre>
            </div>
        `;
        
        // Use textContent for raw bytes to prevent injection inherently
        const decodedBytes = decodeBytes(frame.frame_bytes_base64);
        fEl.querySelector('.raw-bytes').textContent = decodedBytes.text;
        fEl.querySelector('.byte-len').textContent = decodedBytes.length;
        
        framesEl.appendChild(fEl);
    });
}