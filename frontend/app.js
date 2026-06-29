const API_URL = window.location.origin.startsWith('file://') ? 'http://localhost:3402/api' : `${window.location.origin}/api`;

let currentScanData = null;

async function submitScan() {
    const source = document.getElementById('source-code').value;
    const hash = document.getElementById('contract-hash').value || 'unknown';
    const btn = document.getElementById('scan-btn');
    const results = document.getElementById('results');
    const paymentModal = document.getElementById('payment-modal');

    btn.disabled = true;
    btn.classList.add('loading');
    btn.querySelector('.btn-text').textContent = 'Initiating Scan...';
    results.classList.add('hidden');

    currentScanData = { contract_hash: hash, source_code: source };

    try {
        const res = await fetch(`${API_URL}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentScanData),
        });

        if (res.status === 402) {
            // HTTP 402 Payment Required
            const paymentDetails = await res.json();
            showPaymentModal(paymentDetails);
        } else if (res.ok) {
            const data = await res.json();
            renderResults(data);
            results.classList.remove('hidden');
        } else {
            const err = await res.json();
            alert('Error: ' + (err.error || 'Unknown error'));
        }
    } catch (err) {
        alert('Network Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.classList.remove('loading');
        btn.querySelector('.btn-text').textContent = 'Scan for Vulnerabilities';
    }
}

// Casper Wallet Provider Initialization (Dynamic initialization to prevent race conditions)
let walletProvider = null;
function getWalletProvider() {
    if (!walletProvider && window.CasperWalletProvider) {
        try {
            walletProvider = new window.CasperWalletProvider();
        } catch (e) {
            console.error("Error instantiating CasperWalletProvider:", e);
        }
    }
    return walletProvider;
}

function showPaymentModal(details) {
    document.getElementById('pay-amount').textContent = details.amount_cspr + ' CSPR';
    document.getElementById('pay-address').textContent = details.payment_address;
    
    // Check if wallet is detected
    const provider = getWalletProvider();
    if (provider) {
        document.getElementById('casper-wallet-integration').style.display = 'block';
        document.getElementById('wallet-not-detected').style.display = 'none';
        
        // Check if we are already connected to a wallet
        const cachedPubKey = localStorage.getItem('sentinel_casper_pubkey');
        if (cachedPubKey) {
            showWalletConnected(cachedPubKey);
        } else {
            resetWalletUI();
        }
    } else {
        document.getElementById('casper-wallet-integration').style.display = 'none';
        document.getElementById('wallet-not-detected').style.display = 'block';
    }

    const modal = document.getElementById('payment-modal');
    modal.classList.remove('hidden');
    modal.style.display = 'flex';
}

async function connectCasperWallet() {
    const provider = getWalletProvider();
    if (!provider) {
        alert('Casper Wallet is not detected. Please install the extension.');
        return;
    }
    const connectBtn = document.getElementById('connect-wallet-btn');
    connectBtn.disabled = true;
    connectBtn.textContent = '🦊 Connecting Wallet...';
    try {
        const connected = await provider.requestConnection();
        if (connected) {
            const activeKey = await provider.getActivePublicKey();
            localStorage.setItem('sentinel_casper_pubkey', activeKey);
            showWalletConnected(activeKey);
        } else {
            alert('Connection rejected by user.');
            resetWalletUI();
        }
    } catch (err) {
        console.error("Casper Wallet connection error:", err);
        alert('Error connecting to Casper Wallet: ' + err.message);
        resetWalletUI();
    }
}

function showWalletConnected(activeKey) {
    document.getElementById('wallet-connect-section').style.display = 'none';
    document.getElementById('wallet-sign-section').style.display = 'block';
    document.getElementById('wallet-address-display').textContent = 
        activeKey.substring(0, 6) + '...' + activeKey.substring(activeKey.length - 6);
    document.getElementById('wallet-address-display').title = activeKey;
}

function resetWalletUI() {
    document.getElementById('wallet-connect-section').style.display = 'block';
    document.getElementById('wallet-sign-section').style.display = 'none';
    const connectBtn = document.getElementById('connect-wallet-btn');
    connectBtn.disabled = false;
    connectBtn.textContent = 'Connect Casper Wallet';
}

async function payWithCasperWallet() {
    const provider = getWalletProvider();
    if (!provider) {
        alert('Casper Wallet is not detected.');
        return;
    }
    const activeKey = localStorage.getItem('sentinel_casper_pubkey');
    if (!activeKey) {
        alert('Please connect your wallet first.');
        return;
    }
    const signBtn = document.getElementById('sign-tx-btn');
    signBtn.disabled = true;
    signBtn.textContent = '✍️ Waiting for signature...';

    // The message/challenge is the memo: "scan:<contract_hash>"
    const challenge = `scan:${currentScanData.contract_hash}`;

    try {
        const response = await provider.signMessage(challenge, activeKey);
        if (response.cancelled) {
            alert('Signing cancelled by user.');
            signBtn.disabled = false;
            signBtn.textContent = '✍️ Sign & Pay with Casper Wallet';
            return;
        }

        // Hide modal
        const modal = document.getElementById('payment-modal');
        modal.classList.add('hidden');
        modal.style.display = 'none';
        signBtn.disabled = false;
        signBtn.textContent = '✍️ Sign & Pay with Casper Wallet';

        // Submit signature to backend
        currentScanData.payment_proof = response.signatureHex || response.signature;
        currentScanData.public_key = activeKey;

        submitScanWithProof();
    } catch (err) {
        console.error("Casper Wallet signature error:", err);
        alert('Error signing message: ' + err.message);
        signBtn.disabled = false;
        signBtn.textContent = '✍️ Sign & Pay with Casper Wallet';
    }
}

async function simulateAgentPayment() {
    const btn = document.getElementById('pay-btn');
    btn.disabled = true;
    btn.textContent = '💸 Agent is signing tx...';

    // Simulate network delay for on-chain payment
    await new Promise(r => setTimeout(r, 1500));

    // Hide modal
    const modal = document.getElementById('payment-modal');
    modal.classList.add('hidden');
    modal.style.display = 'none';
    btn.disabled = false;
    btn.textContent = 'Simulate Agent Payment (Mock Fallback)';

    // Resubmit with proof
    currentScanData.payment_proof = 'mock_tx_hash_9a8b7c6d5e4f';
    currentScanData.public_key = null; // No public key needed for mock
    submitScanWithProof();
}


async function submitScanWithProof() {
    const btn = document.getElementById('scan-btn');
    const results = document.getElementById('results');

    btn.disabled = true;
    btn.classList.add('loading');
    btn.querySelector('.btn-text').textContent = 'Scanning (Verified)...';

    try {
        const res = await fetch(`${API_URL}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentScanData),
        });

        if (res.ok) {
            const data = await res.json();
            renderResults(data);
            results.classList.remove('hidden');
        } else {
            alert('Error validating scan after payment.');
        }
    } catch (err) {
        alert('Network Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.classList.remove('loading');
        btn.querySelector('.btn-text').textContent = 'Scan for Vulnerabilities';
    }
}

function renderResults(data) {
    const summary = document.getElementById('summary');
    summary.innerHTML = `
        <div class="summary-grid">
            <div class="stat critical">
                <span class="glow-dot" style="margin: 0 auto; width: 8px; height: 8px;"></span>
                <span style="margin-top: 1rem;">Critical (${data.summary.critical !== undefined ? data.summary.critical : 0})</span>
            </div>
            <div class="stat high">
                <span class="glow-dot" style="margin: 0 auto; width: 8px; height: 8px;"></span>
                <span style="margin-top: 1rem;">High (${data.summary.high !== undefined ? data.summary.high : 0})</span>
            </div>
            <div class="stat medium">
                <span class="glow-dot" style="margin: 0 auto; width: 8px; height: 8px;"></span>
                <span style="margin-top: 1rem;">Medium (${data.summary.medium !== undefined ? data.summary.medium : 0})</span>
            </div>
            <div class="stat low">
                <span class="glow-dot" style="margin: 0 auto; width: 8px; height: 8px;"></span>
                <span style="margin-top: 1rem;">Low (${data.summary.low !== undefined ? data.summary.low : 0})</span>
            </div>
            <div class="stat safe">
                <span class="glow-dot" style="margin: 0 auto; width: 8px; height: 8px;"></span>
                <span style="margin-top: 1rem;">Safe</span>
            </div>
        </div>
        <div class="audit-meta-block glass-panel" style="padding: 1.5rem; margin-bottom: 2rem;">
            <div class="meta-row">
                <span class="meta-label">Audit ID</span>
                <code class="meta-value">${data.audit_id}</code>
            </div>
            <div class="meta-row" style="margin-top: 0.75rem;">
                <span class="meta-label">Risk</span>
                <strong class="risk-${data.summary.risk_score.toLowerCase()} meta-value">${data.summary.risk_score}</strong>
            </div>
            ${data.on_chain ? `
            <hr class="meta-divider" style="border: 0; height: 1px; background: var(--border); margin: 1.25rem 0;">
            <div class="on-chain-proof" style="margin-top: 0; padding: 0; background: none; border: none;">
                <h3 style="font-size: 0.95rem; margin-bottom: 1rem; color: var(--text);">📝 On-Chain Proof (Casper Testnet)</h3>
                <div class="meta-row">
                    <span class="meta-label">Deploy Hash</span>
                    <code class="meta-value truncate-middle" title="${data.on_chain.deploy_hash}">${truncateMiddle(data.on_chain.deploy_hash, 24)}</code>
                    ${data.on_chain.simulated ? '<span class="simulated-badge">Simulated</span>' : ''}
                </div>
                <div class="meta-row" style="margin-top: 0.75rem;">
                    <span class="meta-label">Timestamp</span>
                    <code class="meta-value">${new Date(data.on_chain.timestamp * 1000).toISOString()}</code>
                </div>
                ${data.on_chain.simulated ? `
                <div class="wallet-warning" style="margin: 1rem 0; border: 1px dashed rgba(255, 184, 0, 0.3); background: rgba(255, 184, 0, 0.03); padding: 0.75rem; border-radius: 6px; font-size: 0.8rem; text-align: left;">
                    <p style="margin: 0; color: var(--text-dim); line-height: 1.4;">⚠️ <strong>Sandbox Simulation:</strong> This audit was completed in a local test sandbox. The deploy hash above is simulated. Click below to view a real transaction page on the Casper network explorer.</p>
                </div>
                <a href="https://testnet.cspr.live/deploy/dadbee1809cc85862a2665a464df669cac7e8cbd56c135c49abe2bb0759739b4" target="_blank" class="explorer-link" style="display: inline-block; padding: 0.5rem 1rem; background: linear-gradient(135deg, var(--medium), #e5a500); color: #0a0a0f; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 0.85rem;">🔍 View Sample Transaction on CSPR.live →</a>
                ` : `
                <a href="${data.on_chain.explorer_url}" target="_blank" class="explorer-link" style="display: inline-block; margin-top: 1rem; padding: 0.5rem 1rem; background: linear-gradient(135deg, var(--low), #2fa89e); color: #0a0a0f; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 0.85rem;">View on Casper Explorer →</a>
                `}
            </div>` : ''}
        </div>
    `;

    const list = document.getElementById('findings-list');
    if (data.findings.length === 0) {
        list.innerHTML = `<div class="finding"><p>No vulnerabilities found! Great job.</p></div>`;
        return;
    }

    const getIcon = (severity) => {
        switch(severity.toLowerCase()) {
            case 'critical': return '💥';
            case 'high': return '🔥';
            case 'medium': return '⚡';
            case 'low': return '⚠️';
            default: return '✅';
        }
    };

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, safe: 4 };
    const sorted = [...data.findings].sort((a, b) => 
        (severityOrder[a.severity.toLowerCase()] ?? 5) - (severityOrder[b.severity.toLowerCase()] ?? 5)
    );

    list.innerHTML = sorted.map((f, i) => `
        <div class="finding finding-${f.severity.toLowerCase()} animate-in glass-panel" style="animation-delay: ${0.1 + i * 0.15}s; padding: 1.5rem; border-left: 2px solid var(--${f.severity.toLowerCase()});">
            <div class="finding-header">
                <span class="badge badge-${f.severity.toLowerCase()}">
                    <span class="glow-dot"></span>
                    <span style="position: relative; z-index: 1;">${getIcon(f.severity)} ${f.severity}</span>
                </span>
                <span class="finding-id">${f.id}</span>
                <span class="finding-line">L${f.line}</span>
            </div>
            <h3>${f.title}</h3>
            <p>${f.description}</p>
            ${f.ai_explanation ? `
            <div class="ai-explanation">
                <span class="ai-badge">AI Analysis</span>
                <p>${f.ai_explanation}</p>
            </div>` : ''}
        </div>
    `).join('');

    saveToHistory(data);
    renderHistory();
}

// History Management
function saveToHistory(data) {
    let history = JSON.parse(localStorage.getItem('sentinel402_history') || '[]');
    history.unshift({
        id: data.audit_id,
        timestamp: new Date().toLocaleString(),
        score: data.summary.risk_score,
        findings: data.summary.total_findings,
        contract: data.on_chain?.contract_hash || 'unknown',
        explorer: data.on_chain?.explorer_url || '#'
    });
    // Keep only last 10
    if (history.length > 10) history = history.slice(0, 10);
    localStorage.setItem('sentinel402_history', JSON.stringify(history));
}

function renderHistory() {
    const list = document.getElementById('history-list');
    let history = JSON.parse(localStorage.getItem('sentinel402_history') || '[]');
    
    if (history.length === 0) {
        list.innerHTML = `<p class="small-text">No scans yet. Paste a contract above to start.</p>`;
        return;
    }

    list.innerHTML = history.map(h => {
        const score = h.score || h.risk || h.score_risk || 'LOW';
        const scoreClass = score.toLowerCase();
        const id = h.id || 'unknown';
        const timestamp = h.timestamp || '';
        const contract = h.contract || 'unknown';
        const findings = h.findings !== undefined ? h.findings : 0;
        const explorer = h.explorer || '#';
        
        return `
            <div class="history-item glass-panel score-${scoreClass}">
                <div class="history-score">
                    <span class="badge badge-${scoreClass}">
                        <span class="glow-dot"></span>
                        <span style="position: relative; z-index: 1;">${score}</span>
                    </span>
                </div>
                <div class="history-body">
                    <div class="history-id-time">
                        <strong title="${id}">${truncateMiddle(id, 20)}</strong>
                        <span class="small-text history-time">${timestamp}</span>
                    </div>
                </div>
                <div class="history-metrics">
                    <div class="metric-row">
                        <span class="metric-label">Contract:</span> 
                        <span class="metric-val" title="${contract}">${truncateMiddle(contract, 16)}</span>
                    </div>
                    <div class="metric-row">
                        <span class="metric-label">Findings:</span> 
                        <span class="metric-val">${findings}</span>
                    </div>
                </div>
                <div class="history-actions">
                    ${explorer !== '#' ? `<a href="${explorer}" target="_blank" class="explorer-link-mini">🔍 Explorer</a>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function truncateMiddle(str, maxLength) {
    if (!str || str.length <= maxLength) return str;
    const half = Math.floor((maxLength - 3) / 2);
    return str.substring(0, half) + '...' + str.substring(str.length - half);
}

// Explicit global binding for HTML event handlers
window.submitScan = submitScan;
window.connectCasperWallet = connectCasperWallet;
window.payWithCasperWallet = payWithCasperWallet;
window.simulateAgentPayment = simulateAgentPayment;

// Advanced Glow Dot Proximity Animation
let mouseX = -1000;
let mouseY = -1000;

document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
});

function animateGlowDots() {
    const dots = document.querySelectorAll('.glow-dot');
    dots.forEach(dot => {
        const rect = dot.getBoundingClientRect();
        if (rect.width === 0) return;
        
        const dotX = rect.left + rect.width / 2;
        const dotY = rect.top + rect.height / 2;
        
        const dx = mouseX - dotX;
        const dy = mouseY - dotY;
        const distance = Math.sqrt(dx * dx + dy * dy);
        
        const maxDistance = 300;
        let targetIntensity = 0;
        
        const parent = dot.closest('.finding, .history-item, .stat');
        const isHovered = parent && parent.matches(':hover');
        
        if (isHovered) {
            targetIntensity = 0.25;
        }
        
        if (distance < maxDistance) {
            const proximity = Math.pow(1 - (distance / maxDistance), 2);
            targetIntensity = Math.max(targetIntensity, proximity);
        }
        
        let currentIntensity = parseFloat(dot.getAttribute('data-intensity') || '0');
        
        const lerpFactor = targetIntensity > currentIntensity ? 0.04 : 0.08;
        currentIntensity += (targetIntensity - currentIntensity) * lerpFactor;
        
        if (Math.abs(targetIntensity - currentIntensity) < 0.001) {
            currentIntensity = targetIntensity;
        }
        
        dot.setAttribute('data-intensity', currentIntensity);
        dot.style.setProperty('--glow-intensity', currentIntensity.toFixed(3));
        
        // Dynamic box-shadow: base 4px → max 12px, spread 1px → 4px
        const blur1 = 4 + currentIntensity * 8;
        const spread1 = 1 + currentIntensity * 3;
        const blur2 = 10 + currentIntensity * 14;
        const spread2 = 2 + currentIntensity * 6;
        dot.style.boxShadow = `0 0 ${blur1}px ${spread1}px currentColor, 0 0 ${blur2}px ${spread2}px currentColor`;
        
        // PCB texture reacts at 1/3 the intensity of glow dots
        if (parent) {
            parent.style.setProperty('--pcb-intensity', (currentIntensity / 3).toFixed(3));
        }
    });
    
    requestAnimationFrame(animateGlowDots);
}

// Init
document.addEventListener('DOMContentLoaded', () => {
    renderHistory();
    requestAnimationFrame(animateGlowDots);
});
