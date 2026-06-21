const API_URL = window.location.origin.startsWith('file://') ? 'http://localhost:3402/api' : `${window.location.origin}/api`;

let currentScanData = null;

async function submitScan() {
    const source = document.getElementById('source-code').value;
    const hash = document.getElementById('contract-hash').value || 'unknown';
    const btn = document.getElementById('scan-btn');
    const results = document.getElementById('results');
    const paymentModal = document.getElementById('payment-modal');

    btn.disabled = true;
    btn.textContent = '🔍 Initiating Scan...';
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
        btn.textContent = '⚡ Scan for Vulnerabilities';
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

    document.getElementById('payment-modal').style.display = 'flex';
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
        document.getElementById('payment-modal').style.display = 'none';
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
    document.getElementById('payment-modal').style.display = 'none';
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
    btn.textContent = '🔍 Scanning (Payment Verified)...';

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
        btn.textContent = '⚡ Scan for Vulnerabilities';
    }
}

function renderResults(data) {
    const summary = document.getElementById('summary');
    summary.innerHTML = `
        <div class="summary-grid">
            <div class="stat catastrophe">${data.summary.catastrophe} <span>Catastrophe</span></div>
            <div class="stat disaster">${data.summary.disaster} <span>Disaster</span></div>
            <div class="stat calamity">${data.summary.calamity} <span>Calamity</span></div>
            <div class="stat hazard">${data.summary.hazard} <span>Hazard</span></div>
        </div>
        <p class="audit-id">Audit ID: <code>${data.audit_id}</code></p>
        <p class="risk-score">Risk: <strong class="risk-${data.summary.risk_score.toLowerCase()}">${data.summary.risk_score}</strong></p>
        ${data.on_chain ? `
        <div class="on-chain-proof">
            <h3>📝 On-Chain Proof (Casper Testnet)</h3>
            <p>Deploy Hash: <code>${data.on_chain.deploy_hash}</code> ${data.on_chain.simulated ? '<span class="badge badge-low" style="background: rgba(78, 205, 196, 0.15); color: var(--low); font-size: 0.7rem; margin-left: 0.5rem; vertical-align: middle;">Simulated</span>' : ''}</p>
            <p>Timestamp: <code>${new Date(data.on_chain.timestamp * 1000).toISOString()}</code></p>
            ${data.on_chain.simulated ? `
            <div class="wallet-warning" style="margin: 0.75rem 0; border: 1px dashed rgba(255, 184, 0, 0.3); background: rgba(255, 184, 0, 0.03); padding: 0.75rem; border-radius: 6px; font-size: 0.8rem; text-align: left;">
                <p style="margin: 0; color: var(--text-dim); line-height: 1.4;">⚠️ <strong>Sandbox Simulation:</strong> This audit was completed in a local test sandbox. The deploy hash above is simulated. Click below to view a real transaction page on the Casper network explorer.</p>
            </div>
            <a href="https://testnet.cspr.live/deploy/dadbee1809cc85862a2665a464df669cac7e8cbd56c135c49abe2bb0759739b4" target="_blank" class="explorer-link" style="background: linear-gradient(135deg, var(--medium), #e5a500); color: #0a0a0f;">🔍 View Sample Transaction on CSPR.live →</a>
            ` : `
            <a href="${data.on_chain.explorer_url}" target="_blank" class="explorer-link">View on Casper Explorer →</a>
            `}
        </div>` : ''}
    `;

    const list = document.getElementById('findings-list');
    if (data.findings.length === 0) {
        list.innerHTML = `<div class="finding"><p>No vulnerabilities found! Great job.</p></div>`;
        return;
    }

    list.innerHTML = data.findings.map(f => `
        <div class="finding finding-${f.severity.toLowerCase()}">
            <div class="finding-header">
                <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                <span class="finding-id">${f.id}</span>
                <span class="finding-line">L${f.line}</span>
            </div>
            <h3>${f.title}</h3>
            <p>${f.description}</p>
            ${f.ai_explanation ? `
            <div class="ai-explanation">
                <span class="ai-badge">🧠 AI Analysis</span>
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
            <div class="history-item">
                <div class="history-header">
                    <span class="badge badge-${scoreClass}">${score}</span>
                    <strong>${id}</strong>
                    <span class="small-text" style="margin: 0; margin-left: auto;">${timestamp}</span>
                </div>
                <div class="history-details">
                    <span>Contract: ${contract}</span>
                    <span>Findings: ${findings}</span>
                    ${explorer !== '#' ? `<a href="${explorer}" target="_blank">View on Explorer</a>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

// Explicit global binding for HTML event handlers
window.submitScan = submitScan;
window.connectCasperWallet = connectCasperWallet;
window.payWithCasperWallet = payWithCasperWallet;
window.simulateAgentPayment = simulateAgentPayment;

// Init
document.addEventListener('DOMContentLoaded', () => {
    renderHistory();
});
