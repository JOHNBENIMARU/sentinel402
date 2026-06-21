# Sentinel402 — Deploy AuditRegistry to Casper Testnet
# Prerequisites:
#   1. casper-client installed (cargo install casper-client)
#   2. secret_key.pem in this directory (generate with: casper-client keygen .)
#   3. Account funded with testnet CSPR from https://testnet.cspr.live/tools/faucet

param(
    [string]$NodeUrl = "https://rpc.testnet.casperlabs.io/rpc",
    [string]$ChainName = "casper-test",
    [string]$SecretKey = "./keys/secret_key.pem",
    [int]$Payment = 100000000000  # 100 CSPR in motes
)

$WasmPath = "wasm/AuditRegistry.wasm"

if (-not (Test-Path $WasmPath)) {
    Write-Error "WASM file not found at $WasmPath. Run 'cargo odra build' first."
    exit 1
}

if (-not (Test-Path $SecretKey)) {
    Write-Host "🔑 Secret key not found. Generating new keypair..."
    New-Item -ItemType Directory -Path "./keys" -Force | Out-Null
    casper-client keygen ./keys
    Write-Host "✅ Keys generated in ./keys/"
    Write-Host ""
    Write-Host "⚠️  IMPORTANT: Fund your account before deploying!"
    Write-Host "   1. Get your account hash: casper-client account-address --public-key ./keys/public_key.pem"
    Write-Host "   2. Go to https://testnet.cspr.live/tools/faucet"
    Write-Host "   3. Paste your public key and request tokens"
    Write-Host "   4. Wait ~2 minutes for the faucet tx to confirm"
    Write-Host "   5. Re-run this script"
    exit 0
}

Write-Host "🔥 Deploying AuditRegistry to Casper Testnet..."
Write-Host "   Node: $NodeUrl"
Write-Host "   Chain: $ChainName"
Write-Host "   WASM: $WasmPath"
Write-Host ""

$result = casper-client put-deploy `
    --node-address $NodeUrl `
    --chain-name $ChainName `
    --secret-key $SecretKey `
    --payment-amount $Payment `
    --session-path $WasmPath

Write-Host $result
Write-Host ""
Write-Host "✅ Deploy submitted! Use the deploy hash above to track at:"
Write-Host "   https://testnet.cspr.live/deploy/<DEPLOY_HASH>"
