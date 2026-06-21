const fs = require('fs');
const {
  CasperClient,
  Contracts,
  Keys,
  RuntimeArgs,
  DeployUtil,
  CLValueBuilder
} = require('casper-js-sdk');

const RPC_API = 'http://65.109.89.88:7777/rpc';
const casperClient = new CasperClient(RPC_API);
const contractClient = new Contracts.Contract(casperClient);

async function deploy() {
  try {
    console.log("🔥 Starting Casper deployment...");
    
    // 1. Read Secret Key from secret_key.pem
    const keyPath = './contracts/audit-registry/keys/secret_key.pem';
    if (!fs.existsSync(keyPath)) {
      console.error("❌ ERROR: secret_key.pem not found in the sentinel402 directory!");
      console.log("👉 How to fix: Open Casper Wallet -> Account -> Export Private Key -> Save as 'secret_key.pem' in D:\\sentinel402\\");
      return;
    }
    
    console.log("🔑 Reading private key...");
    const keyPair = Keys.Ed25519.loadKeyPairFromPrivateFile(keyPath);
    console.log("💳 Deploying from public key:", keyPair.publicKey.toHex());

    // 2. Read WASM
    const wasmPath = './contracts/audit-registry/wasm/AuditRegistry.wasm';
    if (!fs.existsSync(wasmPath)) {
      console.error("❌ ERROR: WASM file not found at " + wasmPath);
      return;
    }
    const wasm = new Uint8Array(fs.readFileSync(wasmPath));

    // 3. Create Deploy
    console.log("📦 Creating deploy transaction...");
    const runtimeArgs = RuntimeArgs.fromMap({
      "odra_cfg_package_hash_key_name": CLValueBuilder.string("audit_registry_package"),
      "odra_cfg_allow_key_override": CLValueBuilder.bool(true),
      "odra_cfg_is_upgradable": CLValueBuilder.bool(true),
      "odra_cfg_constructor": CLValueBuilder.string("init")
    });

    const deploy = DeployUtil.makeDeploy(
      new DeployUtil.DeployParams(
        keyPair.publicKey,
        'casper-test',
        1, // gasPrice
        1800000 // ttl
      ),
      DeployUtil.ExecutableDeployItem.newModuleBytes(wasm, runtimeArgs),
      DeployUtil.standardPayment(150_000_000_000) // 150 CSPR
    );

    // 4. Sign
    console.log("✍️ Signing transaction...");
    const signedDeploy = DeployUtil.signDeploy(deploy, keyPair);

    // 5. Send
    console.log("🚀 Sending to network...");
    const deployHash = await casperClient.putDeploy(signedDeploy);
    
    console.log("=========================================");
    console.log("✅ SUCCESS! Contract deployed.");
    console.log("🔗 Deploy Hash:", deployHash);
    console.log("🔗 View on Explorer: https://testnet.cspr.live/deploy/" + deployHash);
    console.log("=========================================");
    console.log("⏳ It will take 1-2 minutes for the block to be confirmed.");
    
  } catch(e) {
    console.error("❌ DEPLOY ERROR:", e);
  }
}
deploy();
