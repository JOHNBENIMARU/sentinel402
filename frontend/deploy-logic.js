import { CasperClient, CLPublicKey, DeployUtil, RuntimeArgs } from 'casper-js-sdk';

export async function runDeploy(publicKeyHex) {
    // 1. Download WASM
    const response = await fetch('/AuditRegistry.wasm');
    const arrayBuffer = await response.arrayBuffer();
    const wasmBytes = new Uint8Array(arrayBuffer);

    // 2. Prepare Deploy
    const senderPublicKey = CLPublicKey.fromHex(publicKeyHex);
    const deployParams = new DeployUtil.DeployParams(
        senderPublicKey,
        'casper-test',
        1,
        1800000
    );
    
    const session = DeployUtil.ExecutableDeployItem.newModuleBytes(
        wasmBytes, 
        RuntimeArgs.fromMap({})
    );
    
    const payment = DeployUtil.standardPayment(150_000_000_000); // 150 CSPR
    
    const deploy = DeployUtil.makeDeploy(deployParams, session, payment);
    const deployJson = DeployUtil.deployToJson(deploy);

    // 3. Get provider
    let provider = window.CasperWalletProvider ? window.CasperWalletProvider() : window.casperlabsHelper;
    if (!provider) throw new Error("Wallet not found");

    // 4. Sign
    let signedDeployJson;
    const deployJsonString = JSON.stringify(deployJson);
    console.log("Sending to wallet for signature...");
    
    try {
        if (provider.signMessage) {
            signedDeployJson = await provider.sign(deployJsonString, publicKeyHex);
        } else {
            signedDeployJson = await provider.sign(deployJsonString, publicKeyHex, publicKeyHex);
        }
    } catch(err) {
        throw new Error("Wallet signing failed or was cancelled: " + err.message);
    }
    
    let toParse = signedDeployJson;
    if (typeof toParse === 'string') {
        try {
            toParse = JSON.parse(toParse);
        } catch (e) {
            console.error("Failed to parse signedDeployJson string:", e);
        }
    }
    
    if (toParse && !toParse.deploy) {
        toParse = { deploy: toParse };
    }
    
    // 5. Send
    let signedDeploy;
    try {
        signedDeploy = DeployUtil.deployFromJson(toParse).unwrap();
    } catch(e) {
        console.error("Failed to restore deploy from JSON:", e);
        throw e;
    }
    
    const casperClient = new CasperClient("http://rpc.testnet.casperlabs.io:7777/rpc");
    return await casperClient.putDeploy(signedDeploy);
}

// Attach to window so HTML can use it
window.runDeploy = runDeploy;
