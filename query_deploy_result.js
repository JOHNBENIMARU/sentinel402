const { CasperClient } = require('casper-js-sdk');

const RPC_API = 'http://65.109.89.88:7777/rpc';
const casperClient = new CasperClient(RPC_API);
const deployHash = '7308299283ac0ec65dd5f46ad174e3cea37ad3552527e6c0226bd1441a8a0774';

async function checkDeploy() {
  console.log(`⏳ Checking status of deploy ${deployHash}...`);
  let attempts = 0;
  while (attempts < 30) {
    try {
      const [deploy, result] = await casperClient.getDeploy(deployHash);
      if (result && result.execution_results && result.execution_results.length > 0) {
        const execResult = result.execution_results[0].result;
        console.log("=========================================");
        console.log("✅ Execution completed!");
        console.log(JSON.stringify(execResult, null, 2));
        console.log("=========================================");
        
        // Let's get the account's named keys to see if the contract hash is there
        const accountHex = deploy.header.account.toHex();
        console.log(`🔍 Fetching named keys for account: ${accountHex}...`);
        const stateRootHash = await casperClient.nodeClient.getStateRootHash();
        const accountInfo = await casperClient.nodeClient.getBlockState(stateRootHash, `account-hash-${deploy.header.account.toAccountHashStr().substring(13)}`, []);
        console.log("Account Named Keys:");
        console.log(JSON.stringify(accountInfo.Account.namedKeys, null, 2));
        
        break;
      }
    } catch (e) {
      // It might not be in the block yet
    }
    attempts++;
    console.log(`...waiting (attempt ${attempts}/30)`);
    await new Promise(r => setTimeout(r, 10000));
  }
}

checkDeploy().catch(console.error);
