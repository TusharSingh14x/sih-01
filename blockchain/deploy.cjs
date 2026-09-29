const fs = require('node:fs');
const path = require('node:path');
const solc = require('solc');
const { ethers } = require('ethers');
async function main() {
  const source = fs.readFileSync(path.join(__dirname, 'EvidenceRegistry.sol'), 'utf8');
  const result = JSON.parse(solc.compile(JSON.stringify({language:'Solidity', sources:{'EvidenceRegistry.sol':{content:source}}, settings:{outputSelection:{'*':{'*':['abi','evm.bytecode']}}}})));
  const errors = (result.errors || []).filter(e => e.severity === 'error');
  if (errors.length) throw new Error(errors.map(e => e.formattedMessage).join('\n'));
  const artifact = result.contracts['EvidenceRegistry.sol'].EvidenceRegistry;
  const provider = new ethers.JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL || 'http://127.0.0.1:8545');
  const expectedChainId = process.env.BLOCKCHAIN_CHAIN_ID;
  const network = await provider.getNetwork();
  if (expectedChainId && network.chainId !== BigInt(expectedChainId)) {
    throw new Error(`RPC chain ID ${network.chainId} does not match BLOCKCHAIN_CHAIN_ID ${expectedChainId}`);
  }
  const signer = process.env.BLOCKCHAIN_PRIVATE_KEY
    ? new ethers.Wallet(process.env.BLOCKCHAIN_PRIVATE_KEY, provider)
    : await provider.getSigner(0);
  const contract = await new ethers.ContractFactory(artifact.abi, artifact.evm.bytecode.object, signer).deploy();
  await contract.waitForDeployment();
  fs.writeFileSync(path.join(__dirname, 'deployment.json'), JSON.stringify({abi:artifact.abi,address:await contract.getAddress(),account:await signer.getAddress(),chainId:String((await provider.getNetwork()).chainId)}, null, 2));
  console.log(`BLOCKCHAIN_CONTRACT_ADDRESS=${await contract.getAddress()}\nBLOCKCHAIN_ACCOUNT=${await signer.getAddress()}\nBLOCKCHAIN_CHAIN_ID=${network.chainId}`);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
