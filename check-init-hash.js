const ethers = require('ethers');
const provider = new ethers.JsonRpcProvider('http://localhost:8545');

const FACTORY_ABI = ['function INIT_CODE_PAIR_HASH() view returns (bytes32)'];
const factory = new ethers.Contract('0x0000000000000000000000000000000000000004', FACTORY_ABI, provider);

async function main() {
  const hash = await factory.INIT_CODE_PAIR_HASH();
  console.log('V2 Factory INIT_CODE_PAIR_HASH:', hash);
}
main().catch(console.error);
