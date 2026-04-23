const { ethers } = require("ethers");

// Configuration
const SEQUENCER_ADDRESS = "0x0000000000000000000000000000000000000002";
const MIN_SEQUENCER_BALANCE = ethers.parseEther("100");  // Refill when below 100 AUDT
const REFILL_AMOUNT = ethers.parseEther("1000");         // Send 1000 AUDT each time
const CHECK_INTERVAL_MS = 60000; // Check every minute

// Load validator key securely from Besu data dir
const fs = require("fs");
const VALIDATOR_KEY = fs.readFileSync("/root/auditchain-v2/node1/key", "utf8").trim();

const provider = new ethers.JsonRpcProvider("http://[::1]:8545");
const validatorWallet = new ethers.Wallet(VALIDATOR_KEY, provider);

console.log("=== AuditChain Auto-Funder ===");
console.log("Validator:", validatorWallet.address);
console.log("Sequencer:", SEQUENCER_ADDRESS);
console.log("Min Balance:", ethers.formatEther(MIN_SEQUENCER_BALANCE), "AUDT");
console.log("Refill Amount:", ethers.formatEther(REFILL_AMOUNT), "AUDT");
console.log("");

async function checkAndFund() {
    try {
        const sequencerBalance = await provider.getBalance(SEQUENCER_ADDRESS);
        const validatorBalance = await provider.getBalance(validatorWallet.address);
        
        console.log(`[${new Date().toISOString()}] Sequencer: ${ethers.formatEther(sequencerBalance)} AUDT, Validator: ${ethers.formatEther(validatorBalance)} AUDT`);
        
        if (sequencerBalance < MIN_SEQUENCER_BALANCE) {
            if (validatorBalance < REFILL_AMOUNT) {
                console.log("  WARNING: Validator balance too low to refill!");
                return;
            }
            
            console.log("  -> Sequencer low, sending", ethers.formatEther(REFILL_AMOUNT), "AUDT...");
            
            const tx = await validatorWallet.sendTransaction({
                to: SEQUENCER_ADDRESS,
                value: REFILL_AMOUNT
            });
            
            console.log("  -> TX sent:", tx.hash);
            await tx.wait();
            console.log("  -> Confirmed!");
        }
    } catch (error) {
        console.error("  ERROR:", error.message);
    }
}

// Initial check
checkAndFund();

// Periodic checks
setInterval(checkAndFund, CHECK_INTERVAL_MS);
