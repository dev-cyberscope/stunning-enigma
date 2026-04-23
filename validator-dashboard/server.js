const express = require("express");
const axios = require("axios");
const { ethers } = require("ethers");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Configuration
const RPC_URL = "http://localhost:8545";
const CHAIN_ID = 1337;
const CHAIN_NAME = "AuditChain";

// AUDT token on XRPL
const AUDT_TOKEN = {
  currency: "4155445400000000000000000000000000000000",
  issuer: "rEXAMPLEISSUERxxxxxxxxxxxxxxxxxx"
};

// Settings file
const SETTINGS_FILE = path.join(__dirname, "settings.json");
const APPLICATIONS_FILE = path.join(__dirname, "applications.json");

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      return JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
    }
  } catch (e) {}
  return {
    minAuditHolding: 1000000,
    maxValidators: 21,
    adminPasswordHash: null // Will be set on first access
  };
}

function saveSettings(settings) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
}

function loadApplications() {
  try {
    if (fs.existsSync(APPLICATIONS_FILE)) {
      return JSON.parse(fs.readFileSync(APPLICATIONS_FILE, "utf8"));
    }
  } catch (e) {}
  return [];
}

function saveApplications(apps) {
  fs.writeFileSync(APPLICATIONS_FILE, JSON.stringify(apps, null, 2));
}

// Simple password hashing
function hashPassword(password) {
  return crypto.createHash("sha256").update(password + "auditchain-salt").digest("hex");
}

// RPC helper
async function rpcCall(method, params = []) {
  const response = await axios.post(RPC_URL, {
    jsonrpc: "2.0",
    method,
    params,
    id: Date.now()
  });
  if (response.data.error) {
    throw new Error(response.data.error.message || "RPC Error");
  }
  return response.data.result;
}

// Verify AUDT holdings via XRPL
async function verifyAuditHoldings(xrplAddress) {
  try {
    const response = await axios.post("https://xrplcluster.com", {
      method: "account_lines",
      params: [{
        account: xrplAddress,
        peer: AUDT_TOKEN.issuer,
        limit: 400
      }]
    });

    if (response.data.result?.lines) {
      const auditLine = response.data.result.lines.find(
        line => line.currency === AUDT_TOKEN.currency || line.currency === "AUDT"
      );
      if (auditLine) {
        return parseFloat(auditLine.balance);
      }
    }
    return 0;
  } catch (err) {
    console.error("XRPL verification error:", err.message);
    return 0;
  }
}

// Get current validators from chain
async function getCurrentValidators() {
  try {
    return await rpcCall("qbft_getValidatorsByBlockNumber", ["latest"]);
  } catch (err) {
    console.error("Failed to get validators:", err.message);
    return [];
  }
}

// Propose validator vote (add or remove)
async function proposeValidatorVote(validatorAddress, add = true) {
  try {
    const result = await rpcCall("qbft_proposeValidatorVote", [validatorAddress, add]);
    return { success: true, result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// Check if validator is pending in votes
async function getPendingVotes() {
  try {
    return await rpcCall("qbft_getPendingVotes");
  } catch (err) {
    return {};
  }
}

// ==================== PUBLIC ENDPOINTS ====================

// Get chain stats
app.get("/api/stats", async (req, res) => {
  try {
    const settings = loadSettings();
    const [blockNumber, validators, peers, syncing] = await Promise.all([
      rpcCall("eth_blockNumber"),
      getCurrentValidators(),
      rpcCall("net_peerCount"),
      rpcCall("eth_syncing")
    ]);

    const latestBlock = await rpcCall("eth_getBlockByNumber", ["latest", false]);
    
    res.json({
      chainId: CHAIN_ID,
      chainName: CHAIN_NAME,
      blockNumber: parseInt(blockNumber, 16),
      validators: validators || [],
      validatorCount: validators?.length || 0,
      maxValidators: settings.maxValidators,
      peerCount: parseInt(peers, 16),
      syncing: syncing !== false,
      latestBlockTime: latestBlock ? new Date(parseInt(latestBlock.timestamp, 16) * 1000).toISOString() : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get validators
app.get("/api/validators", async (req, res) => {
  try {
    const validators = await getCurrentValidators();
    const settings = loadSettings();
    res.json({ 
      validators: validators || [], 
      count: validators?.length || 0,
      maxValidators: settings.maxValidators
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get requirements
app.get("/api/requirements", (req, res) => {
  const settings = loadSettings();
  res.json({
    minAuditHolding: settings.minAuditHolding,
    maxValidators: settings.maxValidators,
    auditToken: AUDT_TOKEN,
    chainId: CHAIN_ID
  });
});

// Submit validator application
app.post("/api/apply", async (req, res) => {
  try {
    const { xrplAddress, evmAddress, nodeEndpoint, contactInfo } = req.body;
    const settings = loadSettings();

    if (!xrplAddress || !evmAddress) {
      return res.status(400).json({ error: "XRPL and EVM addresses required" });
    }

    // Validate EVM address
    if (!ethers.utils.isAddress(evmAddress)) {
      return res.status(400).json({ error: "Invalid EVM address format" });
    }

    const normalizedEvmAddress = evmAddress.toLowerCase();

    // Check if already a validator
    const currentValidators = await getCurrentValidators();
    if (currentValidators.some(v => v.toLowerCase() === normalizedEvmAddress)) {
      return res.status(400).json({ error: "This address is already an active validator" });
    }

    // Check validator limit
    if (currentValidators.length >= settings.maxValidators) {
      return res.status(400).json({ error: `Maximum validator limit (${settings.maxValidators}) reached` });
    }

    // Verify AUDT holdings
    const auditBalance = await verifyAuditHoldings(xrplAddress);
    
    if (auditBalance < settings.minAuditHolding) {
      return res.status(400).json({ 
        error: `Insufficient AUDT holdings. Required: ${settings.minAuditHolding.toLocaleString()}, You have: ${auditBalance.toLocaleString()}` 
      });
    }

    // Check if already applied
    const applications = loadApplications();
    const existing = applications.find(a => 
      a.evmAddress.toLowerCase() === normalizedEvmAddress && 
      a.status !== "rejected"
    );
    if (existing) {
      return res.status(400).json({ 
        error: `Application already exists (Status: ${existing.status})` 
      });
    }

    // Create application
    const application = {
      id: crypto.randomUUID(),
      xrplAddress,
      evmAddress: normalizedEvmAddress,
      nodeEndpoint: nodeEndpoint || null,
      contactInfo: contactInfo || null,
      auditBalance,
      status: "pending", // pending, approved, active, rejected
      appliedAt: new Date().toISOString(),
      approvedAt: null,
      activatedAt: null,
      rejectedAt: null,
      txHash: null
    };
    
    applications.push(application);
    saveApplications(applications);

    res.json({ 
      success: true, 
      message: "Application submitted! Your AUDT holdings have been verified. Awaiting admin approval.",
      applicationId: application.id,
      auditBalance,
      status: "pending"
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Check application status
app.get("/api/application/:id", (req, res) => {
  const applications = loadApplications();
  const app = applications.find(a => a.id === req.params.id);
  if (!app) {
    return res.status(404).json({ error: "Application not found" });
  }
  res.json({ application: app });
});

// ==================== ADMIN ENDPOINTS ====================

// Admin auth middleware
function adminAuth(req, res, next) {
  const settings = loadSettings();
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Admin authentication required" });
  }
  
  const password = authHeader.slice(7);
  
  // First time setup - set password
  if (!settings.adminPasswordHash) {
    settings.adminPasswordHash = hashPassword(password);
    saveSettings(settings);
    console.log("Admin password set for first time");
    next();
    return;
  }
  
  if (hashPassword(password) !== settings.adminPasswordHash) {
    return res.status(401).json({ error: "Invalid admin password" });
  }
  
  next();
}

// Get all applications (admin)
app.get("/api/admin/applications", adminAuth, (req, res) => {
  const applications = loadApplications();
  const stats = {
    total: applications.length,
    pending: applications.filter(a => a.status === "pending").length,
    approved: applications.filter(a => a.status === "approved").length,
    active: applications.filter(a => a.status === "active").length,
    rejected: applications.filter(a => a.status === "rejected").length
  };
  res.json({ applications, stats });
});

// Approve application (admin)
app.post("/api/admin/approve/:id", adminAuth, async (req, res) => {
  try {
    const settings = loadSettings();
    const applications = loadApplications();
    const appIndex = applications.findIndex(a => a.id === req.params.id);
    
    if (appIndex === -1) {
      return res.status(404).json({ error: "Application not found" });
    }
    
    const application = applications[appIndex];
    
    if (application.status !== "pending") {
      return res.status(400).json({ error: `Cannot approve: current status is ${application.status}` });
    }

    // Check validator limit
    const currentValidators = await getCurrentValidators();
    if (currentValidators.length >= settings.maxValidators) {
      return res.status(400).json({ error: `Maximum validator limit (${settings.maxValidators}) reached` });
    }

    // Re-verify AUDT holdings before approval
    const auditBalance = await verifyAuditHoldings(application.xrplAddress);
    if (auditBalance < settings.minAuditHolding) {
      application.status = "rejected";
      application.rejectedAt = new Date().toISOString();
      application.rejectionReason = "AUDT holdings dropped below minimum";
      saveApplications(applications);
      return res.status(400).json({ 
        error: `Holdings verification failed. Current: ${auditBalance.toLocaleString()}, Required: ${settings.minAuditHolding.toLocaleString()}` 
      });
    }

    // Propose validator vote to add this address
    const voteResult = await proposeValidatorVote(application.evmAddress, true);
    
    if (!voteResult.success) {
      return res.status(500).json({ error: `Failed to propose validator: ${voteResult.error}` });
    }

    // Update application status
    application.status = "approved";
    application.approvedAt = new Date().toISOString();
    application.auditBalance = auditBalance; // Update verified balance
    saveApplications(applications);

    // Check if they became active immediately (single validator = instant)
    setTimeout(async () => {
      const validators = await getCurrentValidators();
      if (validators.some(v => v.toLowerCase() === application.evmAddress.toLowerCase())) {
        const apps = loadApplications();
        const idx = apps.findIndex(a => a.id === application.id);
        if (idx !== -1 && apps[idx].status === "approved") {
          apps[idx].status = "active";
          apps[idx].activatedAt = new Date().toISOString();
          saveApplications(apps);
          console.log(`Validator ${application.evmAddress} is now active`);
        }
      }
    }, 5000);

    res.json({ 
      success: true, 
      message: "Validator approved and vote proposed!",
      application
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Reject application (admin)
app.post("/api/admin/reject/:id", adminAuth, (req, res) => {
  const applications = loadApplications();
  const appIndex = applications.findIndex(a => a.id === req.params.id);
  
  if (appIndex === -1) {
    return res.status(404).json({ error: "Application not found" });
  }
  
  const application = applications[appIndex];
  
  if (application.status === "active") {
    return res.status(400).json({ error: "Cannot reject an active validator. Use remove instead." });
  }

  application.status = "rejected";
  application.rejectedAt = new Date().toISOString();
  application.rejectionReason = req.body.reason || "Rejected by admin";
  saveApplications(applications);

  res.json({ success: true, message: "Application rejected", application });
});

// Remove active validator (admin)
app.post("/api/admin/remove/:id", adminAuth, async (req, res) => {
  try {
    const applications = loadApplications();
    const appIndex = applications.findIndex(a => a.id === req.params.id);
    
    if (appIndex === -1) {
      return res.status(404).json({ error: "Application not found" });
    }
    
    const application = applications[appIndex];
    
    if (application.status !== "active") {
      return res.status(400).json({ error: "Can only remove active validators" });
    }

    // Propose vote to remove validator
    const voteResult = await proposeValidatorVote(application.evmAddress, false);
    
    if (!voteResult.success) {
      return res.status(500).json({ error: `Failed to propose removal: ${voteResult.error}` });
    }

    application.status = "removed";
    application.removedAt = new Date().toISOString();
    saveApplications(applications);

    res.json({ success: true, message: "Validator removal proposed", application });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update settings (admin)
app.post("/api/admin/settings", adminAuth, (req, res) => {
  const settings = loadSettings();
  
  if (req.body.minAuditHolding !== undefined) {
    settings.minAuditHolding = parseInt(req.body.minAuditHolding) || 1000000;
  }
  if (req.body.maxValidators !== undefined) {
    settings.maxValidators = parseInt(req.body.maxValidators) || 21;
  }
  
  saveSettings(settings);
  res.json({ success: true, settings });
});

// Get settings (admin)
app.get("/api/admin/settings", adminAuth, (req, res) => {
  const settings = loadSettings();
  res.json({ 
    minAuditHolding: settings.minAuditHolding,
    maxValidators: settings.maxValidators
  });
});

// Get pending votes from chain (admin)
app.get("/api/admin/pending-votes", adminAuth, async (req, res) => {
  try {
    const votes = await getPendingVotes();
    res.json({ pendingVotes: votes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Serve frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`AuditChain Validator Dashboard running on port ${PORT}`);
});
