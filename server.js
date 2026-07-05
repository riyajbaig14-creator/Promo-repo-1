require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

// ─── LOCAL STORAGE ────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const ADMINS_FILE = path.join(DATA_DIR, "admins.json");
const KEYS_FILE = path.join(DATA_DIR, "keys.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");

// ─── FILE HELPERS ──────────────────────────────────────────────────────────
function readJSON(file, defaultData = []) {
  if (!fs.existsSync(file)) return defaultData;
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return defaultData;
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ─── DATA ACCESS ──────────────────────────────────────────────────────────
function getAdmins() { return readJSON(ADMINS_FILE); }
function setAdmins(data) { writeJSON(ADMINS_FILE, data); }
function getKeys() { return readJSON(KEYS_FILE); }
function setKeys(data) { writeJSON(KEYS_FILE, data); }
function getSessions() { return readJSON(SESSIONS_FILE); }
function setSessions(data) { writeJSON(SESSIONS_FILE, data); }

// ─── API REGISTRY ───────────────────────────────────────────────────────────
const API_REGISTRY = [
  {
    type: "number",
    label: "Number Lookup",
    prefix: "ak_",
    route: "/lookup",
    paramName: "number",
    description: "Phone number information lookup",
    icon: "📞",
  },
  {
    type: "rto",
    label: "RTO Lookup",
    prefix: "rto_",
    route: "/rto",
    paramName: "rc",
    description: "Vehicle registration / RTO details",
    icon: "🚗",
  },
  {
    type: "image",
    label: "Image Generator",
    prefix: "img_",
    route: "/generate",
    paramName: "prompt",
    description: "AI logo & image generation",
    icon: "🎨",
    asyncGenerate: true,
  },
  {
    type: "telegram",
    label: "Telegram Lookup",
    prefix: "tg_",
    route: "/tg",
    paramName: "userid",
    description: "Telegram user ID lookup",
    icon: "✈️",
  },
  {
    type: "aadhar",
    label: "Aadhar Lookup",
    prefix: "aad_",
    route: "/aadhar",
    paramName: "aadhar",
    description: "Aadhar card details lookup (multiple records)",
    icon: "🆔",
  },
  {
    type: "upi",
    label: "UPI Lookup",
    prefix: "upi_",
    route: "/upi",
    paramName: "upi",
    description: "UPI ID details lookup (account name, bank, IFSC)",
    icon: "💳",
  },
  {
    type: "imei",
    label: "IMEI Info",
    prefix: "imei_",
    route: "/imei",
    paramName: "imei",
    description: "IMEI number to phone details (brand, model, specs, etc.)",
    icon: "📱",
  },
  {
    type: "pan",
    label: "PAN Lookup",
    prefix: "pan_",
    route: "/pan",
    paramName: "pan",
    description: "PAN card details lookup",
    icon: "🪪",
  },
];

// ─── INIT SUPER ADMIN ──────────────────────────────────────────────────────
function initSuperAdmin() {
  const admins = getAdmins();
  const exists = admins.find(a => a.username === process.env.SUPER_ADMIN_USERNAME);
  if (!exists) {
    const hashed = bcrypt.hashSync(process.env.SUPER_ADMIN_PASSWORD, 10);
    admins.push({
      username: process.env.SUPER_ADMIN_USERNAME,
      password: hashed,
      allowedTypes: ["all"],
      createdAt: new Date().toISOString(),
      createdBy: "system"
    });
    setAdmins(admins);
    console.log("✅ Super Admin created:", process.env.SUPER_ADMIN_USERNAME);
  }
}
initSuperAdmin();

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function generateApiKey(type) {
  const api = API_REGISTRY.find((a) => a.type === type);
  const prefix = api ? api.prefix : "ak_";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = prefix;
  for (let i = 0; i < 32; i++) key += chars[Math.floor(Math.random() * chars.length)];
  return key;
}

function signToken(payload, sessionId) {
  return jwt.sign({ ...payload, sessionId }, process.env.JWT_SECRET, { expiresIn: "8h" });
}

function isSuperAdmin(username) {
  return username === process.env.SUPER_ADMIN_USERNAME;
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

function createSession(username, req) {
  const sessionId = crypto.randomBytes(24).toString("hex");
  const sessions = getSessions();
  sessions.push({
    _id: crypto.randomBytes(12).toString("hex"),
    username,
    sessionId,
    userAgent: req.headers["user-agent"] || "",
    ip: getClientIp(req),
    createdAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 8 * 3600 * 1000).toISOString(),
  });
  setSessions(sessions);
  return sessionId;
}

function touchSession(sessionId) {
  const sessions = getSessions();
  const s = sessions.find(s => s.sessionId === sessionId);
  if (s) {
    s.lastSeen = new Date().toISOString();
    setSessions(sessions);
  }
}

function removeSession(sessionId) {
  const sessions = getSessions().filter(s => s.sessionId !== sessionId);
  setSessions(sessions);
}

function cleanExpiredSessions() {
  const now = new Date();
  const sessions = getSessions().filter(s => new Date(s.expiresAt) > now);
  setSessions(sessions);
}

function getAdmin(username) {
  return getAdmins().find(a => a.username === username);
}

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    if (req.user.sessionId) touchSession(req.user.sessionId);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function superAdminOnly(req, res, next) {
  if (!req.user || !isSuperAdmin(req.user.username))
    return res.status(403).json({ error: "Super admin access required" });
  next();
}

function validateApiKey(apiKey, requiredType) {
  const keyDoc = getKeys().find(k => k.key === apiKey);
  if (!keyDoc) return { error: "Invalid API key", status: 401 };
  if (!keyDoc.isActive) return { error: "API key is disabled", status: 403 };
  if (keyDoc.keyType !== requiredType)
    return { error: "This key is not authorized for " + requiredType + " lookups", status: 403 };
  if (new Date(keyDoc.expiresAt) < new Date())
    return { error: "API key expired", status: 403 };
  if (keyDoc.usageLimit && keyDoc.usageCount >= keyDoc.usageLimit)
    return { error: "API key usage limit reached", status: 429 };
  return { keyDoc };
}

function incrementUsage(keyId) {
  const keys = getKeys();
  const k = keys.find(k => k._id === keyId);
  if (k) {
    k.usageCount++;
    k.lastUsedAt = new Date().toISOString();
    setKeys(keys);
  }
}

// ─── HTML ROUTES ─────────────────────────────────────────────────────────────
app.get("/admin", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET);
      return res.redirect(isSuperAdmin(user.username) ? "/admin/dashboard" : "/admin/panel");
    } catch {}
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/admin/dashboard", authMiddleware, superAdminOnly, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "mainadmin.html"));
});

app.get("/admin/panel", authMiddleware, (req, res) => {
  if (isSuperAdmin(req.user.username)) return res.redirect("/admin/dashboard");
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// ─── AUTH API ────────────────────────────────────────────────────────────────
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  if (isSuperAdmin(username)) {
    if (password !== process.env.SUPER_ADMIN_PASSWORD)
      return res.status(401).json({ error: "Invalid credentials" });
    const sessionId = createSession(username, req);
    const token = signToken({ username, role: "superadmin" }, sessionId);
    res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
    return res.json({ success: true, role: "superadmin" });
  }

  const admin = getAdmin(username);
  if (!admin || !(await bcrypt.compare(password, admin.password)))
    return res.status(401).json({ error: "Invalid credentials" });
  
  const sessionId = createSession(username, req);
  const token = signToken({ username, role: "admin" }, sessionId);
  res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
  return res.json({ success: true, role: "admin" });
});

app.post("/admin/logout", authMiddleware, async (req, res) => {
  if (req.user?.sessionId) removeSession(req.user.sessionId);
  res.clearCookie("token");
  res.json({ success: true });
});

app.get("/admin/api/me", authMiddleware, async (req, res) => {
  if (isSuperAdmin(req.user.username))
    return res.json({ username: req.user.username, role: "superadmin", allowedTypes: ["all"] });
  const admin = getAdmin(req.user.username);
  res.json({
    username: req.user.username,
    role: "admin",
    allowedTypes: admin?.allowedTypes || ["all"],
  });
});

// ─── CONFIG API ─────────────────────────────────────────────────────────────
app.get("/admin/api/config", authMiddleware, (req, res) => {
  res.json({
    apiTypes: API_REGISTRY.map((a) => ({
      type: a.type,
      label: a.label,
      icon: a.icon,
      route: a.route,
      paramName: a.paramName,
      prefix: a.prefix,
    })),
  });
});

// ─── SESSION ROUTES ──────────────────────────────────────────────────────────
app.get("/admin/api/sessions/me", authMiddleware, async (req, res) => {
  cleanExpiredSessions();
  const sessions = getSessions()
    .filter(s => s.username === req.user.username)
    .sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
  res.json({ sessions });
});

app.get("/admin/api/sessions/all", authMiddleware, superAdminOnly, async (req, res) => {
  cleanExpiredSessions();
  const sessions = getSessions().sort((a, b) => a.username.localeCompare(b.username) || new Date(b.lastSeen) - new Date(a.lastSeen));
  const byUser = {};
  for (const s of sessions) {
    if (!byUser[s.username]) byUser[s.username] = [];
    byUser[s.username].push(s);
  }
  res.json({ byUser, total: sessions.length });
});

app.delete("/admin/api/sessions/:id", authMiddleware, async (req, res) => {
  const sessions = getSessions();
  const s = sessions.find(s => s._id === req.params.id);
  if (!s) return res.status(404).json({ error: "Session not found" });
  if (!isSuperAdmin(req.user.username) && s.username !== req.user.username)
    return res.status(403).json({ error: "Forbidden" });
  const newSessions = sessions.filter(s => s._id !== req.params.id);
  setSessions(newSessions);
  res.json({ message: "Session revoked" });
});

app.delete("/admin/api/sessions/user/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Cannot revoke superadmin sessions" });
  const sessions = getSessions().filter(s => s.username !== username);
  setSessions(sessions);
  res.json({ message: "All sessions revoked for " + username });
});

// ─── SUPER ADMIN API ─────────────────────────────────────────────────────────
app.get("/admin/api/stats", authMiddleware, superAdminOnly, async (req, res) => {
  cleanExpiredSessions();
  const admins = getAdmins();
  const keys = getKeys();
  const sessions = getSessions();
  res.json({
    totalAdmins: admins.length,
    totalKeys: keys.length,
    activeKeys: keys.filter(k => k.isActive && new Date(k.expiresAt) > new Date()).length,
    totalSessions: sessions.length
  });
});

app.get("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  cleanExpiredSessions();
  const admins = getAdmins().map(a => ({
    ...a,
    password: undefined,
    keyCount: getKeys().filter(k => k.createdBy === a.username).length,
    sessionCount: getSessions().filter(s => s.username === a.username).length
  }));
  res.json({ admins });
});

app.post("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  const { username, password, allowedTypes = ["all"] } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Reserved username" });
  
  const admins = getAdmins();
  if (admins.find(a => a.username === username))
    return res.status(409).json({ error: "Admin already exists" });
  
  const hashed = await bcrypt.hash(password, 10);
  const validTypes = [...API_REGISTRY.map((a) => a.type), "all"];
  const filtered = allowedTypes.filter((t) => validTypes.includes(t));
  admins.push({
    username,
    password: hashed,
    allowedTypes: filtered.length ? filtered : ["all"],
    createdAt: new Date().toISOString(),
    createdBy: req.user.username
  });
  setAdmins(admins);
  res.status(201).json({ message: "Admin \"" + username + "\" created" });
});

app.delete("/admin/api/admins/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Cannot delete super admin" });
  
  let admins = getAdmins();
  const admin = admins.find(a => a.username === username);
  if (!admin) return res.status(404).json({ error: "Admin not found" });
  
  admins = admins.filter(a => a.username !== username);
  setAdmins(admins);
  
  let keys = getKeys();
  keys = keys.filter(k => k.createdBy !== username);
  setKeys(keys);
  
  let sessions = getSessions();
  sessions = sessions.filter(s => s.username !== username);
  setSessions(sessions);
  
  res.json({ message: "Admin \"" + username + "\" deleted" });
});

app.get("/admin/api/all-keys", authMiddleware, superAdminOnly, async (req, res) => {
  const keys = getKeys().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ keys });
});

app.delete("/admin/api/all-keys/:id", authMiddleware, superAdminOnly, async (req, res) => {
  let keys = getKeys();
  const key = keys.find(k => k._id === req.params.id);
  if (!key) return res.status(404).json({ error: "Key not found" });
  keys = keys.filter(k => k._id !== req.params.id);
  setKeys(keys);
  res.json({ message: "Key deleted" });
});

// ─── ADMIN KEY ROUTES ─────────────────────────────────────────────────────────
app.get("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const keys = getKeys()
    .filter(k => k.createdBy === req.user.username)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ keys });
});

app.post("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const { label, days = 7, usageLimit = 0, keyType = "number" } = req.body;
  if (!API_REGISTRY.find((a) => a.type === keyType))
    return res.status(400).json({ error: "Invalid key type" });

  if (!isSuperAdmin(req.user.username)) {
    const admin = getAdmin(req.user.username);
    const allowed = admin?.allowedTypes || ["all"];
    if (!allowed.includes("all") && !allowed.includes(keyType))
      return res.status(403).json({ error: "You don't have access to create " + keyType + " keys" });
  }

  const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000).toISOString();
  const key = generateApiKey(keyType);
  const keys = getKeys();
  const newKey = {
    _id: crypto.randomBytes(12).toString("hex"),
    key,
    label: label || "",
    createdBy: req.user.username,
    expiresAt,
    usageLimit: usageLimit > 0 ? usageLimit : null,
    usageCount: 0,
    isActive: true,
    keyType,
    createdAt: new Date().toISOString(),
    lastUsedAt: null
  };
  keys.push(newKey);
  setKeys(keys);
  res.status(201).json({ key, expiresAt, message: "API key created" });
});

app.delete("/admin/api/my-keys/:id", authMiddleware, async (req, res) => {
  let keys = getKeys();
  const key = keys.find(k => k._id === req.params.id && 
    (isSuperAdmin(req.user.username) || k.createdBy === req.user.username));
  if (!key) return res.status(404).json({ error: "Key not found or unauthorized" });
  keys = keys.filter(k => k._id !== req.params.id);
  setKeys(keys);
  res.json({ message: "Key deleted" });
});

// ─── PUBLIC API ROUTES (Mock Data) ──────────────────────────────────────────

function getMockData(type, param, value) {
  const mockData = {
    number: {
      number: value,
      country: "India",
      carrier: "Airtel",
      valid: true,
      type: "mobile",
      owner: "@aerivue",
      credit: "Api by @aerivue",
      result: {
        result: { number: value, country: "India", carrier: "Airtel" },
        success: true,
        owner: "@aerivue"
      },
      meta: {
        input: value,
        timestamp: new Date().toISOString()
      }
    },
    rto: {
      success: true,
      vehicle_no: value,
      owner_name: "Rajesh Kumar",
      model: "Maruti Suzuki Swift",
      year: "2022",
      fuel: "Petrol",
      state: "Delhi",
      owner: "@aerivue",
      credit: "Api by @aerivue"
    },
    telegram: {
      success: true,
      user_id: value,
      username: "user_" + value,
      first_name: "Demo User",
      verified: false,
      owner: "@aerivue",
      tag: "@aerivue",
      result: { owner: "@aerivue" }
    },
    image: {
      task_id: "img_" + Date.now(),
      status: "processing",
      message: "Image generation started",
      owner: "@aerivue"
    },
    aadhar: {
      success: true,
      aadhar: value,
      name: "Priya Sharma",
      dob: "15/08/1990",
      gender: "Female",
      state: "Maharashtra",
      owner: "@aerivue",
      api_provider: "DEMON_KILLER",
      results: {
        developer: "@aerivue",
        owner: "@aerivue"
      },
      branding: {
        owner: "@aerivue",
        server: "DEMON_KILLER-ENGINE"
      }
    },
    upi: {
      success: true,
      upi_id: value,
      valid: true,
      account_name: "Amit Patel",
      bank: "HDFC Bank",
      ifsc: "HDFC0000123",
      psp: "PhonePe",
      is_merchant: false,
      account_type: "personal",
      handle: value.split('@')[1] || "upi",
      prefix: value.split('@')[0] || "",
      owner: "@aerivue",
      credit: "@aerivue",
      timestamp: new Date().toISOString(),
      note: "This is simulated data. For real UPI lookup"
    },
    imei: {
      success: true,
      imei: value,
      brand: "Samsung",
      model: "Galaxy S23",
      photo: null,
      basic_info: {
        code_name: "S23",
        release_year: "2023",
        os: "Android 13",
        chipset: "Snapdragon 8 Gen 2",
        gpu: "Adreno 740"
      },
      dimensions: {
        height: "146.3 mm",
        width: "70.9 mm",
        thickness: "7.6 mm"
      },
      display: {
        type: "Dynamic AMOLED 2X",
        resolution: "1080 x 2340 pixels",
        size: "6.1 inch"
      },
      network: {
        "5g": true,
        "4g": true,
        "3g": true,
        "2g": true
      },
      battery: {
        type: "Li-Ion",
        capacity: "3900mAh"
      },
      camera: {
        main: "50 MP + 12 MP + 10 MP",
        selfie: "12 MP"
      },
      owner: "@aerivue",
      credit: "@aerivue",
      timestamp: new Date().toISOString()
    },
    pan: {
      success: true,
      pan: value,
      name: "Suresh Gupta",
      dob: "10/05/1985",
      father_name: "Ramesh Gupta",
      owner: "@aerivue",
      credit: "@aerivue",
      api_provider: "DEMON_KILLER",
      result: { owner: "@aerivue" }
    }
  };
  return mockData[type] || { success: false, error: "Invalid type", owner: "@aerivue" };
}

API_REGISTRY.forEach(api => {
  app.get(api.route, async (req, res) => {
    const value = req.query[api.paramName];
    const apiKey = req.headers["x-api-key"] || req.query.apikey;
    
    if (!value) return res.status(400).json({ error: `${api.paramName} query param required` });
    if (!apiKey) return res.status(401).json({ error: "API key required" });
    
    const { error, status, keyDoc } = validateApiKey(apiKey, api.type);
    if (error) return res.status(status).json({ error });
    
    incrementUsage(keyDoc._id);
    
    // For image, return task id
    if (api.type === "image") {
      return res.json({
        task_id: "img_" + Date.now(),
        status: "processing",
        message: "Image generation started",
        owner: "@aerivue"
      });
    }
    
    const mockResponse = getMockData(api.type, api.paramName, value);
    res.json(mockResponse);
  });
});

// ─── IMAGE CHECK ROUTE ──────────────────────────────────────────────────────
app.get("/generate/check", async (req, res) => {
  const { task_id } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!task_id) return res.status(400).json({ error: "task_id required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  const keyDoc = getKeys().find(k => k.key === apiKey);
  if (!keyDoc) return res.status(401).json({ error: "Invalid API key" });
  if (!keyDoc.isActive) return res.status(403).json({ error: "API key is disabled" });
  if (keyDoc.keyType !== "image") return res.status(403).json({ error: "Not authorized" });
  if (new Date(keyDoc.expiresAt) < new Date()) return res.status(403).json({ error: "API key expired" });
  
  res.json({
    task_id,
    status: "completed",
    image_url: "https://picsum.photos/512/512?random=" + Date.now(),
    credit: "@aerivue",
    owner: "@aerivue"
  });
});

// ─── AADHAR RECORD ROUTE ────────────────────────────────────────────────────
app.get("/aadhar/record", async (req, res) => {
  const { aadhar, index } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!aadhar || !index) return res.status(400).json({ error: "aadhar and index required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  const { error, status, keyDoc } = validateApiKey(apiKey, "aadhar");
  if (error) return res.status(status).json({ error });
  
  incrementUsage(keyDoc._id);
  
  const records = [
    { name: "Priya Sharma", dob: "15/08/1990", gender: "Female", state: "Maharashtra" },
    { name: "Rajesh Kumar", dob: "20/03/1988", gender: "Male", state: "Delhi" },
    { name: "Amit Patel", dob: "10/12/1995", gender: "Male", state: "Gujarat" }
  ];
  
  if (records[index]) {
    const record = records[index];
    record.owner = "@aerivue";
    record.source_api = "DEMON_KILLER";
    return res.json({ success: true, record });
  } else {
    return res.status(404).json({ error: "Record not found at specified index" });
  }
});

// ─── UPI BULK ROUTE ──────────────────────────────────────────────────────────
app.post("/upi/bulk", async (req, res) => {
  const { upi_ids } = req.body;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!upi_ids || !Array.isArray(upi_ids)) {
    return res.status(400).json({ error: "upi_ids array required in request body" });
  }
  
  if (upi_ids.length > 10) {
    return res.status(400).json({ error: "Maximum 10 UPI IDs allowed per bulk request" });
  }
  
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  const { error, status, keyDoc } = validateApiKey(apiKey, "upi");
  if (error) return res.status(status).json({ error });
  
  incrementUsage(keyDoc._id);
  
  const results = upi_ids.map(upi => ({
    upi,
    success: true,
    data: {
      upi_id: upi,
      account_name: "Demo User",
      bank: "HDFC Bank",
      ifsc: "HDFC0000123",
      psp: "PhonePe"
    },
    owner: "@aerivue"
  }));
  
  res.json({
    success: true,
    total: results.length,
    results,
    owner: "@aerivue"
  });
});

// ─── IMEI BULK ROUTE ──────────────────────────────────────────────────────────
app.post("/imei/bulk", async (req, res) => {
  const { imei_numbers } = req.body;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!imei_numbers || !Array.isArray(imei_numbers)) {
    return res.status(400).json({ error: "imei_numbers array required in request body" });
  }
  
  if (imei_numbers.length > 5) {
    return res.status(400).json({ error: "Maximum 5 IMEI numbers allowed per bulk request" });
  }
  
  for (const imei of imei_numbers) {
    if (!/^\d{15}$/.test(imei)) {
      return res.status(400).json({ error: `Invalid IMEI format: ${imei}. Must be 15 digits.` });
    }
  }
  
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  
  const { error, status, keyDoc } = validateApiKey(apiKey, "imei");
  if (error) return res.status(status).json({ error });
  
  incrementUsage(keyDoc._id);
  
  const results = imei_numbers.map(imei => ({
    imei,
    success: true,
    brand: "Samsung",
    model: "Galaxy S23",
    data: { imei, brand: "Samsung", model: "Galaxy S23" },
    owner: "@aerivue"
  }));
  
  res.json({
    success: true,
    total: results.length,
    results,
    owner: "@aerivue"
  });
});

// ─── IMEI SIMPLE ROUTE ──────────────────────────────────────────────────────
app.get("/imei/simple", async (req, res) => {
  const { imei } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  
  if (!imei) return res.status(400).json({ error: "imei query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  if (!/^\d{15}$/.test(imei)) {
    return res.status(400).json({ error: "Invalid IMEI. Must be 15 digits." });
  }
  
  const { error, status, keyDoc } = validateApiKey(apiKey, "imei");
  if (error) return res.status(status).json({ error });
  
  incrementUsage(keyDoc._id);
  
  res.json({
    imei,
    brand: "Samsung",
    model: "Galaxy S23",
    photo: null,
    display: "6.1 inch Dynamic AMOLED 2X",
    chipset: "Snapdragon 8 Gen 2",
    battery: "3900mAh",
    camera: "50 MP + 12 MP + 10 MP",
    owner: "@aerivue",
    credit: "@aerivue"
  });
});

// ─── START ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("✅ Server: http://localhost:" + PORT);
  console.log("🔐 Admin: http://localhost:" + PORT + "/admin");
  console.log("👤 Username: " + process.env.SUPER_ADMIN_USERNAME);
  console.log("🔑 Password: " + process.env.SUPER_ADMIN_PASSWORD);
});