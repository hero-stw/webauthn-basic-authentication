const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const {
  getUserByEmail,
  createUser,
  updateUserCounter,
  getUserById,
} = require("./db");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.set("trust proxy", 1);

const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";
const RP_ID = process.env.RP_ID || "localhost";
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: CLIENT_URL, credentials: true }));

function parseJsonOrNull(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch (e) {
    return null;
  }
}

// In-memory, short-lived session stores for stateless (cookie-less) challenge tracking
const regSessions = new Map(); // sessionId -> { userId, email, challenge, expires }
const authSessions = new Map(); // sessionId -> { userId, challenge, expires }

function createSessionId() {
  return crypto.randomBytes(16).toString("hex");
}

function isExpired(expires) {
  return typeof expires === "number" && Date.now() > expires;
}

app.get("/init-register", async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  if (getUserByEmail(email) != null) {
    return res.status(400).json({ error: "User already exists" });
  }

  const options = await generateRegistrationOptions({
    rpID: RP_ID,
    rpName: "Web Dev Simplified",
    userName: email,
  });

  // Track challenge server-side using a short-lived sessionId returned to the client
  const sessionId = createSessionId();
  regSessions.set(sessionId, {
    userId: options.user.id,
    email,
    challenge: options.challenge,
    expires: Date.now() + 60000,
  });

  res.json({ ...options, sessionId });
});

app.post("/verify-register", async (req, res) => {
  const sessionId = req.body.sessionId;
  const regInfo = sessionId ? regSessions.get(sessionId) : null;

  if (!regInfo || isExpired(regInfo.expires)) {
    if (sessionId) regSessions.delete(sessionId);
    return res.status(400).json({ error: "Registration info not found" });
  }

  const verification = await verifyRegistrationResponse({
    response: req.body,
    expectedChallenge: regInfo.challenge,
    expectedOrigin: CLIENT_URL,
    expectedRPID: RP_ID,
  });

  if (verification.verified) {
    createUser(regInfo.userId, regInfo.email, {
      id: verification.registrationInfo.credentialID,
      publicKey: verification.registrationInfo.credentialPublicKey,
      counter: verification.registrationInfo.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
      transport: req.body.transports,
    });
    regSessions.delete(sessionId);
    return res.json({ verified: verification.verified });
  } else {
    return res
      .status(400)
      .json({ verified: false, error: "Verification failed" });
  }
});

app.get("/init-auth", async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = getUserByEmail(email);
  if (user == null) {
    return res.status(400).json({ error: "No user for this email" });
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: [
      {
        id: user.passKey.id,
        type: "public-key",
        transports: user.passKey.transports,
      },
    ],
  });

  // Track challenge server-side using a short-lived sessionId returned to the client
  const sessionId = createSessionId();
  authSessions.set(sessionId, {
    userId: user.id,
    challenge: options.challenge,
    expires: Date.now() + 60000,
  });

  res.json({ ...options, sessionId });
});

app.post("/verify-auth", async (req, res) => {
  const sessionId = req.body.sessionId;
  const authInfo = sessionId ? authSessions.get(sessionId) : null;

  if (!authInfo || isExpired(authInfo.expires)) {
    if (sessionId) authSessions.delete(sessionId);
    return res.status(400).json({ error: "Authentication info not found" });
  }

  const user = getUserById(authInfo.userId);
  if (user == null || user.passKey.id != req.body.id) {
    return res.status(400).json({ error: "Invalid user" });
  }

  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge: authInfo.challenge,
    expectedOrigin: CLIENT_URL,
    expectedRPID: RP_ID,
    authenticator: {
      credentialID: user.passKey.id,
      credentialPublicKey: user.passKey.publicKey,
      counter: user.passKey.counter,
      transports: user.passKey.transports,
    },
  });

  if (verification.verified) {
    updateUserCounter(user.id, verification.authenticationInfo.newCounter);
    authSessions.delete(sessionId);
    // Save user in a session cookie
    return res.json({ verified: verification.verified });
  } else {
    return res
      .status(400)
      .json({ verified: false, error: "Verification failed" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
