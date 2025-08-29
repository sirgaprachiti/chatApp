// const express = require("express");
// const bcrypt = require("bcryptjs");
// const jwt = require("jsonwebtoken");
// const User = require("../models/User");

// const router = express.Router();

// // POST /api/auth/signup
// router.post("/signup", async (req, res) => {
//   try {
//     const { username, password } = req.body;

//     if (!username || !password)
//       return res.status(400).json({ error: "Username and password are required" });

//     const existing = await User.findOne({ username });
//     if (existing) return res.status(409).json({ error: "Username already taken" });

//     const hashed = await bcrypt.hash(password, 10);
//     const user = await User.create({ username, password: hashed });

//     res.status(201).json({ message: "User created", user: { id: user._id, username: user.username } });
//   } catch (err) {
//     console.error("Signup error:", err);
//     res.status(500).json({ error: "Signup failed" });
//   }
// });

// // POST /api/auth/login
// router.post("/login", async (req, res) => {
//   try {
//     const { username, password } = req.body;

//     const user = await User.findOne({ username });
//     if (!user) return res.status(400).json({ error: "Invalid credentials" });

//     const ok = await bcrypt.compare(password, user.password);
//     if (!ok) return res.status(400).json({ error: "Invalid credentials" });

//     const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, {
//       expiresIn: "1d",
//     });

//     res.json({ token, user: { id: user._id, username: user.username } });
//   } catch (err) {
//     console.error("Login error:", err);
//     res.status(500).json({ error: "Login failed" });
//   }
// });

// module.exports = router;



const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { body } = require("express-validator");
const validate = require("../middleware/validate");
const User = require("../models/User");
const sendEmail = require("../utils/sendEmail");

const router = express.Router();

function signAccess(user) {
  return jwt.sign({ id: user._id, username: user.username }, process.env.JWT_ACCESS_SECRET, { expiresIn: process.env.ACCESS_TOKEN_TTL });
}
function signRefresh(user) {
  return jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.REFRESH_TOKEN_TTL });
}

// --- Signup (with email verification link)
router.post(
  "/signup",
  [
    body("username").isLength({ min: 3, max: 30 }).trim(),
    body("email").isEmail().normalizeEmail(),
    body("password").isStrongPassword({ minLength: 8, minSymbols: 0 }) // tweak policy
  ],
  validate,
  async (req, res) => {
    const { username, email, password } = req.body;

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.status(409).json({ error: "Username or email already in use" });

    const hash = await bcrypt.hash(password, 12);
    const verifyToken = crypto.randomBytes(32).toString("hex");
    const verifyHash = crypto.createHash("sha256").update(verifyToken).digest("hex");

    const user = await User.create({
      username, email, password: hash,
      emailVerifyToken: verifyHash,
      emailVerifyExpires: new Date(Date.now() + 1000 * 60 * 60 * 24) // 24h
    });

    const link = `${process.env.CLIENT_URL}/verify-email?token=${verifyToken}&email=${encodeURIComponent(email)}`;
    await sendEmail(email, "Verify your ChatApp email", `<p>Hi ${username}, verify your email:</p><a href="${link}">${link}</a>`);

    return res.status(201).json({ message: "User created, verification email sent" });
  }
);

// --- Verify email
router.post(
  "/verify-email",
  [ body("email").isEmail(), body("token").isString() ],
  validate,
  async (req, res) => {
    const { email, token } = req.body;
    const tokenHash = require("crypto").createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      email,
      emailVerifyToken: tokenHash,
      emailVerifyExpires: { $gt: new Date() }
    });
    if (!user) return res.status(400).json({ error: "Invalid or expired token" });

    user.isEmailVerified = true;
    user.emailVerifyToken = undefined;
    user.emailVerifyExpires = undefined;
    await user.save();

    res.json({ message: "Email verified" });
  }
);

// --- Login (issue access token + refresh cookie)
router.post(
  "/login",
  [ body("email").isEmail(), body("password").isString() ],
  validate,
  async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });

    if (!user.isEmailVerified) {
      return res.status(403).json({ error: "Email not verified" });
    }

    const accessToken = signAccess(user);
    const refreshToken = signRefresh(user);
    user.refreshTokenHash = await bcrypt.hash(refreshToken, 12);
    await user.save();

    // httpOnly refresh cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, secure: false, sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.json({ token: accessToken, user: { id: user._id, username: user.username, email: user.email } });
  }
);

// --- Refresh access token
router.post("/refresh", async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ error: "No refresh token" });

  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(payload.id);
    if (!user || !user.refreshTokenHash) return res.status(401).json({ error: "Invalid refresh" });

    const match = await bcrypt.compare(token, user.refreshTokenHash);
    if (!match) return res.status(401).json({ error: "Invalid refresh" });

    const newAccess = signAccess(user);
    res.json({ token: newAccess });
  } catch {
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }
});

// --- Logout (clear refresh cookie & DB hash)
router.post("/logout", async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (token) {
    try {
      const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
      await User.updateOne({ _id: payload.id }, { $unset: { refreshTokenHash: 1 } });
    } catch { /* ignore */ }
  }
  res.clearCookie("refreshToken");
  res.json({ message: "Logged out" });
});

// --- Forgot password (send link)
router.post(
  "/forgot-password",
  [ body("email").isEmail() ],
  validate,
  async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ message: "If that email exists, a link was sent" });

    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 1000 * 60 * 30); // 30 min
    await user.save();

    const link = `${process.env.CLIENT_URL}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
    await sendEmail(email, "Reset your ChatApp password", `<p>Reset password:</p><a href="${link}">${link}</a>`);
    res.json({ message: "If that email exists, a link was sent" });
  }
);

// --- Reset password
router.post(
  "/reset-password",
  [ body("email").isEmail(), body("token").isString(), body("newPassword").isStrongPassword({ minLength: 8, minSymbols: 0 }) ],
  validate,
  async (req, res) => {
    const { email, token, newPassword } = req.body;
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      email,
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() }
    });
    if (!user) return res.status(400).json({ error: "Invalid or expired token" });

    user.password = await bcrypt.hash(newPassword, 12);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: "Password updated" });
  }
);

module.exports = router;
