const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const User = require("../models/User");

const router = express.Router();

// Validation helpers
const normalizeEmail = (email = "") => email.trim().toLowerCase();

const isSingleEmail = (email) => !/[\s,;]/.test(email);

const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const isStrongPassword = (password) => {
  const hasMinLength = password.length >= 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*]/.test(password);
  return hasMinLength && hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
};

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || "smtp.gmail.com",
  port: Number(process.env.EMAIL_PORT || 587),
  secure: process.env.EMAIL_SECURE === "true",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

transporter.verify((error) => {
  if (error) {
    console.log("EMAIL CONFIG ERROR:", error.message);
  } else {
    console.log("Email service ready");
  }
});

const sendResetOtp = async (to, otp) => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    throw new Error("Email service not configured");
  }

  const from = process.env.EMAIL_FROM || process.env.EMAIL_USER;
  const info = await transporter.sendMail({
    from,
    to,
    subject: "Your password reset OTP",
    text: `Your OTP is ${otp}. It expires in 10 minutes.`,
    html: `<p>Your OTP is <strong>${otp}</strong>. It expires in 10 minutes.</p>`
  });
  console.log("OTP EMAIL SENT:", {
    messageId: info.messageId,
    accepted: info.accepted,
    rejected: info.rejected,
    response: info.response
  });
};

// REGISTER ROUTE
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (!isSingleEmail(normalizedEmail) || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Enter a single valid email" });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        message: "Password must be at least 8 characters with uppercase, lowercase, number, and special character (!@#$%^&*)"
      });
    }

    const userExists = await User.findOne({ email: normalizedEmail });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email: normalizedEmail,
      password: hashedPassword
    });

    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.log("REGISTER ERROR:", error);
    res.status(500).json({ message: error.message });
  }
});

// LOGIN ROUTE
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!isSingleEmail(normalizedEmail) || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Enter a single valid email" });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    console.log("LOGIN ERROR:", error);
    res.status(500).json({ message: error.message });
  }
});

// FORGOT PASSWORD (SEND OTP)
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    if (!isSingleEmail(normalizedEmail) || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Enter a single valid email" });
    }

    const user = await User.findOne({ email: normalizedEmail });

    if (user) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

      user.resetOtpHash = otpHash;
      user.resetOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
      await user.save();

      try {
        await sendResetOtp(normalizedEmail, otp);
      } catch (emailError) {
        console.log("SEND OTP ERROR:", emailError);
        return res.status(500).json({ message: "Email service error. OTP not sent." });
      }
    }

    res.json({ message: "If the account exists, an OTP was sent." });
  } catch (error) {
    console.log("FORGOT PASSWORD ERROR:", error);
    res.status(500).json({ message: error.message });
  }
});

// VERIFY OTP
router.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!email || !otp) {
      return res.status(400).json({ message: "Email and OTP are required" });
    }

    if (!isSingleEmail(normalizedEmail) || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Enter a single valid email" });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user || !user.resetOtpHash || !user.resetOtpExpires) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    const isValid =
      otpHash === user.resetOtpHash && user.resetOtpExpires > new Date();

    if (!isValid) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    res.json({ message: "OTP verified" });
  } catch (error) {
    console.log("VERIFY OTP ERROR:", error);
    res.status(500).json({ message: error.message });
  }
});

// RESET PASSWORD
router.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const normalizedEmail = normalizeEmail(email);

    if (!email || !otp || !newPassword) {
      return res
        .status(400)
        .json({ message: "Email, OTP, and new password are required" });
    }

    if (!isSingleEmail(normalizedEmail) || !isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: "Enter a single valid email" });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user || !user.resetOtpHash || !user.resetOtpExpires) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    const isValid =
      otpHash === user.resetOtpHash && user.resetOtpExpires > new Date();

    if (!isValid) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetOtpHash = undefined;
    user.resetOtpExpires = undefined;
    await user.save();

    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.log("RESET PASSWORD ERROR:", error);
    res.status(500).json({ message: error.message });
  }
});

const authMiddleware = require("../middleware/authMiddleware");

router.put("/update", authMiddleware, async (req, res) => {
  try {
    const { name, email } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { name, email },
      { new: true }
    );

    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Update failed" });
  }
});

router.delete("/delete", authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user.userId);
    res.json({ message: "Account deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Delete failed" });
  }
});

module.exports = router;

