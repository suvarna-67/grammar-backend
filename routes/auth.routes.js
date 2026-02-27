const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const User = require("../models/user");
const Otp = require("../models/Otp");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ensure uploads folder exists
const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage });
const normalizeRole = (role) => (role === "recruiter" ? "recruiter" : "jobseeker");

// Middleware to protect routes
const protect = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "Not authorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select("-password");
    next();
  } catch (err) {
    return res.status(401).json({ message: "Not authorized" });
  }
};

// GOOGLE AUTH START
router.get(
  "/google",
  (req, res, next) => {
    const role = normalizeRole(req.query.role);
    passport.authenticate("google", {
      scope: ["profile", "email"],
      prompt: "select_account",
      session: false,
      state: role,
    })(req, res, next);
  }
);

// GOOGLE AUTH CALLBACK
router.get(
  "/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/api/auth/google/failure" }),
  async (req, res) => {
    try {
      const token = jwt.sign(
        { id: req.user._id, role: req.user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
return res.redirect(`${frontendUrl}?token=${encodeURIComponent(token)}`);
    } catch (err) {
      return res.redirect("/api/auth/google/failure");
    }
  }
);

router.get("/google/failure", (req, res) => {
  return res.status(401).json({ message: "Google authentication failed" });
});

// SIGNUP
router.post("/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password, role, employmentStatus, phone } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name: `${firstName || ''} ${lastName || ''}`.trim(),
      firstName: firstName || '',
      lastName: lastName || '',
      email,
      phone: phone || '',
      password: hashedPassword,
      role,
      employmentStatus: employmentStatus || 'experienced',
    });

    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: "Signup failed" });
  }
});

// SIGNIN
router.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    if (!user.password) {
      return res.status(400).json({ message: "Use Google sign-in for this account" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      role: user.role,
      name: user.name,
      firstName: user.firstName,
      lastName: user.lastName,
      phone: user.phone,
      email: user.email,
      employmentStatus: user.employmentStatus,
    });
  } catch (err) {
    res.status(500).json({ message: "Signin failed" });
  }
});

// SIGNIN INIT (validate credentials and send OTP for signin)
router.post('/signin-init', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    if (!user.password) {
      return res.status(400).json({ message: "Use Google sign-in for this account" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate OTP and store, reuse /send-otp logic
    const otp = crypto.randomInt(100000, 999999).toString();
    await Otp.deleteMany({ email });
    await Otp.create({ email, otp, expiresAt: new Date(Date.now() + 5 * 60 * 1000) });

    const emailSent = await sendEmail(email, otp, 'signin');
    if (!emailSent) {
      console.error('Signin-init: email sending failed for', email);
      return res.status(500).json({ message: 'Failed to send OTP' });
    }

    return res.json({ message: 'OTP sent for signin' });
  } catch (err) {
    console.error('Signin-init error:', err);
    return res.status(500).json({ message: 'Signin failed' });
  }
});

// SIGNIN VERIFY (verify OTP then issue token)
router.post('/signin-verify', async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await Otp.findOne({ email, otp });
    if (!record) return res.status(400).json({ message: 'Invalid OTP' });
    if (record.expiresAt < new Date()) return res.status(400).json({ message: 'OTP Expired' });

    // remove used OTPs
    await Otp.deleteMany({ email });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    return res.json({
      token,
      role: user.role,
      name: user.name,
      firstName: user.firstName,
      lastName: user.lastName,
      phone: user.phone,
      email: user.email,
      employmentStatus: user.employmentStatus,
    });
  } catch (err) {
    console.error('Signin-verify error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// SEND OTP - stores OTP in Otp collection and emails it
router.post('/send-otp', async (req, res) => {
  try {
    const { email, context = 'password_reset' } = req.body;
    const emailContext = context === 'signin' ? 'signin' : 'password_reset';

    const otp = crypto.randomInt(100000, 999999).toString();

    // Delete any existing OTPs for this email
    await Otp.deleteMany({ email });

    // Create new OTP record
    await Otp.create({
      email,
      otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    });

    const emailSent = await sendEmail(email, otp, emailContext);
    if (!emailSent) {
      console.error('Send OTP: email sending failed for', email);
      return res.status(500).json({ message: 'Failed to send OTP' });
    }

    return res.json({ message: 'OTP sent successfully' });
  } catch (err) {
    console.error('Send OTP error:', err);
    return res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// VERIFY OTP
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await Otp.findOne({ email, otp });
    if (!record) return res.status(400).json({ message: 'Invalid OTP' });

    if (record.expiresAt < new Date()) return res.status(400).json({ message: 'OTP Expired' });

    // remove used OTPs
    await Otp.deleteMany({ email });

    return res.json({ message: 'OTP Verified' });
  } catch (err) {
    console.error('Verify OTP error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// RESET PASSWORD
router.post('/reset-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.findOneAndUpdate({ email }, { password: hashedPassword });

    // remove OTP records for this email
    await Otp.deleteMany({ email });

    return res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    return res.status(500).json({ message: 'Failed to reset password' });
  }
});
// Note: Resend can be implemented client-side by calling /send-otp again when needed.

// UPDATE PROFILE
router.put("/update-profile", protect, async (req, res) => {
  try {
    // Only $set allowed fields to avoid accidental overwrite
    const allowed = [
      'firstName', 'lastName', 'phone', 'location', 'headline', 'about', 'profilePhoto',
      'totalExperience', 'employmentStatus', 'currentJobTitle', 'currentCompany', 'noticePeriod', 'currentCTC', 'expectedCTC', 'project',
      'primarySkills', 'secondarySkills', 'experiences', 'education', 'certifications',
      'preferredJobType', 'preferredLocation', 'workMode', 'notificationsEnabled', 'profileVisible', 'resume'
    ];

    const payload = {};
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) payload[key] = req.body[key];
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { $set: payload },
      { new: true }
    );

    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ message: "Profile update failed" });
  }
});

// GET PROFILE
router.get("/get-profile", protect, async (req, res) => {
  res.json(req.user);
});

// Alternative profile endpoint (returns same data)
// Middleware to verify token and expose userId
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token" });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // attach full user for routes that expect req.user
    req.user = await User.findById(decoded.id).select("-password");
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// GET USER PROFILE (mounted at /api/auth/profile)
router.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch profile" });
  }
});

// GET /me (convenience endpoint)
router.get('/me', authMiddleware, async (req, res) => {
  try {
    return res.json(req.user);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch user' });
  }
});

// UPDATE EDUCATION
router.put('/update-education', authMiddleware, async (req, res) => {
  try {
    const { education } = req.body;

    const user = await User.findByIdAndUpdate(
      req.userId,
      { $set: { education } },
      { new: true }
    );

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Failed to update education' });
  }
});

// UPDATE EXPERIENCE
router.put('/update-experience', authMiddleware, async (req, res) => {
  try {
    const { experiences } = req.body;

    const user = await User.findByIdAndUpdate(
      req.userId,
      { $set: { experiences } },
      { new: true }
    );

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Failed to update experiences' });
  }
});

// UPDATE CERTIFICATIONS (explicit endpoint)
router.put('/update-certifications', authMiddleware, async (req, res) => {
  try {
    const { certifications } = req.body;
    if (!Array.isArray(certifications)) return res.status(400).json({ message: 'Invalid certifications' });

    const user = await User.findByIdAndUpdate(
      req.userId,
      { $set: { certifications } },
      { new: true }
    );

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update certifications' });
  }
});

// UPDATE SKILLS (explicit endpoint)
router.put('/update-skills', authMiddleware, async (req, res) => {
  try {
    const { primarySkills, secondarySkills } = req.body;
    const payload = {};
    if (primarySkills) payload.primarySkills = Array.isArray(primarySkills) ? primarySkills : [];
    if (secondarySkills) payload.secondarySkills = Array.isArray(secondarySkills) ? secondarySkills : [];

    const user = await User.findByIdAndUpdate(
      req.userId,
      { $set: payload },
      { new: true }
    );

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update skills' });
  }
});

// UPLOAD PROFILE PHOTO
router.post('/upload-photo', protect, upload.single('photo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const photoPath = `/uploads/${req.file.filename}`;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { profilePhoto: photoPath },
      { new: true }
    );

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Photo upload failed' });
  }
});

// UPLOAD RESUME
router.post('/upload-resume', protect, upload.single('resume'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const resumePath = `/uploads/${req.file.filename}`;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { resume: resumePath },
      { new: true }
    );

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Resume upload failed' });
  }
});

module.exports = router;
