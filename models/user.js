const mongoose = require("mongoose");

const experienceSchema = new mongoose.Schema({
  designation: String,
  company: String,
  startDate: String,
  endDate: String,
  currentlyWorking: Boolean,
  location: String, // ✅ ADDED
  description: String,
});

const educationSchema = new mongoose.Schema({
  degree: String,
  college: String,
  startYear: String,
  endYear: String,
});

const certificationSchema = new mongoose.Schema({
  name: String,
  year: String,
});

const userSchema = new mongoose.Schema(
  {
    name: String,
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: String,
    googleId: String,
    role: String,

    // 🔹 Basic Info
    firstName: String,
    lastName: String,
    phone: String,
    location: String,
    headline: String,
    about: String,
    profilePhoto: String,
    resume: String,

    // 🔹 Professional Info
    totalExperience: String,
    employmentStatus: String,
    currentJobTitle: String,
    currentCompany: String,
    noticePeriod: String,
    currentCTC: String,
    expectedCTC: String,
    // For freshers: project details
    project: {
      name: String,
      duration: String,
      domains: [String],
    },

    // 🔹 Skills
    primarySkills: [String],
    secondarySkills: [String],

    // 🔹 Nested Arrays
    experiences: [experienceSchema],
    education: [educationSchema],
    certifications: [certificationSchema],

    // 🔹 Preferences
    preferredJobType: String,
    preferredLocation: String,
    workMode: String,
    notificationsEnabled: Boolean,
    profileVisible: Boolean,
    // 🔹 Password reset
    otp: String,
    otpExpires: Date,
    isOtpVerified: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
