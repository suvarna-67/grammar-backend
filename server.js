require('dotenv').config();
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require("passport");
const connectDB = require("./config/db");

dotenv.config();
connectDB();
require("./config/passport");

const app = express();

app.use(cors());
app.use(express.json());
app.use(passport.initialize());

const path = require('path');
const fs = require('fs');

// ensure uploads folder exists and serve it
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

app.use("/api/auth", require("./routes/auth.routes"));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(` Server running on port ${PORT}`);
});
