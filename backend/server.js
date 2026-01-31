const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config({ path: "./.env" });

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Debug (remove later if you want)
console.log("MONGO_URI =", process.env.MONGO_URI);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
  })
  .catch((err) => {
    console.log("MongoDB error:", err.message);
  });

// Routes
app.use("/api/auth", require("./routes/auth"));

const authMiddleware = require("./middleware/authMiddleware");

// Protected route
app.get("/api/protected", authMiddleware, (req, res) => {
  res.json({ message: "Access granted" });
});

// Test route (optional)
app.get("/", (req, res) => {
  res.send("Server is running");
});

// Server start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  let url;
  if (process.env.RENDER_EXTERNAL_URL) {
    url = `${process.env.RENDER_EXTERNAL_URL}`;
  } else {
    url = `http://localhost:5000`;
  }
  console.log(`Server running at:5000`);
});
