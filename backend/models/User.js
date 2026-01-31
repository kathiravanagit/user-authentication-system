const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  isConfirmed: {
    type: Boolean,
    default: false
  },
  confirmationToken: {
    type: String
  },
  resetOtpHash: {
    type: String
  },
  resetOtpExpires: {
    type: Date
  }
});

module.exports = mongoose.model("User", userSchema);
