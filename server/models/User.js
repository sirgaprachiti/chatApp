// const mongoose = require("mongoose");

// const UserSchema = new mongoose.Schema(
//   {
//     username: { type: String, required: true, unique: true, trim: true },
//     password: { type: String, required: true }, // hashed
//   },
//   { timestamps: true }
// );

// module.exports = mongoose.model("User", UserSchema);

const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30 },
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true }, // bcrypt hash
  avatarUrl:{ type: String, default: "" },
  status:   { type: String, enum: ["online","offline","busy"], default: "offline" },
  lastSeen: { type: Date, default: Date.now },

  // account lifecycle
  isEmailVerified:   { type: Boolean, default: false },
  emailVerifyToken:  { type: String },    // random token hash
  emailVerifyExpires:{ type: Date },
  resetPasswordToken:{ type: String },
  resetPasswordExpires:{ type: Date },

  // optional: allow one refresh token at a time (rotate on login)
  refreshTokenHash:  { type: String }
}, { timestamps: true });

UserSchema.index({ username: 1 });
UserSchema.index({ email: 1 });

module.exports = mongoose.model("User", UserSchema);
