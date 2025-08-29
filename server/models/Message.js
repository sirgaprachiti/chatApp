const mongoose = require("mongoose");
const MessageSchema = new mongoose.Schema({
  room:   { type: mongoose.Schema.Types.ObjectId, ref: "Room", required: true, index: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text:   { type: String, required: true, trim: true },
  // optional attachments later
}, { timestamps: true });

MessageSchema.index({ room: 1, createdAt: -1 });

module.exports = mongoose.model("Message", MessageSchema);
