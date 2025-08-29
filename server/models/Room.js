const mongoose = require("mongoose");
const RoomSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
}, { timestamps: true });

RoomSchema.index({ name: 1, createdBy: 1 });

module.exports = mongoose.model("Room", RoomSchema);
