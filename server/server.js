// const express = require("express");
// const path = require("path");
// const mongoose = require("mongoose");
// const cors = require("cors");
// const dotenv = require("dotenv");

// dotenv.config({ path: path.join(__dirname, ".env") });

// // dotenv.config();
// console.log("MONGO_URI from env:", process.env.MONGO_URI);

// const app = express();
// const PORT = process.env.PORT || 5000;

// // Middleware
// app.use(cors());
// app.use(express.json());

// // MongoDB connection
// mongoose
//   .connect(process.env.MONGO_URI)
//   .then(() => console.log("✅ MongoDB connected"))
//   .catch((err) => console.error("MongoDB error:", err));

//   // after app + middleware:
// const authRoutes = require("./routes/auth");
// app.use("/api/auth", authRoutes);

// // Test route
// app.get("/", (req, res) => {
//   res.send("ChatApp backend running 🚀");
// });

// // Start server
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const dotenv = require("dotenv");

dotenv.config({ path: path.join(__dirname, ".env") });

const app = express();
const PORT = process.env.PORT || 5000;

// security + parsing
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// basic rate limit for auth endpoints
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use("/api/auth", authLimiter);

// db
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("MongoDB error:", err); process.exit(1); });

// routes
app.use("/api/auth", require("./routes/auth"));
app.use("/api/rooms", require("./routes/rooms"));
app.use("/api/messages", require("./routes/messages"));

app.get("/", (_req, res) => res.send("ChatApp backend running 🚀"));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
