import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "node:crypto";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: "5mb" }));

const OTP_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_DAYS = 90;
const otpStore = new Map();

/* ------------------------------------------------------------------ models */

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    phone: { type: String, required: true, unique: true, trim: true },
    upiId: { type: String, default: "", trim: true },
    isVerified: { type: Boolean, default: false },
  },
  { timestamps: true },
);
const User = mongoose.model("User", userSchema);

const sessionSchema = new mongoose.Schema(
  {
    token: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    // MongoDB removes the session automatically once it expires.
    createdAt: { type: Date, default: Date.now, expires: SESSION_TTL_DAYS * 24 * 60 * 60 },
  },
);
const Session = mongoose.model("Session", sessionSchema);

// One document per user holding their personal expense data.
const expenseDataSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
    categories: { type: Array, default: [] },
    daily: { type: Array, default: [] },
    monthly: { type: Array, default: [] },
    incomes: { type: Array, default: [] },
    // Split settlements already turned into income entries, so they are not added twice.
    syncedSettlements: { type: [String], default: [] },
  },
  { timestamps: true, minimize: false },
);
const ExpenseData = mongoose.model("ExpenseData", expenseDataSchema);

const friendSchema = new mongoose.Schema(
  {
    ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    name: { type: String, required: true, trim: true },
    phone: { type: String, required: true, trim: true },
  },
  { timestamps: true },
);
friendSchema.index({ ownerId: 1, phone: 1 }, { unique: true });
const Friend = mongoose.model("Friend", friendSchema);

const shareSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    phone: { type: String, required: true, trim: true },
    amount: { type: Number, required: true, min: 0 },
    isPayer: { type: Boolean, default: false },
    settled: { type: Boolean, default: false },
    settledAt: { type: Date, default: null },
    settledVia: { type: String, enum: ["upi", "cash", null], default: null },
    settledBy: { type: String, enum: ["member", "payer", null], default: null },
  },
  { _id: false },
);

const splitSchema = new mongoose.Schema(
  {
    payerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    payerName: { type: String, required: true },
    payerPhone: { type: String, required: true },
    amount: { type: Number, required: true, min: 0 },
    category: { name: String, icon: String, color: String },
    remark: { type: String, default: "", trim: true },
    paidTo: { type: String, default: "", trim: true },
    paidAt: { type: Date, default: Date.now },
    shares: { type: [shareSchema], default: [] },
  },
  { timestamps: true },
);
splitSchema.index({ "shares.phone": 1 });
const Split = mongoose.model("Split", splitSchema);

/* ----------------------------------------------------------------- helpers */

const cleanPhone = (v) => String(v || "").replace(/\D/g, "").slice(-10);
const round2 = (n) => Math.round(Number(n) * 100) / 100;

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

const publicUser = (u) => ({ _id: u._id, name: u.name, phone: u.phone, upiId: u.upiId || "", isVerified: u.isVerified });

async function issueSession(user) {
  const token = crypto.randomBytes(32).toString("hex");
  await Session.create({ token, userId: user._id });
  return token;
}

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const requireAuth = asyncRoute(async (req, res, next) => {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const session = token ? await Session.findOne({ token }) : null;
  const user = session ? await User.findById(session.userId) : null;
  if (!user) {
    return res.status(401).json({ success: false, message: "Please login again." });
  }
  req.user = user;
  next();
});

/** Adds the payer's UPI ID and which members are on the app, for display on the client. */
async function decorateSplits(splits) {
  const payerIds = [...new Set(splits.map((s) => String(s.payerId)))];
  const phones = [...new Set(splits.flatMap((s) => s.shares.map((sh) => sh.phone)))];
  const [payers, members] = await Promise.all([
    User.find({ _id: { $in: payerIds } }, { upiId: 1 }),
    User.find({ phone: { $in: phones } }, { phone: 1 }),
  ]);
  const upiById = new Map(payers.map((p) => [String(p._id), p.upiId || ""]));
  const onApp = new Set(members.map((m) => m.phone));
  return splits.map((s) => {
    const o = s.toObject();
    o.payerUpiId = upiById.get(String(s.payerId)) || "";
    o.shares = o.shares.map((sh) => ({ ...sh, onApp: onApp.has(sh.phone) }));
    return o;
  });
}

/* -------------------------------------------------------------------- auth */

app.get("/api/health", (_req, res) => {
  res.json({ success: true, message: "Expense Buddy API is running" });
});

app.post("/api/auth/send-otp", asyncRoute(async (req, res) => {
  const { phone, mode } = req.body || {};
  const cleaned = cleanPhone(phone);

  if (cleaned.length < 10) {
    return res.status(400).json({ success: false, message: "Valid mobile number is required." });
  }

  // "login" needs an existing account, "signup" needs a new number.
  if (mode === "login" || mode === "signup") {
    const exists = await User.exists({ phone: cleaned });
    if (mode === "login" && !exists) {
      return res.status(404).json({ success: false, code: "NO_ACCOUNT", message: "No account found with this number. Please create an account." });
    }
    if (mode === "signup" && exists) {
      return res.status(409).json({ success: false, code: "ACCOUNT_EXISTS", message: "An account with this number already exists. Please login." });
    }
  }

  const otp = generateOtp();
  otpStore.set(cleaned, { otp, createdAt: Date.now(), verified: false });

  // Demo mode: the OTP is returned instead of being sent by SMS.
  return res.json({ success: true, message: `OTP sent to ${cleaned}. Demo OTP: ${otp}`, otp });
}));

app.post("/api/auth/verify-otp", asyncRoute(async (req, res) => {
  const { phone, otp } = req.body || {};
  const cleaned = cleanPhone(phone);
  const record = otpStore.get(cleaned);

  if (!record || record.otp !== String(otp || "")) {
    return res.status(400).json({ success: false, message: "Invalid OTP" });
  }
  if (Date.now() - record.createdAt > OTP_TTL_MS) {
    otpStore.delete(cleaned);
    return res.status(400).json({ success: false, message: "OTP expired. Please request a new one." });
  }

  const user = await User.findOne({ phone: cleaned });
  if (!user) {
    // Keep the verified record so create-profile can confirm this number passed OTP.
    record.verified = true;
    return res.json({ success: true, message: "OTP verified. Please create your profile.", user: null });
  }

  otpStore.delete(cleaned);
  user.isVerified = true;
  await user.save();
  return res.json({ success: true, message: "OTP verified successfully.", user: publicUser(user), token: await issueSession(user) });
}));

app.post("/api/auth/create-profile", asyncRoute(async (req, res) => {
  const { phone, name } = req.body || {};
  const cleaned = cleanPhone(phone);
  const trimmedName = String(name || "").trim();

  if (cleaned.length < 10) {
    return res.status(400).json({ success: false, message: "Valid mobile number is required." });
  }
  if (!trimmedName) {
    return res.status(400).json({ success: false, message: "Name is required." });
  }

  const record = otpStore.get(cleaned);
  if (!record?.verified || Date.now() - record.createdAt > OTP_TTL_MS) {
    return res.status(401).json({ success: false, message: "Please verify your mobile number with OTP first." });
  }
  otpStore.delete(cleaned);

  let user = await User.findOne({ phone: cleaned });
  if (!user) {
    user = await User.create({ name: trimmedName, phone: cleaned, isVerified: true });
  } else {
    user.name = trimmedName;
    user.isVerified = true;
    await user.save();
  }

  return res.json({ success: true, message: "Profile saved successfully.", user: publicUser(user), token: await issueSession(user) });
}));

app.post("/api/auth/logout", requireAuth, asyncRoute(async (req, res) => {
  const token = (req.get("authorization") || "").slice(7);
  await Session.deleteOne({ token });
  res.json({ success: true });
}));

/* ---------------------------------------------------------------------- me */

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ success: true, data: publicUser(req.user) });
});

app.put("/api/me", requireAuth, asyncRoute(async (req, res) => {
  const { name, upiId } = req.body || {};
  if (name !== undefined) {
    const trimmed = String(name).trim();
    if (!trimmed) return res.status(400).json({ success: false, message: "Name is required." });
    req.user.name = trimmed;
  }
  if (upiId !== undefined) {
    const v = String(upiId).trim();
    if (v && !/^[\w.\-]{2,}@[a-zA-Z][\w.\-]*$/.test(v)) {
      return res.status(400).json({ success: false, message: "Enter a valid UPI ID, e.g. name@okaxis" });
    }
    req.user.upiId = v;
  }
  await req.user.save();
  res.json({ success: true, message: "Profile updated.", data: publicUser(req.user) });
}));

app.get("/api/me/expenses", requireAuth, asyncRoute(async (req, res) => {
  const doc = await ExpenseData.findOne({ userId: req.user._id });
  res.json({
    success: true,
    data: doc
      ? { categories: doc.categories, daily: doc.daily, monthly: doc.monthly, incomes: doc.incomes, syncedSettlements: doc.syncedSettlements, updatedAt: doc.updatedAt }
      : null,
  });
}));

app.put("/api/me/expenses", requireAuth, asyncRoute(async (req, res) => {
  const { categories, daily, monthly, incomes, syncedSettlements } = req.body || {};
  const asArray = (v) => (Array.isArray(v) ? v : []);
  const doc = await ExpenseData.findOneAndUpdate(
    { userId: req.user._id },
    {
      categories: asArray(categories),
      daily: asArray(daily),
      monthly: asArray(monthly),
      incomes: asArray(incomes),
      syncedSettlements: asArray(syncedSettlements).map(String),
    },
    { new: true, upsert: true },
  );
  res.json({ success: true, message: "Expenses saved.", data: { updatedAt: doc.updatedAt } });
}));

/* ----------------------------------------------------------------- friends */

app.get("/api/friends", requireAuth, asyncRoute(async (req, res) => {
  const friends = await Friend.find({ ownerId: req.user._id }).sort({ name: 1 });
  const onApp = new Set((await User.find({ phone: { $in: friends.map((f) => f.phone) } }, { phone: 1 })).map((u) => u.phone));
  res.json({ success: true, data: friends.map((f) => ({ _id: f._id, name: f.name, phone: f.phone, onApp: onApp.has(f.phone) })) });
}));

app.post("/api/friends", requireAuth, asyncRoute(async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const phone = cleanPhone(req.body?.phone);
  if (!name || phone.length < 10) {
    return res.status(400).json({ success: false, message: "Name and valid 10 digit mobile number are required." });
  }
  if (phone === req.user.phone) {
    return res.status(400).json({ success: false, message: "That's your own number." });
  }
  const friend = await Friend.findOneAndUpdate({ ownerId: req.user._id, phone }, { name }, { new: true, upsert: true });
  const onApp = Boolean(await User.exists({ phone }));
  res.status(201).json({ success: true, data: { _id: friend._id, name: friend.name, phone: friend.phone, onApp } });
}));

app.delete("/api/friends/:id", requireAuth, asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ success: false, message: "Invalid id." });
  await Friend.deleteOne({ _id: req.params.id, ownerId: req.user._id });
  res.json({ success: true });
}));

/* ------------------------------------------------------------------ splits */

app.get("/api/splits", requireAuth, asyncRoute(async (req, res) => {
  const splits = await Split.find({ $or: [{ payerId: req.user._id }, { "shares.phone": req.user.phone }] }).sort({ paidAt: -1 }).limit(500);
  res.json({ success: true, data: await decorateSplits(splits) });
}));

app.post("/api/splits", requireAuth, asyncRoute(async (req, res) => {
  const { amount, category, remark, paidTo, paidAt, shares } = req.body || {};
  const total = round2(amount);
  if (!(total > 0)) return res.status(400).json({ success: false, message: "Amount must be greater than 0." });
  if (!Array.isArray(shares) || shares.length < 2) {
    return res.status(400).json({ success: false, message: "Select at least one person to split with." });
  }

  const seen = new Set();
  const cleanShares = [];
  for (const s of shares) {
    const phone = cleanPhone(s?.phone);
    const name = String(s?.name || "").trim();
    const shareAmount = round2(s?.amount);
    if (!name || phone.length < 10 || !(shareAmount >= 0) || seen.has(phone)) {
      return res.status(400).json({ success: false, message: "Each person needs a name, a unique 10 digit number and an amount." });
    }
    seen.add(phone);
    const isPayer = phone === req.user.phone;
    // The payer's own share is settled from the start.
    cleanShares.push({ name, phone, amount: shareAmount, isPayer, settled: isPayer, settledAt: isPayer ? new Date() : null });
  }
  if (!cleanShares.some((s) => s.isPayer)) {
    return res.status(400).json({ success: false, message: "Your own share must be included." });
  }
  const sum = round2(cleanShares.reduce((t, s) => t + s.amount, 0));
  if (Math.abs(sum - total) > 0.01) {
    return res.status(400).json({ success: false, message: `Shares add up to ₹${sum}, but the total is ₹${total}.` });
  }

  const split = await Split.create({
    payerId: req.user._id,
    payerName: req.user.name,
    payerPhone: req.user.phone,
    amount: total,
    category: { name: String(category?.name || "Other"), icon: String(category?.icon || "MoreHorizontal"), color: String(category?.color || "#1C7C93") },
    remark: String(remark || "").trim(),
    paidTo: String(paidTo || "").trim(),
    paidAt: paidAt ? new Date(paidAt) : new Date(),
    shares: cleanShares,
  });

  // Remember everyone in the split as the payer's friends for next time.
  await Promise.all(
    cleanShares.filter((s) => !s.isPayer).map((s) =>
      Friend.updateOne({ ownerId: req.user._id, phone: s.phone }, { $setOnInsert: { name: s.name } }, { upsert: true }),
    ),
  );

  const [decorated] = await decorateSplits([split]);
  res.status(201).json({ success: true, message: "Split saved.", data: decorated });
}));

app.post("/api/splits/:id/settle", requireAuth, asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ success: false, message: "Invalid id." });
  const split = await Split.findById(req.params.id);
  if (!split) return res.status(404).json({ success: false, message: "Split not found." });

  const phone = cleanPhone(req.body?.phone);
  const via = req.body?.via === "cash" ? "cash" : "upi";
  const isPayer = String(split.payerId) === String(req.user._id);
  // A member can settle their own share; the payer can mark anyone's share as received.
  if (!isPayer && phone !== req.user.phone) {
    return res.status(403).json({ success: false, message: "You can only settle your own share." });
  }

  const share = split.shares.find((s) => s.phone === phone);
  if (!share || share.isPayer) return res.status(404).json({ success: false, message: "Share not found." });
  if (share.settled) return res.status(409).json({ success: false, message: "This share is already settled." });

  share.settled = true;
  share.settledAt = new Date();
  share.settledVia = via;
  share.settledBy = isPayer ? "payer" : "member";
  await split.save();

  const [decorated] = await decorateSplits([split]);
  res.json({ success: true, message: "Marked as settled.", data: decorated });
}));

app.delete("/api/splits/:id", requireAuth, asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ success: false, message: "Invalid id." });
  const split = await Split.findById(req.params.id);
  if (!split) return res.status(404).json({ success: false, message: "Split not found." });
  if (String(split.payerId) !== String(req.user._id)) {
    return res.status(403).json({ success: false, message: "Only the person who paid can delete this split." });
  }
  if (split.shares.some((s) => !s.isPayer && s.settled)) {
    return res.status(409).json({ success: false, message: "Someone has already paid their share, so this split can't be deleted." });
  }
  await split.deleteOne();
  res.json({ success: true });
}));

/* ------------------------------------------------------------------ server */

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ success: false, message: "Something went wrong on the server." });
});

async function startServer() {
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    console.error("MONGODB_URI is not set. Add it to .env locally, or to the service's Environment settings on Render.");
    process.exit(1);
  }
  try {
    await mongoose.connect(mongoUri);
    console.log("MongoDB connected successfully.");

    app.listen(PORT, () => {
      console.log(`Expense Buddy API running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("MongoDB connection failed:", error);
    process.exit(1);
  }
}

startServer();
