require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/my_custom_auth_db";
const JWT_SECRET = process.env.JWT_SECRET || "MY_CUSTOM_SECRET_KEY_2026";
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

let genAI = null;
if (GEMINI_API_KEY) {
  genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
}

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(express.static(path.resolve(__dirname)));
app.use("/uploads", express.static(uploadDir));

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/dashboard.html", (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/unlock.html", (req, res) => res.sendFile(path.join(__dirname, "unlock.html")));

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB Connected!"))
  .catch((err) => console.error("Database Connection Error:", err.message));

const userSchema = new mongoose.Schema({
  customUserId: { type: String, required: true, unique: true, trim: true, lowercase: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  securityQuestion: { type: String, required: true },
  securityAnswer: { type: String, required: true }, // Lowercase & trimmed
  isQrLocked: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const documentSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  category: { type: String, required: true, default: "Documents & certificates" },
  title: { type: String, required: true },
  physicalLocation: { type: String, required: true },
  personName: { type: String, default: "" },
  documentType: { type: String, default: "" },
  issueDate: { type: Date, default: null },
  importantDate: { type: Date, default: null },
  validitySpan: { type: String, default: "Permanent" },
  renewalTip: { type: String, default: "" },
  aiSummary: { type: String, default: "" },
  fileName: { type: String, default: "no-file" },
  fileOriginalName: { type: String, default: "No File Attached" },
  fileUrl: { type: String, default: "/uploads/no-file" },
  fileType: { type: String, default: "text/plain" },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("CustomUser", userSchema);
const Document = mongoose.model("UserDocument", documentSchema);

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const token = authHeader.split(" ")[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid Token" });
  }
};

function parseAnyDateToUTC(dateStr) {
  if (!dateStr || dateStr === "null" || dateStr === "undefined") return null;
  const match = String(dateStr).match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
  if (match) {
    const day = parseInt(match[1], 10);
    const month = parseInt(match[2], 10) - 1;
    const year = parseInt(match[3], 10);
    return new Date(Date.UTC(year, month, day));
  }
  const ymdMatch = String(dateStr).match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
  if (ymdMatch) {
    const year = parseInt(ymdMatch[1], 10);
    const month = parseInt(ymdMatch[2], 10) - 1;
    const day = parseInt(ymdMatch[3], 10);
    return new Date(Date.UTC(year, month, day));
  }
  const d = new Date(dateStr);
  return isNaN(d.getTime()) ? null : d;
}

// ---------------- AUTH ROUTES ----------------

app.post("/api/auth/signup", async (req, res) => {
  const { name, customUserId, password, securityQuestion, securityAnswer } = req.body;
  if (!name || !customUserId || !password || !securityQuestion || !securityAnswer) {
    return res.status(400).json({ error: "All fields including security question are required." });
  }

  try {
    const formattedUserId = customUserId.trim().toLowerCase();
    const userExists = await User.findOne({ customUserId: formattedUserId });
    if (userExists) return res.status(400).json({ error: "User ID is already taken." });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Normalize security answer: trim and lowercase (case-insensitive)
    const normalizedAnswer = securityAnswer.trim().toLowerCase();
    const hashedAnswer = await bcrypt.hash(normalizedAnswer, salt);

    const newUser = new User({
      name,
      customUserId: formattedUserId,
      password: hashedPassword,
      securityQuestion,
      securityAnswer: hashedAnswer,
      isQrLocked: true
    });
    await newUser.save();

    const token = jwt.sign({ customUserId: newUser.customUserId, name: newUser.name }, JWT_SECRET, { expiresIn: "7d" });
    return res.status(201).json({ message: "Success", token, user: { name: newUser.name, customUserId: newUser.customUserId, isQrLocked: newUser.isQrLocked } });
  } catch (err) {
    return res.status(500).json({ error: "Database error during registration." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { customUserId, password } = req.body;
  if (!customUserId || !password) return res.status(400).json({ error: "Please enter both credentials." });

  try {
    const formattedUserId = customUserId.trim().toLowerCase();
    const user = await User.findOne({ customUserId: formattedUserId });
    if (!user) return res.status(404).json({ error: "User not found." });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Incorrect password." });

    const token = jwt.sign({ customUserId: user.customUserId, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ message: "Success", token, user: { name: user.name, customUserId: user.customUserId, isQrLocked: user.isQrLocked } });
  } catch (err) {
    return res.status(500).json({ error: "Database error" });
  }
});

// ---------------- PASSWORD RESET / RECREATE APIS ----------------

// Step 1: Fetch Security Question for User
app.post("/api/auth/get-security-question", async (req, res) => {
  try {
    const { customUserId } = req.body;
    if (!customUserId) return res.status(400).json({ error: "Please enter User ID." });

    const user = await User.findOne({ customUserId: customUserId.trim().toLowerCase() });
    if (!user) return res.status(404).json({ error: "No account found with this User ID." });

    return res.json({ securityQuestion: user.securityQuestion });
  } catch (err) {
    return res.status(500).json({ error: "Server error." });
  }
});

// Step 2: Verify Answer & Reset Password
app.post("/api/auth/reset-password-with-answer", async (req, res) => {
  try {
    const { customUserId, securityAnswer, newPassword } = req.body;
    if (!customUserId || !securityAnswer || !newPassword) {
      return res.status(400).json({ error: "All fields are required." });
    }

    const user = await User.findOne({ customUserId: customUserId.trim().toLowerCase() });
    if (!user) return res.status(404).json({ error: "User not found." });

    // Verify answer case-insensitively
    const normalizedInputAnswer = securityAnswer.trim().toLowerCase();
    const isAnswerMatch = await bcrypt.compare(normalizedInputAnswer, user.securityAnswer);

    if (!isAnswerMatch) {
      return res.status(400).json({ error: "Incorrect answer to the security question." });
    }

    // Hash and replace old password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    return res.json({ message: "Password updated successfully! You can now log in." });
  } catch (err) {
    return res.status(500).json({ error: "Password reset failed." });
  }
});

// 🤖 Chatbot Recovery Support
app.post("/api/auth/chat-recovery", async (req, res) => {
  try {
    const { message, userId } = req.body;
    if (!GEMINI_API_KEY || !genAI) {
      return res.json({
        reply: "You can reset your password directly using the 'Forgot Password' option by answering your security question, or contact the admin at vikram.2872006@gmail.com."
      });
    }

    const model = genAI.getGenerativeModel({ model: "gemini-3.5-flash" });
    const prompt = `You are "Vortex AI Support".
The user has failed login attempts. User Context: "${userId || 'Unknown'}". User Message: "${message}".
Guide them in 2 short sentences: They can click the "Forgot Password" button on the screen to answer their Security Question and reset their password instantly, or email vikram.2872006@gmail.com for help. English only.`;

    const result = await model.generateContent(prompt);
    return res.json({ reply: result.response.text() });
  } catch (err) {
    return res.json({
      reply: "Click 'Forgot Password' to answer your security question and recreate your password."
    });
  }
});

// QR Status & Privacy APIs
app.get("/api/auth/qr-status/:userId", async (req, res) => {
  try {
    const user = await User.findOne({ customUserId: req.params.userId.trim().toLowerCase() });
    if (!user) return res.status(404).json({ error: "Vault User not found" });

    let instantToken = null;
    if (!user.isQrLocked) {
      instantToken = jwt.sign({ customUserId: user.customUserId, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
    }

    return res.json({ name: user.name, customUserId: user.customUserId, isQrLocked: user.isQrLocked, instantToken });
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/update-qr-privacy", authMiddleware, async (req, res) => {
  try {
    const { isQrLocked } = req.body;
    const user = await User.findOneAndUpdate(
      { customUserId: req.user.customUserId },
      { isQrLocked: Boolean(isQrLocked) },
      { new: true }
    );
    return res.json({ message: "QR Privacy updated successfully", isQrLocked: user.isQrLocked });
  } catch (err) {
    return res.status(500).json({ error: "Failed to update QR privacy." });
  }
});

// ---------------- DOCUMENT UPLOAD & AI OCR ----------------

app.post("/api/documents/upload", authMiddleware, upload.single("docFile"), async (req, res) => {
  try {
    const { title, physicalLocation, category, manualDate } = req.body;
    if (!title || !physicalLocation) {
      return res.status(400).json({ error: "Title and details/location are required." });
    }

    let calculatedExpiryDate = manualDate ? parseAnyDateToUTC(manualDate) : null;
    let extractedIssueDate = null;
    let personName = "";
    let documentType = "";
    let validitySpan = "Permanent";
    let renewalTip = "";
    let aiSummary = "";
    let fileUrl = "/uploads/no-file";
    let fileName = "no-file";
    let fileOriginalName = "No File Attached";
    let fileType = "text/plain";

    if (req.file) {
      fileName = req.file.filename;
      fileOriginalName = req.file.originalname;
      fileUrl = `/uploads/${req.file.filename}`;
      fileType = req.file.mimetype;

      if (GEMINI_API_KEY && genAI) {
        try {
          const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
          const filePath = path.join(uploadDir, req.file.filename);
          
          let mimeType = req.file.mimetype || "image/jpeg";
          if (mimeType === "application/octet-stream") mimeType = "image/jpeg";

          const filePart = {
            inlineData: {
              data: fs.readFileSync(filePath).toString("base64"),
              mimeType: mimeType
            }
          };

          const prompt = `Extract JSON from document:
1. "personName": Person / Customer name
2. "documentType": Exact certificate/bill title
3. "issueDate": DD/MM/YYYY
4. "validitySpan": Lifespan string
5. "expiryDate": DD/MM/YYYY or null
6. "renewalTip": Short renewal tip
7. "summary": Brief note

Return raw JSON:
{"personName":"","documentType":"","issueDate":"","validitySpan":"","expiryDate":null,"renewalTip":"","summary":""}`;

          const result = await model.generateContent([prompt, filePart]);
          const cleanJson = result.response.text().replace(/```json/gi, "").replace(/```/g, "").trim();
          const parsed = JSON.parse(cleanJson);

          personName = parsed.personName || "";
          documentType = parsed.documentType || "";
          extractedIssueDate = parseAnyDateToUTC(parsed.issueDate);
          if (!calculatedExpiryDate) calculatedExpiryDate = parseAnyDateToUTC(parsed.expiryDate);
          validitySpan = parsed.validitySpan || "Permanent";
          renewalTip = parsed.renewalTip || "";
          aiSummary = parsed.summary || "";
        } catch (aiErr) {
          console.error("AI Scan Error:", aiErr.message);
        }
      }
    }

    const newDoc = new Document({
      userId: req.user.customUserId,
      category: category || "Documents & certificates",
      title: title.trim(),
      physicalLocation: physicalLocation.trim(),
      personName,
      documentType,
      issueDate: extractedIssueDate,
      importantDate: calculatedExpiryDate,
      validitySpan,
      renewalTip,
      aiSummary,
      fileName,
      fileOriginalName,
      fileUrl,
      fileType
    });

    await newDoc.save();
    return res.status(201).json({ message: "Stored successfully", document: newDoc });
  } catch (err) {
    return res.status(500).json({ error: "Upload failed." });
  }
});

app.get("/api/documents", authMiddleware, async (req, res) => {
  try {
    const docs = await Document.find({ userId: req.user.customUserId }).sort({ createdAt: -1 });
    return res.json({ documents: docs });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch." });
  }
});

app.delete("/api/documents/:id", authMiddleware, async (req, res) => {
  try {
    const doc = await Document.findOne({ _id: req.params.id, userId: req.user.customUserId });
    if (!doc) return res.status(404).json({ error: "Not found." });

    if (doc.fileName && doc.fileName !== "no-file") {
      const filePath = path.join(uploadDir, doc.fileName);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    await Document.findByIdAndDelete(req.params.id);
    return res.json({ message: "Deleted" });
  } catch (err) {
    return res.status(500).json({ error: "Delete failed." });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on http://127.0.0.1:${PORT}`);
});