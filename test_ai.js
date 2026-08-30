require("dotenv").config();
const { GoogleGenerativeAI } = require("@google/generative-ai");

async function checkAI() {
  console.log("Checking API Key:", process.env.GEMINI_API_KEY ? "Found ✅" : "Missing ❌");

  try {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    // Use latest flash tag or fallback to gemini-pro
    const model = genAI.getGenerativeModel({ model: "gemini-3.5-flash" });

    console.log("Sending test prompt to Gemini...");
    const result = await model.generateContent("Hello! Reply with 'AI is working perfectly!'");
    console.log("🤖 Response:", result.response.text());
  } catch (error) {
    console.error("❌ Gemini Error:", error.message);
  }
}

checkAI();