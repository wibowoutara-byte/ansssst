const express = require("express");
const ivasmsRouter = require("./ivasms");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use("/api/ivasms", ivasmsRouter);

app.get("/", (req, res) => {
  res.json({
    message: "IVASMS API wrapper running",
    endpoints: [
      "GET  /api/ivasms?type=numbers",
      "GET  /api/ivasms?type=sms",
      "GET  /api/ivasms/status",
      "GET  /api/ivasms/raw-sms",
      "POST /api/ivasms/update-session"
    ]
  });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
