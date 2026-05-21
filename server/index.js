const express = require("express");
const cors = require("cors");
const { getPortOverview } = require("./portScanner");

const app = express();

const PORT = process.env.PORTSCOPE_SERVER_PORT || 4177;

app.use(cors());
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "PortScope",
    message: "PortScope API is running"
  });
});

app.get("/api/ports", async (req, res) => {
  try {
    const overview = await getPortOverview();
    res.json(overview);
  } catch (err) {
    console.error("Port scan failed:", err);

    res.status(500).json({
      error: "Port scan failed",
      message:
        "PortScope could not inspect local ports on this machine. Try running with normal terminal permissions."
    });
  }
});

app.listen(PORT, () => {
  console.log(`PortScope API running at http://localhost:${PORT}`);
});