const { execFile } = require("child_process");
const os = require("os");

const COMMON_PORTS = [
  {
    port: 20,
    label: "FTP Data",
    category: "File Transfer",
    description: "Legacy FTP data transfer channel.",
    riskLevel: "Medium"
  },
  {
    port: 21,
    label: "FTP Control",
    category: "File Transfer",
    description: "Legacy FTP command channel.",
    riskLevel: "High"
  },
  {
    port: 22,
    label: "SSH",
    category: "Remote Access",
    description: "Secure shell access for remote administration.",
    riskLevel: "Medium"
  },
  {
    port: 25,
    label: "SMTP",
    category: "Email",
    description: "Email sending server.",
    riskLevel: "Medium"
  },
  {
    port: 53,
    label: "DNS",
    category: "Networking",
    description: "Domain name resolution.",
    riskLevel: "Medium"
  },
  {
    port: 80,
    label: "HTTP",
    category: "Web",
    description: "Standard unencrypted web traffic.",
    riskLevel: "Medium"
  },
  {
    port: 443,
    label: "HTTPS",
    category: "Web",
    description: "Standard encrypted web traffic.",
    riskLevel: "Low"
  },
  {
    port: 3000,
    label: "React / Express Dev",
    category: "Development",
    description: "Common local development server.",
    riskLevel: "Low"
  },
  {
    port: 3306,
    label: "MySQL",
    category: "Database",
    description: "MySQL database server.",
    riskLevel: "Medium"
  },
  {
    port: 4177,
    label: "PortScope API",
    category: "Development",
    description: "Default backend port for this PortScope project.",
    riskLevel: "Low"
  },
  {
    port: 5173,
    label: "Vite",
    category: "Development",
    description: "Default Vite frontend development server.",
    riskLevel: "Low"
  },
  {
    port: 5174,
    label: "PortScope UI",
    category: "Development",
    description: "Frontend port used by this PortScope project.",
    riskLevel: "Low"
  },
  {
    port: 5432,
    label: "PostgreSQL",
    category: "Database",
    description: "PostgreSQL database server.",
    riskLevel: "Medium"
  },
  {
    port: 5672,
    label: "RabbitMQ",
    category: "Messaging",
    description: "Message broker for queue-based systems.",
    riskLevel: "Medium"
  },
  {
    port: 5900,
    label: "VNC",
    category: "Remote Access",
    description: "Remote desktop access.",
    riskLevel: "High"
  },
  {
    port: 6379,
    label: "Redis",
    category: "Cache",
    description: "In-memory cache and key-value database.",
    riskLevel: "Medium"
  },
  {
    port: 8000,
    label: "Local API",
    category: "Development",
    description: "Common local backend development port.",
    riskLevel: "Low"
  },
  {
    port: 8080,
    label: "HTTP Alternate",
    category: "Development",
    description: "Common alternate web server port.",
    riskLevel: "Low"
  },
  {
    port: 8443,
    label: "HTTPS Alternate",
    category: "Development",
    description: "Common alternate secure web server port.",
    riskLevel: "Low"
  },
  {
    port: 27017,
    label: "MongoDB",
    category: "Database",
    description: "MongoDB database server.",
    riskLevel: "Medium"
  }
];

function runCommand(command, args) {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      args,
      {
        timeout: 7000,
        maxBuffer: 1024 * 1024
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }

        resolve({
          stdout,
          stderr,
          commandUsed: `${command} ${args.join(" ")}`
        });
      }
    );
  });
}

function extractPort(address) {
  if (!address) return null;

  const text = String(address).trim();

  const bracketMatch = text.match(/\]:(\d+)$/);
  if (bracketMatch) return Number(bracketMatch[1]);

  const normalMatch = text.match(/[.:](\d+)$/);
  if (normalMatch) return Number(normalMatch[1]);

  return null;
}

function classifyPort(port) {
  const common = COMMON_PORTS.find((item) => item.port === port);

  if (common) return common;

  if (port >= 1 && port <= 1023) {
    return {
      port,
      label: "Reserved System Port",
      category: "System",
      description: "Low-numbered port commonly reserved for system services.",
      riskLevel: "Medium"
    };
  }

  if (port >= 1024 && port <= 49151) {
    return {
      port,
      label: "Application Port",
      category: "Application",
      description: "Registered or application-level service port.",
      riskLevel: "Low"
    };
  }

  return {
    port,
    label: "Temporary Port",
    category: "Temporary",
    description: "High-numbered ephemeral port often used by short-lived connections.",
    riskLevel: "Low"
  };
}

function parseLsofOutput(output) {
  const lines = output.split("\n").filter(Boolean);
  const ports = [];

  for (const line of lines.slice(1)) {
    if (!line.includes("LISTEN")) continue;

    const parts = line.trim().split(/\s+/);
    if (parts.length < 9) continue;

    const processName = parts[0];
    const pid = parts[1];
    const user = parts[2];
    const nameField = parts.slice(8).join(" ");
    const address = nameField.replace(/\s+\(LISTEN\)$/, "");
    const port = extractPort(address);

    if (!Number.isInteger(port)) continue;

    ports.push({
      port,
      protocol: "TCP",
      address,
      processName,
      pid,
      user,
      raw: line
    });
  }

  return ports;
}

function parseSsOutput(output) {
  const lines = output.split("\n").filter(Boolean);
  const ports = [];

  for (const line of lines.slice(1)) {
    if (!line.includes("LISTEN")) continue;

    const parts = line.trim().split(/\s+/);
    const localAddress = parts[3];

    if (!localAddress) continue;

    const port = extractPort(localAddress);
    if (!Number.isInteger(port)) continue;

    const processMatch = line.match(/users:\(\("([^"]+)",pid=(\d+)/);

    ports.push({
      port,
      protocol: "TCP",
      address: localAddress,
      processName: processMatch ? processMatch[1] : "Unknown",
      pid: processMatch ? processMatch[2] : "",
      user: "",
      raw: line
    });
  }

  return ports;
}

function parseNetstatOutput(output) {
  const lines = output.split("\n").filter(Boolean);
  const ports = [];

  for (const line of lines) {
    if (!/LISTEN|LISTENING/i.test(line)) continue;

    const parts = line.trim().split(/\s+/);
    const protocol = parts[0]?.toUpperCase().startsWith("UDP") ? "UDP" : "TCP";

    const address = parts.find((part, index) => {
      if (index === 0) return false;
      return extractPort(part) !== null;
    });

    if (!address) continue;

    const port = extractPort(address);
    if (!Number.isInteger(port)) continue;

    const possiblePid = parts[parts.length - 1];
    const pid = /^\d+$/.test(possiblePid) ? possiblePid : "";

    ports.push({
      port,
      protocol,
      address,
      processName: "Unknown",
      pid,
      user: "",
      raw: line
    });
  }

  return ports;
}

function parsePowerShellJson(output) {
  if (!output.trim()) return [];

  const parsed = JSON.parse(output);
  const rows = Array.isArray(parsed) ? parsed : [parsed];

  return rows
    .map((row) => {
      const port = Number(row.LocalPort);

      if (!Number.isInteger(port)) {
        return null;
      }

      return {
        port,
        protocol: "TCP",
        address: `${row.LocalAddress}:${row.LocalPort}`,
        processName: row.ProcessName || "Unknown",
        pid: row.OwningProcess ? String(row.OwningProcess) : "",
        user: "",
        raw: JSON.stringify(row)
      };
    })
    .filter(Boolean);
}

function enrichPorts(ports) {
  return ports.map((port) => {
    const info = classifyPort(port.port);

    return {
      ...port,
      label: info.label,
      category: info.category,
      description: info.description,
      riskLevel: info.riskLevel,
      isCommon: COMMON_PORTS.some((item) => item.port === port.port)
    };
  });
}

function dedupePorts(ports) {
  const seen = new Map();

  for (const port of ports) {
    const key = `${port.port}-${port.protocol}-${port.address}-${port.processName}-${port.pid}`;
    seen.set(key, port);
  }

  return Array.from(seen.values()).sort((a, b) => a.port - b.port);
}

function groupPorts(ports) {
  const groups = new Map();

  for (const port of ports) {
    if (!groups.has(port.category)) {
      groups.set(port.category, []);
    }

    groups.get(port.category).push(port);
  }

  return Array.from(groups.entries())
    .map(([category, groupPorts]) => ({
      category,
      ports: groupPorts.sort((a, b) => a.port - b.port)
    }))
    .sort((a, b) => a.category.localeCompare(b.category));
}

async function scanWindowsPorts() {
  const command = `
    Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress,LocalPort,OwningProcess,State,@{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    ConvertTo-Json -Compress
  `;

  const candidates = ["powershell.exe", "powershell", "pwsh"];

  for (const candidate of candidates) {
    try {
      const result = await runCommand(candidate, [
        "-NoProfile",
        "-Command",
        command
      ]);

      return {
        ports: parsePowerShellJson(result.stdout),
        commandUsed: result.commandUsed
      };
    } catch {
      // Try the next PowerShell executable.
    }
  }

  const fallback = await runCommand("netstat", ["-ano"]);
  return {
    ports: parseNetstatOutput(fallback.stdout),
    commandUsed: fallback.commandUsed
  };
}

async function scanUnixPorts() {
  try {
    const result = await runCommand("lsof", [
      "-nP",
      "-iTCP",
      "-sTCP:LISTEN"
    ]);

    return {
      ports: parseLsofOutput(result.stdout),
      commandUsed: result.commandUsed
    };
  } catch {
    // Continue to fallback.
  }

  if (os.platform() === "linux") {
    try {
      const result = await runCommand("ss", ["-ltnp"]);

      return {
        ports: parseSsOutput(result.stdout),
        commandUsed: result.commandUsed
      };
    } catch {
      // Continue to netstat fallback.
    }
  }

  const result = await runCommand("netstat", ["-an"]);

  return {
    ports: parseNetstatOutput(result.stdout),
    commandUsed: result.commandUsed
  };
}

async function getPortOverview() {
  const scan =
    os.platform() === "win32" ? await scanWindowsPorts() : await scanUnixPorts();

  const activePorts = dedupePorts(enrichPorts(scan.ports));
  const activePortNumbers = new Set(activePorts.map((port) => port.port));

  const commonReference = COMMON_PORTS.map((port) => {
    const activeMatch = activePorts.find((item) => item.port === port.port);

    return {
      ...port,
      status: activePortNumbers.has(port.port) ? "used" : "free",
      processName: activeMatch?.processName || "",
      pid: activeMatch?.pid || "",
      address: activeMatch?.address || ""
    };
  });

  return {
    inspectedAt: new Date().toISOString(),
    hostname: os.hostname(),
    platform: os.platform(),
    commandUsed: scan.commandUsed,
    counts: {
      activePorts: activePorts.length,
      commonPortsUsed: commonReference.filter((port) => port.status === "used")
        .length,
      highRiskPorts: activePorts.filter((port) => port.riskLevel === "High")
        .length,
      categories: groupPorts(activePorts).length
    },
    activePorts,
    groups: groupPorts(activePorts),
    commonReference
  };
}

module.exports = {
  getPortOverview
};