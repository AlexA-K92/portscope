import { useEffect, useMemo, useState } from "react";
import {
  getPortOverview,
  type ActivePort,
  type CommonReferencePort,
  type PortOverview,
  type RiskLevel
} from "./api/portsApi";
import "./styles.css";

type ViewMode = "active" | "common";

export default function App() {
  const [overview, setOverview] = useState<PortOverview | null>(null);
  const [query, setQuery] = useState("");
  const [viewMode, setViewMode] = useState<ViewMode>("active");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedPort, setSelectedPort] = useState<ActivePort | null>(null);

  async function loadPorts() {
    setLoading(true);
    setError("");

    try {
      const data = await getPortOverview();
      setOverview(data);
    } catch (err) {
      console.error(err);
      setError("Could not scan local ports. Make sure the Node API is running.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadPorts();
  }, []);

  const filteredGroups = useMemo(() => {
    if (!overview) return [];

    const normalizedQuery = query.trim().toLowerCase();

    return overview.groups
      .map((group) => {
        const ports = group.ports.filter((port) => {
          if (!normalizedQuery) return true;

          return [
            port.port,
            port.protocol,
            port.address,
            port.processName,
            port.pid,
            port.label,
            port.category,
            port.description,
            port.riskLevel
          ]
            .join(" ")
            .toLowerCase()
            .includes(normalizedQuery);
        });

        return {
          ...group,
          ports
        };
      })
      .filter((group) => group.ports.length > 0);
  }, [overview, query]);

  const filteredCommonPorts = useMemo(() => {
    if (!overview) return [];

    const normalizedQuery = query.trim().toLowerCase();

    return overview.commonReference.filter((port) => {
      if (!normalizedQuery) return true;

      return [
        port.port,
        port.label,
        port.category,
        port.description,
        port.riskLevel,
        port.status,
        port.processName,
        port.pid,
        port.address
      ]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery);
    });
  }, [overview, query]);

  if (loading && !overview) {
    return (
      <main className="app-shell">
        <section className="hero">
          <p className="eyebrow">PortScope</p>
          <h1>Scanning local ports...</h1>
          <p>Checking active listening services on this machine.</p>
        </section>
      </main>
    );
  }

  if (error && !overview) {
    return (
      <main className="app-shell">
        <section className="hero">
          <p className="eyebrow">PortScope</p>
          <h1>Scan unavailable</h1>
          <p>{error}</p>
          <button className="primary-button" onClick={loadPorts}>
            Try Again
          </button>
        </section>
      </main>
    );
  }

  if (!overview) return null;

  return (
    <main className="app-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">PortScope</p>
          <h1>Local Port Activity</h1>
          <p>
            A standalone local dashboard that scans listening TCP ports,
            identifies common services, and organizes everything into a clean
            developer-friendly view.
          </p>
        </div>

        <div className="terminal-card">
          <div className="terminal-dots">
            <span />
            <span />
            <span />
          </div>
          <code>{overview.commandUsed}</code>
        </div>
      </section>

      <section className="summary-grid">
        <SummaryCard label="Active Ports" value={overview.counts.activePorts} />
        <SummaryCard
          label="Common Ports Used"
          value={overview.counts.commonPortsUsed}
        />
        <SummaryCard
          label="High Risk"
          value={overview.counts.highRiskPorts}
        />
        <SummaryCard label="Categories" value={overview.counts.categories} />
      </section>

      <section className="meta-panel">
        <div>
          <span>Host</span>
          <strong>{overview.hostname}</strong>
        </div>
        <div>
          <span>Platform</span>
          <strong>{overview.platform}</strong>
        </div>
        <div>
          <span>Last Scan</span>
          <strong>{new Date(overview.inspectedAt).toLocaleTimeString()}</strong>
        </div>
      </section>

      <section className="toolbar">
        <div className="tabs">
          <button
            className={viewMode === "active" ? "active" : ""}
            onClick={() => setViewMode("active")}
          >
            Active Ports
          </button>

          <button
            className={viewMode === "common" ? "active" : ""}
            onClick={() => setViewMode("common")}
          >
            Common Ports
          </button>
        </div>

        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search port, process, PID, category..."
        />

        <button className="primary-button" onClick={loadPorts} disabled={loading}>
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </section>

      {viewMode === "active" ? (
        <section className="groups-wrapper">
          {filteredGroups.length === 0 ? (
            <EmptyState message="No active ports match your search." />
          ) : (
            filteredGroups.map((group) => (
              <div className="port-group" key={group.category}>
                <div className="group-header">
                  <h2>{group.category}</h2>
                  <span>
                    {group.ports.length} port
                    {group.ports.length === 1 ? "" : "s"}
                  </span>
                </div>

                <div className="port-card-grid">
                  {group.ports.map((port) => (
                    <PortCard
                      key={`${port.port}-${port.pid}-${port.address}`}
                      port={port}
                    />
                  ))}
                </div>
              </div>
            ))
          )}
        </section>
      ) : (
        <section className="common-panel">
          <div className="group-header">
            <h2>Common Port Reference</h2>
            <span>{filteredCommonPorts.length} shown</span>
          </div>

          <div className="common-table">
            {filteredCommonPorts.map((port) => (
              <CommonPortRow key={`${port.port}-${port.label}`} port={port} />
            ))}
          </div>
        </section>
      )}
    </main>
  );
}

function SummaryCard({ label, value }: { label: string; value: number }) {
  return (
    <article className="summary-card">
      <p>{label}</p>
      <strong>{value}</strong>
    </article>
  );
}

function PortCard({ port }: { port: ActivePort }) {
  return (
    <article className="port-card">
      <div className="port-card-header">
        <div>
          <p className="port-number">:{port.port}</p>
          <h3>{port.label}</h3>
        </div>

        <RiskPill riskLevel={port.riskLevel} />
      </div>

      <p className="port-description">{port.description}</p>

      <div className="port-details">
        <Detail label="Process" value={port.processName || "Unknown"} />
        <Detail label="PID" value={port.pid || "Unknown"} />
        <Detail label="Address" value={port.address || "Unknown"} />
        <Detail label="Protocol" value={port.protocol} />
      </div>
    </article>
  );
}

function CommonPortRow({ port }: { port: CommonReferencePort }) {
  return (
    <div className="common-row">
      <strong className="common-port">:{port.port}</strong>

      <div>
        <h3>{port.label}</h3>
        <p>{port.description}</p>
      </div>

      <span className="category-label">{port.category}</span>

      <div className="common-process">
        {port.status === "used" ? (
          <>
            <strong>{port.processName || "Unknown"}</strong>
            <span>{port.pid ? `PID ${port.pid}` : "PID unknown"}</span>
          </>
        ) : (
          <span>Available</span>
        )}
      </div>

      <span className={`status-pill ${port.status}`}>
        {port.status === "used" ? "Used" : "Free"}
      </span>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function RiskPill({ riskLevel }: { riskLevel: RiskLevel }) {
  return (
    <span className={`risk-pill risk-${riskLevel.toLowerCase()}`}>
      {riskLevel}
    </span>
  );
}

function EmptyState({ message }: { message: string }) {
  return <div className="empty-state">{message}</div>;
}