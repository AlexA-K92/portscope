export type RiskLevel = "Low" | "Medium" | "High";

export type ActivePort = {
  port: number;
  protocol: string;
  address: string;
  processName: string;
  pid: string;
  user: string;
  raw: string;
  label: string;
  category: string;
  description: string;
  riskLevel: RiskLevel;
  isCommon: boolean;
};

export type PortGroup = {
  category: string;
  ports: ActivePort[];
};

export type CommonReferencePort = {
  port: number;
  label: string;
  category: string;
  description: string;
  riskLevel: RiskLevel;
  status: "used" | "free";
  processName: string;
  pid: string;
  address: string;
};

export type PortOverview = {
  inspectedAt: string;
  hostname: string;
  platform: string;
  commandUsed: string;
  counts: {
    activePorts: number;
    commonPortsUsed: number;
    highRiskPorts: number;
    categories: number;
  };
  activePorts: ActivePort[];
  groups: PortGroup[];
  commonReference: CommonReferencePort[];
};

export async function getPortOverview(): Promise<PortOverview> {
  const response = await fetch("/api/ports");

  if (!response.ok) {
    throw new Error("Failed to fetch port overview");
  }

  return response.json();
}