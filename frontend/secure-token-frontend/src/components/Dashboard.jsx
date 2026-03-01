import { useState, useEffect, useRef, useMemo } from "react";

import ThreatMeter from "../components/ThreatMeter";
import StatsBar from "../components/StatsBar";
import DeviceTable from "../components/DeviceTable";
import AuditFeed from "../components/AuditFeed";
import ControlPanel from "../components/ControlPanel";
import NetworkTopology from "../components/NetworkTopology";
import RiskChart from "../components/RiskChart";
import AttackBreakdown from "../components/AttackBreakdown";
import EscalationTimeline from "../components/EscalationTimeline";
import LogChainVisualizer from "../components/LogChainVisualizer";
import ExecutiveToggle from "../components/ExecutiveToggle";
import RealAttackMap from "../components/RealAttackMap";
import AttackGlobe from "./AttackGlobe";
import AnimatedAttackLines from "./AnimatedAttackLines";
import AIThreatPrediction from "./AIThreatPrediction";
import AIRiskPrediction from "./AIRiskPrediction";
import ThreatCluster from "./ThreatCluster";
import PulsingAttackHeatmap from "./PulsingAttackHeatmap";

export default function Dashboard() {
  const [logs, setLogs] = useState([]);
  const [threatLevel, setThreatLevel] = useState("NORMAL");
  const [riskScore, setRiskScore] = useState(0);
  const [mode, setMode] = useState("EXECUTIVE");
  const [riskHistory, setRiskHistory] = useState([]);

  const wsRef = useRef(null);

  useEffect(() => {
    let ws;

    const connect = () => {
      ws = new WebSocket("ws://localhost:8000/ws/audit");
      wsRef.current = ws;

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        setLogs((prev) => [data, ...prev].slice(0, 500));

        if (data.global_threat) {
          setThreatLevel(data.global_threat);
        }

        if (typeof data.global_risk === "number") {
          setRiskScore(data.global_risk);

          setRiskHistory((prev) => [
            ...prev.slice(-50),
            { time: Date.now(), value: data.global_risk },
          ]);
        }
      };

      ws.onclose = () => {
        setTimeout(connect, 2000);
      };
    };

    connect();

    return () => ws.close();
  }, []);

  const devices = useMemo(() => {
    const map = {};

    logs.forEach((log) => {
      if (!log.user_id || log.user_id === "SYSTEM") return;

      const key = `${log.user_id}-${log.device_id}`;

      map[key] = {
        user_id: log.user_id,
        device_id: log.device_id,
        risk_score: log.device_risk || 0,
        threat_level: log.device_threat || "NORMAL",
        status:
          log.status === "DEVICE_QUARANTINED" ? "QUARANTINED" : "ACTIVE",
      };
    });

    return Object.values(map);
  }, [logs]);

  const stats = {
    devices: devices.length,
    tokensIssued: logs.filter((l) => l.action === "ISSUE_TOKEN").length,
    replayAttacks: logs.filter((l) => l.status === "REPLAY_JTI").length,
  };

  return (
    <div className="min-h-screen bg-[#050816] text-white p-6">

      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold tracking-widest">
          🛡 Secure Token Gateway SOC
        </h1>

        <ExecutiveToggle mode={mode} setMode={setMode} />
      </div>

      <ThreatMeter level={threatLevel} score={riskScore} />

      <StatsBar stats={stats} />

      <EscalationTimeline logs={logs} />

      {mode === "EXECUTIVE" ? (
        <>

          <AttackGlobe logs={logs} />
          <div className="grid grid-cols-2 gap-6 mt-6">
              <AnimatedAttackLines logs={logs} />
              <AIThreatPrediction logs={logs} />
        </div>
          <NetworkTopology threatLevel={threatLevel} />
          <RiskChart riskHistory={riskHistory} />
          <AIRiskPrediction riskHistory={riskHistory} />

          <ThreatCluster logs={logs} />

          <PulsingAttackHeatmap logs={logs} />


          <AttackBreakdown logs={logs} />
        </>
      ) : (
        <>
          <DeviceTable devices={devices} />
          <LogChainVisualizer logs={logs} />
          <AuditFeed logs={logs} />
        </>
      )}

      <ControlPanel />
    </div>
  );
}