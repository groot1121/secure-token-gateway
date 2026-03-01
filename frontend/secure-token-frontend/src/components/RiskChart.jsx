import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer
} from "recharts";

export default function RiskChart({ riskHistory }) {

  return (
    <div className="bg-[#020617] p-6 rounded-xl border border-slate-700">

      <h2 className="text-white mb-4">
        Global Risk Evolution
      </h2>

      <ResponsiveContainer width="100%" height={250}>
        <LineChart data={riskHistory}>

          <XAxis
            dataKey="time"
            tickFormatter={(t) =>
              new Date(t).toLocaleTimeString()
            }
          />

          <YAxis />

          <Tooltip />

          <Line
            type="monotone"
            dataKey="value"
            stroke="#ef4444"
            strokeWidth={2}
            dot={false}
          />

        </LineChart>
      </ResponsiveContainer>

    </div>
  );
}