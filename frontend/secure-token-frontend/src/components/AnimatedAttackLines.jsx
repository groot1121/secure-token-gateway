import { ComposableMap, Geographies, Geography, Line } from "react-simple-maps";
import { useEffect, useState } from "react";

const geoUrl =
  "https://raw.githubusercontent.com/deldersveld/topojson/master/world-countries.json";

export default function AnimatedAttackLines({ logs }) {
  const [attacks, setAttacks] = useState([]);

  useEffect(() => {
    const newAttacks = logs
      .filter((l) => l.status === "REPLAY_JTI" || l.status === "REPLAY_ATTACK")
      .slice(0, 20)
      .map(() => ({
        from: [Math.random() * 360 - 180, Math.random() * 180 - 90],
        to: [Math.random() * 360 - 180, Math.random() * 180 - 90],
      }));

    setAttacks(newAttacks);
  }, [logs]);

  return (
    <div className="bg-[#0a0f2c] rounded-xl p-4 shadow-lg">
      <h2 className="text-lg mb-2 text-red-400 font-semibold">
        Live Attack Vectors
      </h2>

      <ComposableMap projectionConfig={{ scale: 150 }}>
        <Geographies geography={geoUrl}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="#0b1736"
                stroke="#1a2b55"
                strokeWidth={0.5}
              />
            ))
          }
        </Geographies>

        {attacks.map((a, i) => (
          <Line
            key={i}
            from={a.from}
            to={a.to}
            stroke="#ff4d4d"
            strokeWidth={2}
            strokeLinecap="round"
            style={{
              animation: "dash 2s linear infinite",
            }}
          />
        ))}
      </ComposableMap>
    </div>
  );
}