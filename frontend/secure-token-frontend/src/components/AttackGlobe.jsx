import { useMemo } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  Line,
} from "react-simple-maps";

const geoUrl =
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// simple geo lookup mock
const countryCoords = {
  India: [78.9629, 20.5937],
  USA: [-95.7129, 37.0902],
  China: [104.1954, 35.8617],
  Russia: [105.3188, 61.524],
  Germany: [10.4515, 51.1657],
  Brazil: [-51.9253, -14.235],
};

export default function AttackGlobe({ logs }) {
  const attacks = useMemo(() => {
    return logs
      .filter(
        (l) =>
          l.status === "REPLAY_JTI" ||
          l.status === "GEO_ANOMALY" ||
          l.status === "TOKEN_REVOKED"
      )
      .slice(0, 20)
      .map((log) => {
        const source =
          countryCoords[log.payload?.country] ||
          countryCoords["USA"];

        const target = countryCoords["India"];

        return { source, target };
      });
  }, [logs]);

  return (
    <div className="bg-[#0b1026] rounded-xl p-4 shadow-lg">
      <h2 className="text-xl font-semibold mb-4 text-red-400">
        Global Attack Map
      </h2>

      <ComposableMap projectionConfig={{ scale: 140 }}>
        <Geographies geography={geoUrl}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="#111827"
                stroke="#1f2937"
                style={{
                  default: { outline: "none" },
                  hover: { fill: "#1f2937", outline: "none" },
                  pressed: { outline: "none" },
                }}
              />
            ))
          }
        </Geographies>

        {attacks.map((attack, i) => (
          <Line
            key={i}
            from={attack.source}
            to={attack.target}
            stroke="#ff3b3b"
            strokeWidth={1.5}
            strokeLinecap="round"
          />
        ))}

        {attacks.map((attack, i) => (
          <Marker key={`src-${i}`} coordinates={attack.source}>
            <circle r={3} fill="#ff0000" />
          </Marker>
        ))}

        {attacks.map((attack, i) => (
          <Marker key={`dst-${i}`} coordinates={attack.target}>
            <circle r={4} fill="#00ff9d" />
          </Marker>
        ))}
      </ComposableMap>
    </div>
  );
}