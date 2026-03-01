import { useMemo } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker
} from "react-simple-maps";

const geoUrl =
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export default function RealAttackMap({ logs }) {

  const attacks = useMemo(() => {
    return logs.filter(
      (l) =>
        l.status === "REPLAY_JTI" ||
        l.status === "BAD_SIGNATURE" ||
        l.status === "GEO_ANOMALY"
    );
  }, [logs]);

  return (
    <div className="bg-black rounded-xl p-4 border border-red-500/20">
      <h2 className="text-red-400 font-semibold mb-4">
        🌍 Live Attack Geolocation
      </h2>

      <ComposableMap projectionConfig={{ scale: 150 }}>
        <Geographies geography={geoUrl}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill="#0f172a"
                stroke="#1e293b"
              />
            ))
          }
        </Geographies>

        {attacks.map((a, i) => (
          <Marker
            key={i}
            coordinates={[
              a.geo?.lon || 0,
              a.geo?.lat || 0
            ]}
          >
            <circle
              r={6}
              fill="red"
              className="animate-ping"
            />
          </Marker>
        ))}
      </ComposableMap>
    </div>
  );
}