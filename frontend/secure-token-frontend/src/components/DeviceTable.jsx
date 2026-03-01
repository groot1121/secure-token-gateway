export default function DeviceTable({ devices }) {
  return (
    <div className="bg-[#0b1026] border border-[#1b2245] p-6 rounded-xl mb-6 overflow-x-auto">

      <h2 className="text-lg font-semibold mb-4">Device Registry</h2>

      <table className="w-full text-sm">

        <thead>
          <tr className="text-gray-400 border-b border-gray-700">
            <th className="text-left py-2">User</th>
            <th className="text-left py-2">Device</th>
            <th className="text-left py-2">Risk</th>
            <th className="text-left py-2">Threat</th>
            <th className="text-left py-2">Status</th>
          </tr>
        </thead>

        <tbody>
          {devices.map((d, i) => (
            <tr key={i} className="border-b border-gray-800">

              <td className="py-2">{d.user_id}</td>

              <td>{d.device_id}</td>

              <td>{Math.round(d.risk_score)}</td>

              <td>{d.threat_level}</td>

              <td className={d.status === "QUARANTINED" ? "text-red-400" : "text-green-400"}>
                {d.status}
              </td>

            </tr>
          ))}
        </tbody>

      </table>
    </div>
  );
}