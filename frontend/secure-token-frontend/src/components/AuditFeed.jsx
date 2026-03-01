export default function AuditFeed({ logs }) {
  return (
    <div className="bg-blue-900 rounded-xl p-4 h-[400px] overflow-y-auto">
      <h2 className="font-bold mb-3">Live Audit Feed</h2>

      {logs.map((log, index) => (
        <div
          key={index}
          className={`mb-2 p-2 rounded-lg text-sm ${
            log.action === "ACCESS_DENIED"
              ? "bg-red-700"
              : "bg-green-700"
          }`}
        >
          {log.action} ({log.status})
        </div>
      ))}
    </div>
  );
}