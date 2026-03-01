export default function ExecutiveToggle({ mode, setMode }) {
  return (
    <div className="flex gap-4">
      <button
        onClick={() => setMode("EXECUTIVE")}
        className={`px-4 py-2 rounded ${
          mode === "EXECUTIVE"
            ? "bg-green-600"
            : "bg-gray-700"
        }`}
      >
        Executive View
      </button>

      <button
        onClick={() => setMode("ANALYST")}
        className={`px-4 py-2 rounded ${
          mode === "ANALYST"
            ? "bg-red-600"
            : "bg-gray-700"
        }`}
      >
        Analyst View
      </button>
    </div>
  );
}