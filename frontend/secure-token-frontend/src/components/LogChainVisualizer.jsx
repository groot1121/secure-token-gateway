import sha256 from "crypto-js/sha256";

export default function LogChainVisualizer({ logs }) {

  const chain = logs.slice(0, 5).reverse().map((log, index, arr) => {
    const previousHash =
      index === 0 ? "GENESIS" : sha256(JSON.stringify(arr[index - 1])).toString();
    const currentHash = sha256(JSON.stringify(log)).toString();

    return {
      ...log,
      previousHash,
      currentHash,
    };
  });

  return (
    <div className="bg-white/5 p-6 rounded-xl mt-6">
      <h2 className="text-xl font-bold text-cyan-400 mb-4">
        🔗 Immutable Log Chain
      </h2>

      <div className="space-y-4">
        {chain.map((block, idx) => (
          <div
            key={idx}
            className="bg-black border border-gray-700 p-4 rounded"
          >
            <div className="text-sm text-gray-400">
              Prev Hash:
            </div>
            <div className="text-xs break-all text-gray-500">
              {block.previousHash}
            </div>

            <div className="text-sm text-gray-400 mt-2">
              Current Hash:
            </div>
            <div className="text-xs break-all text-green-400">
              {block.currentHash}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}