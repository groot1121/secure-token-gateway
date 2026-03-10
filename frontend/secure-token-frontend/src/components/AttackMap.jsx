import { motion } from "framer-motion";

export default function AttackMap({ threatLevel }) {

  const active = threatLevel === "HIGH" || threatLevel === "ATTACK";

  return (

    <div className="bg-white/5 backdrop-blur-xl border border-white/10 p-6 rounded-xl mt-6 relative overflow-hidden">

      <h2 className="text-xl font-bold mb-4 text-red-400">
        📡 Live Attack Map
      </h2>

      <div className="relative h-64 bg-black rounded overflow-hidden">

        {active && (

          <>
            {/* Attack pulse 1 */}
            <motion.div
              className="absolute w-4 h-4 bg-red-500 rounded-full"
              animate={{ scale: [1,2,1], opacity: [1,0.3,1] }}
              transition={{ repeat: Infinity, duration: 1 }}
              style={{ top: "30%", left: "60%" }}
            />

            {/* Attack pulse 2 */}
            <motion.div
              className="absolute w-4 h-4 bg-red-500 rounded-full"
              animate={{ scale: [1,2,1], opacity: [1,0.3,1] }}
              transition={{ repeat: Infinity, duration: 1.2 }}
              style={{ top: "50%", left: "40%" }}
            />

            {/* Attack pulse 3 */}
            <motion.div
              className="absolute w-4 h-4 bg-red-500 rounded-full"
              animate={{ scale: [1,2,1], opacity: [1,0.3,1] }}
              transition={{ repeat: Infinity, duration: 0.9 }}
              style={{ top: "40%", left: "75%" }}
            />
          </>

        )}

        <div className="absolute inset-0 flex items-center justify-center text-gray-500 text-sm">
          Global Network Monitoring
        </div>

      </div>

    </div>

  );

}