import { motion } from "framer-motion";

const endpoints = [
  "Register Device",
  "Issue Token",
  "Protected Resource",
  "Rotate Token",
];

export default function EndpointList({ selected, onSelect }) {
  return (
    <div className="bg-blue-950 p-4 rounded-xl">
      <h2 className="text-xl font-semibold mb-4">Endpoints</h2>

      {endpoints.map((ep) => (
        <motion.div
          key={ep}
          whileHover={{ scale: 1.05 }}
          className={`p-3 mb-2 rounded-lg cursor-pointer ${
            selected === ep ? "bg-blue-700" : "bg-blue-900"
          }`}
          onClick={() => onSelect(ep)}
        >
          {ep}
        </motion.div>
      ))}
    </div>
  );
}