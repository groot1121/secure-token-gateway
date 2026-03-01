import { Canvas, useFrame } from "@react-three/fiber";
import { Sphere, OrbitControls, Stars } from "@react-three/drei";
import { useRef } from "react";

function RotatingGlobe() {
  const ref = useRef();

  useFrame(() => {
    ref.current.rotation.y += 0.002;
  });

  return (
    <Sphere ref={ref} args={[2, 64, 64]}>
      <meshStandardMaterial
        color="#0ea5e9"
        wireframe
        emissive="#0ea5e9"
        emissiveIntensity={0.6}
      />
    </Sphere>
  );
}

export default function GlobeNetwork() {
  return (
    <div className="bg-white/5 backdrop-blur-xl border border-white/10 p-6 rounded-xl mt-6 h-[400px]">
      <h2 className="text-xl font-bold mb-4 text-cyan-400">
        🌍 Global Attack Surface
      </h2>

      <Canvas camera={{ position: [0, 0, 6] }}>
        <ambientLight intensity={0.5} />
        <pointLight position={[10, 10, 10]} />
        <Stars />
        <RotatingGlobe />
        <OrbitControls enableZoom={false} />
      </Canvas>
    </div>
  );
}