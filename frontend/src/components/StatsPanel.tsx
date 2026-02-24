import React from 'react';

interface Props {
  packets: number;
  pps: number;
}

export default function StatsPanel({ packets, pps }: Props) {
  return (
    <div className="grid grid-cols-2 gap-6 flex-1">
      <div className="bg-gray-900 p-4 rounded-xl border border-gray-700 text-center shadow hover:shadow-cyan-500/40 transition">
        <div className="text-3xl font-bold text-cyan-200 animate-count">
          {packets.toLocaleString()}
        </div>
        <div className="text-gray-200 text-sm">Packets Captured</div>
      </div>

      <div className="bg-gray-900 p-4 rounded-xl border border-gray-700 text-center shadow hover:shadow-green-500/40 transition">
        <div className="text-3xl font-bold text-green-200 animate-count">
          {pps}
        </div>
        <div className="text-gray-200 text-sm">Packets/sec</div>
      </div>
    </div>
  );
}