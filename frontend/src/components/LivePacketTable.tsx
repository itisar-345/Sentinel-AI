import React from 'react';
import { Packet } from '../types'; // Use your types/index.ts
import { AlertTriangle, Shield } from 'lucide-react';

// === PROTOCOL → COLOR MAPPING ===
const PROTOCOL_COLORS: Record<string, string> = {
  TCP: 'bg-emerald-600 text-white',
  UDP: 'bg-blue-600 text-white',
  ICMP: 'bg-yellow-600 text-white',
  IGMP: 'bg-orange-600 text-white',
  OSPF: 'bg-purple-600 text-white',
  ESP: 'bg-red-600 text-white',
  AH: 'bg-pink-600 text-white',
  IPv6: 'bg-indigo-600 text-white',
  default: 'bg-gray-600 text-white',
};

const getProtocolColor = (protocol: string) => {
  return PROTOCOL_COLORS[protocol.toUpperCase()] || PROTOCOL_COLORS.default;
};

// === IST TIME FORMATTER ===
const formatISTTime = (timestamp: number) => {
  const date = new Date(timestamp);
  // Convert to IST (UTC + 5:30)
  const istOffset = 5.5 * 60 * 60 * 1000;
  const istTime = new Date(date.getTime() + istOffset);

  return istTime.toLocaleTimeString('en-US', {
    timeZone: 'Asia/Kolkata',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  });
};

export default function LivePacketTable({
  packets,
  capturing,
}: {
  packets: Packet[];
  capturing: boolean;
}) {
  if (packets.length === 0) {
    return (
      <div className="text-center text-gray-500 py-8 bg-gray-900/50 rounded-xl">
        {capturing ? (
          <div className="flex flex-col items-center justify-center space-y-3">
            <div className="animate-pulse">
              <div className="w-16 h-16 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
            </div>
            <p className="text-sm">Capturing network traffic...</p>
          </div>
        ) : (
          <p className="text-sm">Start capture to see live packets</p>
        )}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto max-h-64">
      <table className="min-w-full text-sm font-mono border-collapse bg-gray-800 rounded-xl shadow-lg overflow-hidden">
        <thead>
          <tr className="bg-gradient-to-r from-cyan-600 to-purple-700 sticky top-0 text-white">
            <th className="px-4 py-3 text-left font-semibold">Time (IST)</th>
            <th className="px-4 py-3 text-left font-semibold">Source</th>
            <th className="px-4 py-3 text-left font-semibold">Destination</th>
            <th className="px-4 py-3 text-left font-semibold">Protocol</th>
            <th className="px-4 py-3 text-left font-semibold">Slice</th>
            <th className="px-4 py-3 text-left font-semibold">Size</th>
            <th className="px-4 py-3 text-left font-semibold">
              <div className="flex items-center gap-3">
                Detection
                
              </div>
            </th>
          </tr>
        </thead>
        <tbody>
          {packets.map((p, idx) => {
            const isSimulated = p.packet_data?.simulated === true;
            const isMalicious = p.isMalicious === true;
            const protoColor = getProtocolColor(p.protocol);

            return (
              <tr
                key={idx}
                className={`transition-all duration-200 border-b ${
                  isMalicious
                    ? isSimulated
                      ? 'bg-purple-900/20 hover:bg-purple-900/30 border-l-4 border-l-purple-500'
                      : 'bg-red-900/20 hover:bg-red-900/30 border-l-4 border-l-red-500'
                    : 'border-gray-700 hover:bg-cyan-900/10'
                }`}
              >
                {/* Time in IST */}
                <td className="px-4 py-2 text-gray-300 text-xs font-medium">
                  {formatISTTime(p.timestamp)}
                </td>

                {/* Source IP with icon */}
                <td className="px-4 py-2">
                  <div className="flex items-center gap-1.5">
                    {isMalicious && isSimulated && (
                      <Shield className="w-3.5 h-3.5 text-purple-400" />
                    )}
                    {isMalicious && !isSimulated && (
                      <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                    )}
                    <span
                      className={`font-mono text-sm ${
                        isMalicious
                          ? isSimulated
                            ? 'text-purple-300'
                            : 'text-red-300'
                          : 'text-orange-300'
                      }`}
                    >
                      {p.srcIP}
                    </span>
                  </div>
                </td>

                {/* Destination IP */}
                <td className="px-4 py-2 text-purple-300 font-mono text-sm">
                  {p.dstIP}
                </td>

                {/* Protocol Badge */}
                <td className="px-4 py-2">
                  <span
                    className={`px-2.5 py-1 rounded font-bold text-xs tracking-wider ${protoColor}`}
                  >
                    {p.protocol}
                  </span>
                </td>

                {/* Network Slice Badge */}
                <td className="px-4 py-2">
                  <span
                    className={`px-2 py-1 rounded text-white text-xs font-medium ${
                      p.network_slice === 'eMBB'
                        ? 'bg-purple-700/80'
                        : p.network_slice === 'URLLC'
                        ? 'bg-blue-600/80'
                        : 'bg-green-600/80'
                    }`}
                  >
                    {p.network_slice || 'eMBB'}
                  </span>
                </td>

                {/* Packet Size */}
                <td className="px-4 py-2 text-gray-200 font-mono text-sm">
                  {p.packetSize}B
                </td>

                {/* Detection Status */}
                <td className="px-4 py-2">
                  {isMalicious ? (
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`px-2.5 py-1 rounded text-white text-xs font-bold flex items-center gap-1.5 ${
                          isSimulated
                            ? 'bg-purple-600/90'
                            : 'bg-red-500/90'
                        }`}
                      >
                        {isSimulated ? (
                          <Shield className="w-3.5 h-3.5" />
                        ) : (
                          <AlertTriangle className="w-3.5 h-3.5" />
                        )}
                        Malicious
                        {p.confidence !== undefined && (
                          <span className="ml-1 opacity-90">
                            ({(p.confidence * 100).toFixed(0)}%)
                          </span>
                        )}
                      </span>
                    </div>
                  ) : (
                    <span className="px-2.5 py-1 bg-green-500/80 rounded text-white text-xs font-bold">
                      Normal
                      {p.confidence !== undefined && (
                        <span className="ml-1 opacity-80">
                          ({((1 - p.confidence) * 100).toFixed(0)}%)
                        </span>
                      )}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}