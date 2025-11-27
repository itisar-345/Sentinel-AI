import React, { useState, useEffect } from 'react';
import { apiService, getSocket } from './services/api';
import Header from './components/Header';
import ConnectionStatus from './components/ConnectionStatus';
import StatsPanel from './components/StatsPanel';
import ControlButton from './components/ControlButton';
import LivePacketTable from './components/LivePacketTable';
import TrafficChart from './components/TrafficChart';
import BlockedIPs from './components/BlockedIPs';
import Footer from './components/Footer';
import { Packet } from './types';

export default function App() {
  const [connected, setConnected] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [packets, setPackets] = useState(0);
  const [pps, setPps] = useState(0);
  const [livePackets, setLivePackets] = useState<Packet[]>([]);
  const [trafficData, setTrafficData] = useState<
    Array<{ time: number; normalPps: number; maliciousPps: number; simulatedPps?: number }>
  >([]);
  const [blockedIPs, setBlockedIPs] = useState<any[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    const check = async () => {
      try {
        await apiService.healthCheck();
        setConnected(true);
        setError('');
      } catch {
        setConnected(false);
      }
    };
    check();
    const interval = setInterval(check, 2000);

    socket.on('connect', () => {
      setConnected(true);
      setError('');
    });

    socket.on('connect_error', () => {
      setConnected(false);
      setError('Reconnecting...');
    });

    socket.on('capture-started', () => {
      setCapturing(true);
      setPackets(0);
      setLivePackets([]);
    });

    socket.on('capture-stopped', () => setCapturing(false));

    socket.on('new_packet', (pkt: any) => {
      setPackets(p => p + 1);
      setPps(Math.floor(Math.random() * 50) + 10);

      const isMalicious = !!pkt.isMalicious;
      const isSimulated = !!pkt.packet_data?.simulated;
      const timestamp = pkt.timestamp || Date.now();
      const packetSize = pkt.packetSize ?? 1024;
      const detectionReason =
        pkt.detectionReason ||
        (isSimulated ? 'Simulated DDoS Attack (locust)' : 'Suspicious activity');

      const newPacket: Packet = {
        timestamp,
        srcIP: pkt.srcIP ?? '0.0.0.0',
        dstIP: pkt.dstIP ?? '0.0.0.0',
        protocol: pkt.protocol ?? 'TCP',
        packetSize,
        network_slice: pkt.network_slice ?? 'eMBB',
        isMalicious,
        detectionReason,
        confidence: pkt.confidence,
        packet_data: pkt.packet_data ?? {},
      };

      setLivePackets(prev => [newPacket, ...prev.slice(0, 19)]);

      setTrafficData(prev => {
        const now = Math.floor(Date.now() / 1000);
        const last = prev[prev.length - 1];

        if (!last || now > last.time) {
          return [
            ...prev.slice(-29),
            {
              time: now,
              normalPps: isMalicious ? 0 : 1,
              maliciousPps: isMalicious ? 1 : 0,
              simulatedPps: isMalicious && isSimulated ? 1 : 0,
            },
          ];
        }

        const updated = {
          ...last,
          normalPps: isMalicious ? last.normalPps : last.normalPps + 1,
          maliciousPps: isMalicious ? last.maliciousPps + 1 : last.maliciousPps,
          simulatedPps:
            isMalicious && isSimulated
              ? (last.simulatedPps ?? 0) + 1
              : last.simulatedPps ?? 0,
        };
        return [...prev.slice(0, -1), updated];
      });

      if (isMalicious) {
        setBlockedIPs(prev => {
          if (prev.some(i => i.ip === pkt.srcIP)) return prev;
          return [
            {
              ip: pkt.srcIP,
              timestamp: new Date().toISOString(),
              reason: detectionReason,
              threatLevel: isSimulated ? 'simulated' : 'high',
              mitigation: 'SDN DROP Rule',
              isSimulated,
              confidence: pkt.confidence,
            },
            ...prev,
          ];
        });
      }
    });

    socket.on('initial_blocked_ips', (ips: any[]) => setBlockedIPs(ips));
    socket.on('update_blocked_ips', (ips: any[]) => setBlockedIPs(ips));
    socket.on('ip_blocked', (ipData: any) =>
      setBlockedIPs(prev =>
        prev.some(i => i.ip === ipData.ip) ? prev : [...prev, ipData]
      )
    );
    socket.on('unblocked_ip', ({ ip }) =>
      setBlockedIPs(prev => prev.filter(b => b.ip !== ip))
    );

    return () => {
      clearInterval(interval);
      socket.off();
    };
  }, []);

  const toggleCapture = async () => {
    if (capturing) await apiService.stopPacketCapture();
    else await apiService.startPacketCapture('192.168.56.1');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-black to-gray-900 text-white p-8 font-sans">
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <Header />
          <ConnectionStatus connected={connected} error={error} />
        </div>

        <div className="flex flex-col md:flex-row gap-6 mb-8 items-center">
          <StatsPanel packets={packets} pps={pps} />
          <ControlButton capturing={capturing} onToggle={toggleCapture} />
        </div>

        <div className="mb-8">
          <div className="bg-gray-900 rounded-2xl p-6 border border-gray-800">
            <h3 className="text-xl font-bold mb-4">Live Packets</h3>
            <LivePacketTable packets={livePackets} capturing={capturing} />
          </div>
        </div>

        <div className="mb-8">
          <TrafficChart data={trafficData} />
        </div>

        <div className="mb-8">
          <BlockedIPs blockedIPs={blockedIPs} />
        </div>

        <Footer connected={connected} />
      </div>

      <style>{`
        .animate-count { transition: all 0.4s cubic-bezier(0.17,0.67,0.83,0.67); }
      `}</style>
    </div>
  );
}