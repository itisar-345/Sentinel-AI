export interface Packet {
  timestamp: number;
  srcIP: string;
  dstIP: string;
  protocol: string;
  network_slice?: string;
  packetSize: number;
  isMalicious?: boolean;
  detectionReason?: string;
  confidence?: number;
  packet_data?: {
    simulated?: boolean;
    avg_packet_size?: number;
    [key: string]: any;
  };
}