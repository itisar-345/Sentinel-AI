// frontend/src/services/api.ts - UPDATED FOR LAPTOP (localhost:3000)
import axios from 'axios';
import { io, Socket } from 'socket.io-client';

const getBackendUrl = () => {
  const host = window.location.hostname;
  if (host === '192.168.56.1' || host.includes('192.168.56')) {
    return 'http://192.168.56.1:3000';  // VM view to laptop backend
  }
  return 'http://localhost:3000';  // Laptop local
};

const BACKEND_URL = getBackendUrl();

let socket: Socket | null = null;

export const initializeWebSocket = (): Socket => {
  if (!socket || !socket.connected) {
    socket = io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      reconnectionAttempts: 10,
      timeout: 10000,
      forceNew: true
    });
  }
  return socket;
};

export const getSocket = (): Socket | null => socket;

// Initialize
initializeWebSocket();

const api = axios.create({
  baseURL: `${BACKEND_URL}/api`,
  timeout: 10000,
});

export interface DetectionRequest {
  traffic: number[];
  ip: string;
  packet_data: {
    packet_rate: number;
    avg_packet_size: number;
  };
  network_slice: string;
}

export interface DetectionResponse {
  prediction: string;
  confidence: number;
  abuseScore: number;
  isDDoS: boolean;
  ensemble_score?: number;
  threat_level?: string;
  ddos_indicators?: number;
  slice_recommendation?: { action: string };
  network_analysis?: any;
  selected_model?: string;
  confidence_factors?: string[];
}

export const apiService = {
  healthCheck: async () => {
    const res = await api.get('/health');
    return res.data.status === 'OK';
  },

  getLocalIPs: async () => {
    try {
      const res = await api.get('/local-ips');
      return res.data;
    } catch {
      return [
        { interface: 'Laptop-ETH', address: '192.168.56.1' },
        { interface: 'VM-ETH', address: '192.168.56.101' }
      ];
    }
  },

  startPacketCapture: (ip: string, iface?: string) =>
    api.post('/start-capture', { targetIP: ip, iface }),

  stopPacketCapture: () => api.post('/stop-capture'),

  getCaptureStatus: () => api.get('/capture-status'),

  getSystemStatus: async () => ({
    ml_model_status: 'connected',
    capture_active: false
  }),

  detectDDoS: async (request: DetectionRequest): Promise<DetectionResponse> => {
    // Simulate or call Flask directly if needed
    return {
      prediction: Math.random() > 0.7 ? 'ddos' : 'normal',
      confidence: Math.random(),
      abuseScore: Math.floor(Math.random() * 80),
      isDDoS: Math.random() > 0.7,
      ensemble_score: Math.random(),
      threat_level: Math.random() > 0.8 ? 'HIGH' : 'LOW',
      ddos_indicators: Math.floor(Math.random() * 5),
      slice_recommendation: { action: 'Monitor' },
      network_analysis: {
        max_traffic: Math.floor(Math.random() * 1000),
        avg_traffic: Math.floor(Math.random() * 500),
        bandwidth_utilization_mbps: Math.floor(Math.random() * 100)
      },
      selected_model: 'ENHANCED_FALLBACK',
      confidence_factors: ['IP reputation', 'Packet rate']
    };
  }
};

export const handleApiError = (error: any) => {
  if (axios.isAxiosError(error)) {
    return error.response?.data?.error || 'Network error';
  }
  return 'Unknown error';
};