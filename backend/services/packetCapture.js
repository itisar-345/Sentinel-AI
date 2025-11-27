// packetCapture.js
const { spawn } = require('child_process');
const EventEmitter = require('events');
const axios = require('axios');

class PacketCapture extends EventEmitter {
  constructor() {
    super();
    this.isCapturing = false;
    this.tsharkProcess = null;
    this.flowWindow = [];
    this.windowDuration = 60000; // 60 seconds
    this.tsharkPath = 'C:\\Program Files\\Wireshark\\tshark.exe';
    this.mlEndpoint = 'http://localhost:5001/process-packet';
  }

  startCapture(targetIP, interfaceName) {
    if (this.isCapturing) return;
    
    this.isCapturing = true;
    this.flowWindow = [];
    this.captureStartTime = Date.now();
    
    // Extended fields for better feature extraction
    const args = [
      '-i', interfaceName,
      '-f', `host ${targetIP}`,
      '-l',
      '-T', 'fields',
      '-e', 'frame.time_epoch',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', '_ws.col.Protocol',
      '-e', 'tcp.srcport',
      '-e', 'tcp.dstport',
      '-e', 'udp.srcport',
      '-e', 'udp.dstport',
      '-e', 'frame.len',
      '-e', 'tcp.flags.syn',
      '-e', 'tcp.flags.fin',
      '-e', 'tcp.flags.reset',
      '-e', 'tcp.flags.push',
      '-e', 'tcp.flags.ack',
      '-e', 'tcp.flags.urg',
      '-e', 'tcp.flags.ece',
      '-e', 'tcp.flags.cwr',
      '-e', 'tcp.window_size',
      '-e', 'ip.hdr_len',
      '-e', 'tcp.hdr_len'
    ];
    
    console.log(`Starting tshark capture: ${this.tsharkPath} ${args.join(' ')}`);
    
    try {
      this.tsharkProcess = spawn(this.tsharkPath, args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true // Hide console window on Windows
      });
      
      this.tsharkProcess.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        lines.forEach(line => {
          if (line.trim()) {
            this.processPacketLine(line.trim(), targetIP);
          }
        });
      });
      
      this.tsharkProcess.stderr.on('data', (data) => {
        const errorMsg = data.toString();
        console.error('tshark stderr:', errorMsg);
        if (errorMsg.includes('No such device') || errorMsg.includes('permission denied')) {
          this.emit('error', new Error('Interface access error'));
          this.stopCapture();
        }
      });
      
      this.tsharkProcess.on('close', (code) => {
        console.log(`tshark process exited with code ${code}`);
        this.isCapturing = false;
      });
      
      // Periodic flow analysis
      this.flowInterval = setInterval(() => this.analyzeFlows(), 5000);
      
    } catch (error) {
      console.error('Failed to start tshark:', error);
      this.emit('error', error);
      this.isCapturing = false;
    }
  }

  processPacketLine(line, targetIP) {
    const fields = line.split('\t').map(f => f.trim());
    
    if (fields.length < 9) {
      console.warn('Incomplete packet data:', fields);
      return;
    }
    
    const protocol = fields[3].toUpperCase();
    const isTCP = protocol === 'TCP';
    const isUDP = protocol === 'UDP';
    const isICMP = protocol === 'ICMP';
    
    const packet = {
      timestamp: parseFloat(fields[0]) * 1000, // Convert to ms
      src_ip: fields[1],
      dst_ip: fields[2],
      protocol: isTCP ? 6 : isUDP ? 17 : isICMP ? 1 : 0,
      src_port: parseInt(isTCP ? fields[4] : isUDP ? fields[6] : 0),
      dst_port: parseInt(isTCP ? fields[5] : isUDP ? fields[7] : 0),
      size: parseInt(fields[8]),
      flags: isTCP ? {
        syn: fields[9] === '1',
        fin: fields[10] === '1',
        reset: fields[11] === '1',
        push: fields[12] === '1',
        ack: fields[13] === '1',
        urg: fields[14] === '1',
        ece: fields[15] === '1',
        cwr: fields[16] === '1'
      } : {},
      window_size: isTCP ? parseInt(fields[17]) : 0,
      ip_hdr_len: parseInt(fields[18]),
      tcp_hdr_len: isTCP ? parseInt(fields[19]) : 0
    };
    
    // Add to flow window
    this.flowWindow.push(packet);
    
    // Clean old packets
    const now = Date.now();
    this.flowWindow = this.flowWindow.filter(p => now - p.timestamp < this.windowDuration);
    
    // Send to ML endpoint
    this.sendToML(packet);
    
    this.emit('packet', packet);
  }

  async sendToML(packet) {
    try {
      await axios.post(this.mlEndpoint, { packet });
      console.log(`Sent packet from ${packet.src_ip} to ML for analysis`);
    } catch (error) {
      console.error('Failed to send packet to ML:', error.message);
    }
  }

  analyzeFlows() {
    const now = Date.now();
    const recentPackets = this.flowWindow.filter(p => now - p.timestamp < 5000);
    
    if (recentPackets.length > 0) {
      const flows = this.groupByFlow(recentPackets);
      const stats = this.calculateFlowStats(flows);
      this.emit('flow_stats', stats);
    }
  }

  groupByFlow(packets) {
    const flows = new Map();
    
    packets.forEach(p => {
      const key = `${p.src_ip}:${p.src_port}->${p.dst_ip}:${p.dst_port}:${p.protocol}`;
      if (!flows.has(key)) {
        flows.set(key, {
          srcIP: p.src_ip,
          dstIP: p.dst_ip,
          srcPort: p.src_port,
          dstPort: p.dst_port,
          protocol: p.protocol,
          packets: [],
          totalBytes: 0
        });
      }
      const flow = flows.get(key);
      flow.packets.push(p);
      flow.totalBytes += p.size;
    });
    
    return Array.from(flows.values());
  }

  calculateFlowStats(flows) {
    let totalPackets = 0;
    let totalBytes = 0;
    let srcPorts = new Set();
    let dstPorts = new Set();
    let protocols = new Set();
    let packetSizes = [];
    let interArrivalTimes = [];
    
    flows.forEach(flow => {
      totalPackets += flow.packets.length;
      totalBytes += flow.totalBytes;
      srcPorts.add(flow.srcPort);
      dstPorts.add(flow.dstPort);
      protocols.add(flow.protocol);
      
      flow.packets.forEach(p => packetSizes.push(p.size));
      
      const sortedPackets = flow.packets.sort((a,b) => a.timestamp - b.timestamp);
      for (let i = 1; i < sortedPackets.length; i++) {
        interArrivalTimes.push((sortedPackets[i].timestamp - sortedPackets[i-1].timestamp) / 1000);
      }
    });
    
    const duration = flows.reduce((max, flow) => {
      const flowDuration = flow.packets.length > 0 ? 
        Math.max(...flow.packets.map(p => p.timestamp)) - Math.min(...flow.packets.map(p => p.timestamp)) : 0;
      return Math.max(max, flowDuration);
    }, 0) / 1000;

    return {
      duration: Math.max(duration, 1),
      total_packets: totalPackets,
      total_bytes: totalBytes,
      packets_per_second: totalPackets / Math.max(duration, 1),
      bytes_per_second: totalBytes / Math.max(duration, 1),
      avg_packet_size: packetSizes.length > 0 ? packetSizes.reduce((a, b) => a + b, 0) / packetSizes.length : 0,
      std_packet_size: this.calculateStd(packetSizes),
      min_packet_size: packetSizes.length > 0 ? Math.min(...packetSizes) : 0,
      max_packet_size: packetSizes.length > 0 ? Math.max(...packetSizes) : 0,
      avg_iat: interArrivalTimes.length > 0 ? interArrivalTimes.reduce((a, b) => a + b, 0) / interArrivalTimes.length : 0,
      std_iat: this.calculateStd(interArrivalTimes),
      unique_src_ports: srcPorts.size,
      unique_dst_ports: dstPorts.size,
      unique_protocols: protocols.size,
      is_tcp: protocols.has(6),
      is_udp: protocols.has(17),
      is_icmp: protocols.has(1),
      flows: flows.map(f => ({
        src_ip: f.srcIP,
        dst_ip: f.dstIP,
        protocol: f.protocol === 6 ? 'TCP' : f.protocol === 17 ? 'UDP' : f.protocol === 1 ? 'ICMP' : 'Unknown',
        packets: f.packets.length,
        bytes: f.totalBytes
      }))
    };
  }

  calculateStd(values) {
    if (values.length <= 1) return 0;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
  }

  getFlowWindow() {
    return this.flowWindow;
  }

  stopCapture() {
    this.isCapturing = false;
    
    if (this.tsharkProcess) {
      // Gracefully terminate tshark
      this.tsharkProcess.kill('SIGTERM');
      
      // Force kill if not terminated within 3 seconds
      setTimeout(() => {
        if (this.tsharkProcess && !this.tsharkProcess.killed) {
          this.tsharkProcess.kill('SIGKILL');
        }
      }, 3000);
      
      this.tsharkProcess = null;
    }
    
    if (this.flowInterval) {
      clearInterval(this.flowInterval);
      this.flowInterval = null;
    }
    
    // Clear flow window
    this.flowWindow = [];
    
    console.log('Packet capture stopped');
    this.emit('capture_stopped');
  }
}

module.exports = PacketCapture;