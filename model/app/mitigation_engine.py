# mitigation_engine.py
import logging
import time
from datetime import datetime
from typing import Dict, List
from sdn_controller import SDNController
from performance_cache import performance_monitor

class MitigationEngine:
    def __init__(self, sdn_controller: SDNController):
        self.sdn_controller = sdn_controller
        self.logger = logging.getLogger(__name__)
        self.blocked_ips: Dict[str, dict] = {}
        self.mitigation_history: List[dict] = []

        self.config = {
            'default_switch_id': 1,
            'ddos_threshold': 0.5,
            'block_duration': 3600,
            'max_history': 1000,
            'check_interval': 60
        }
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        import threading
        def cleanup_loop():
            while True:
                self._cleanup_expired_blocks()
                time.sleep(self.config['check_interval'])
        threading.Thread(target=cleanup_loop, daemon=True).start()

    def _cleanup_expired_blocks(self):
        now = time.time()
        expired = [ip for ip, d in self.blocked_ips.items() if now - d['timestamp'] > self.config['block_duration']]
        for ip in expired:
            self.unblock_ip(ip)
            self.logger.info(f"Block expired for IP: {ip}")

        if len(self.mitigation_history) > self.config['max_history']:
            self.mitigation_history = self.mitigation_history[-self.config['max_history']:]

    def is_ip_blocked(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            self.blocked_ips[ip]['last_seen'] = time.time()
            self.blocked_ips[ip]['packets_blocked'] += 1
            return True
        return False

    @performance_monitor
    def execute_mitigation(self, detection_result: dict, flow_info: dict) -> dict:
        src_ip = flow_info.get('src_ip', 'unknown')
        if src_ip in ('unknown', '0.0.0.0'):
            return {"status": "error", "message": "Invalid IP", "mitigation_applied": False}

        if self.is_ip_blocked(src_ip):
            return {
                "status": "already_blocked",
                "ip": src_ip,
                "since": datetime.fromtimestamp(self.blocked_ips[src_ip]['timestamp']).isoformat(),
                "packets_blocked": self.blocked_ips[src_ip]['packets_blocked'],
                "mitigation_applied": False
            }

        is_ddos = detection_result.get('prediction', '').lower() == 'ddos'
        confidence = float(detection_result.get('confidence', 0.0))

        if is_ddos and confidence >= self.config['ddos_threshold']:
            if self.block_ip(src_ip, 'DDoS detected', confidence):
                self.mitigation_history.append({
                    'timestamp': time.time(),
                    'ip': src_ip,
                    'confidence': confidence,
                    'action': 'BLOCKED',
                    'details': flow_info
                })
                return {
                    "status": "blocked",
                    "ip": src_ip,
                    "confidence": confidence,
                    "timestamp": datetime.now().isoformat(),
                    "mitigation_applied": True
                }
            else:
                return {"status": "block_failed", "ip": src_ip, "mitigation_applied": False}

        return {"status": "normal", "ip": src_ip, "confidence": confidence, "mitigation_applied": False}

    def block_ip(self, ip: str, reason: str = 'DDoS Detection', confidence: float = 0.0) -> bool:
        if not ip or ip in ("0.0.0.0", "unknown"):
            self.logger.warning(f"block_ip refused invalid IP: {ip}")
            return False

        self.logger.info(f"BLOCKING IP {ip} (reason: {reason}, confidence: {confidence*100:.1f}%)")
        success = self.sdn_controller.block_ip(ip)

        if success:
            self.blocked_ips[ip] = {
                "timestamp": time.time(),
                "confidence": confidence,
                "packets_blocked": 0,
                "reason": reason,
                "last_seen": time.time()
            }
            self.logger.info(f"SUCCESSFULLY blocked {ip}")
        else:
            self.logger.warning(f"Failed to block {ip}")

        return success

    def unblock_ip(self, ip: str) -> bool:
        if ip not in self.blocked_ips:
            return False
        success = self.sdn_controller.unblock_ip(ip)
        if success:
            del self.blocked_ips[ip]
            self.logger.info(f"SUCCESSFULLY unblocked {ip}")
        return success

    def get_blocked_ips(self) -> List[dict]:
        return [
            {
                "ip": ip,
                "timestamp": datetime.fromtimestamp(d["timestamp"]).isoformat(),
                "reason": d["reason"],
                "confidence": d["confidence"],
                "packets_blocked": d["packets_blocked"],
                "last_seen": datetime.fromtimestamp(d["last_seen"]).isoformat()
            }
            for ip, d in self.blocked_ips.items()
        ]

    def get_mitigation_history(self, limit: int = 50) -> List[dict]:
        return self.mitigation_history[-limit:]