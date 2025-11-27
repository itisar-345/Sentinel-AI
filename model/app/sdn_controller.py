# sdn_controller.py
import requests
import logging

log = logging.getLogger(__name__)

class SDNController:
    def __init__(self, host='127.0.0.1', port=8080):
        self.base_url = f"http://{host}:{port}"
        log.info(f"SDNController → Ryu at {self.base_url}")
        self._check_connection()

    def _check_connection(self):
        try:
            r = requests.get(f"{self.base_url}/stats/switches", timeout=5)
            if r.status_code == 200:
                log.info("Ryu controller connected")
            else:
                log.warning(f"Ryu status {r.status_code}")
        except Exception as e:
            log.error(f"Cannot reach Ryu: {e}")

    def install_flow_rule(self, dpid, rule):
        url = f"{self.base_url}/stats/flowentry/add"
        data = {
            "dpid": dpid,
            **rule
        }
        try:
            r = requests.post(url, json=data, timeout=5)
            return r.status_code in (200, 201)
        except Exception as e:
            log.error(f"Install flow error: {e}")
            return False

    def remove_flow_rule(self, dpid, rule):
        url = f"{self.base_url}/stats/flowentry/delete"
        data = {
            "dpid": dpid,
            **rule
        }
        try:
            r = requests.post(url, json=data, timeout=5)
            return r.status_code in (200, 201)
        except Exception as e:
            log.error(f"Remove flow error: {e}")
            return False

    def block_ip(self, ip):
        url = f"{self.base_url}/simpleswitch/block/1"
        data = {"ip": ip}
        try:
            r = requests.post(url, json=data, timeout=5)
            if r.status_code in (200, 201):
                log.info(f"Blocked IP {ip} on switch 1")
                return True
            else:
                log.error(f"Block failed: {r.text}")
                return False
        except Exception as e:
            log.error(f"Block exception: {e}")
            return False

    def unblock_ip(self, ip):
        url = f"{self.base_url}/simpleswitch/unblock/1"
        data = {"ip": ip}
        try:
            r = requests.post(url, json=data, timeout=5)
            if r.status_code in (200, 201):
                log.info(f"Unblocked IP {ip} on switch 1")
                return True
            else:
                log.error(f"Unblock failed: {r.text}")
                return False
        except Exception as e:
            log.error(f"Unblock exception: {e}")
            return False