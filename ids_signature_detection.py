"""
Signature-Based Detection Module
Rule engine for threat pattern detection
"""

import re
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class SignatureDetectionEngine:
    """Signature-based threat detection using pattern matching and rules"""
    
    def __init__(self):
        self.rules = self._initialize_rules()
        self.rule_count = len(self.rules)
    
    def _initialize_rules(self) -> List[Dict]:
        """Initialize detection rules database"""
        return [
            # SQL Injection Detection
            {
                'id': 'SQL_INJECTION_001',
                'name': 'SQL Injection - UNION SELECT',
                'severity': 'high',
                'type': 'sql_injection',
                'pattern': r"(?i)union\s+select",
                'description': 'Detects UNION-based SQL injection attempts',
                'enabled': True,
                'false_positive_rate': 0.02
            },
            {
                'id': 'SQL_INJECTION_002',
                'name': 'SQL Injection - DROP TABLE',
                'severity': 'high',
                'type': 'sql_injection',
                'pattern': r"(?i)drop\s+table",
                'description': 'Detects DROP TABLE SQL injection attempts',
                'enabled': True,
                'false_positive_rate': 0.01
            },
            {
                'id': 'SQL_INJECTION_003',
                'name': 'SQL Injection - OR 1=1',
                'severity': 'high',
                'type': 'sql_injection',
                'pattern': r"(?i)or\s+1\s*=\s*1",
                'description': 'Detects basic OR-based SQL injection',
                'enabled': True,
                'false_positive_rate': 0.03
            },
            {
                'id': 'SQL_INJECTION_004',
                'name': 'SQL Injection - INSERT INTO',
                'severity': 'high',
                'type': 'sql_injection',
                'pattern': r"(?i)insert\s+into",
                'description': 'Detects INSERT-based SQL injection',
                'enabled': True,
                'false_positive_rate': 0.04
            },
            
            # Port Scanning Detection
            {
                'id': 'PORT_SCAN_001',
                'name': 'Port Scanning - SYN Scan',
                'severity': 'medium',
                'type': 'port_scan',
                'pattern': r"sequential_syn_packets",
                'description': 'Detects TCP SYN port scanning',
                'enabled': True,
                'false_positive_rate': 0.05
            },
            {
                'id': 'PORT_SCAN_002',
                'name': 'Port Scanning - UDP Scan',
                'severity': 'medium',
                'type': 'port_scan',
                'pattern': r"sequential_udp_packets",
                'description': 'Detects UDP port scanning',
                'enabled': True,
                'false_positive_rate': 0.06
            },
            
            # XSS Detection
            {
                'id': 'XSS_001',
                'name': 'XSS - Script Tag Injection',
                'severity': 'high',
                'type': 'xss',
                'pattern': r"(?i)<\s*script\s*>",
                'description': 'Detects <script> tag injection attempts',
                'enabled': True,
                'false_positive_rate': 0.02
            },
            {
                'id': 'XSS_002',
                'name': 'XSS - JavaScript Event Handler',
                'severity': 'high',
                'type': 'xss',
                'pattern': r"(?i)on(load|click|error|submit)\s*=",
                'description': 'Detects JavaScript event handler injection',
                'enabled': True,
                'false_positive_rate': 0.03
            },
            {
                'id': 'XSS_003',
                'name': 'XSS - HTML Encoding Bypass',
                'severity': 'medium',
                'type': 'xss',
                'pattern': r"(?i)(&lt;|&#x3c;|&#60;)script",
                'description': 'Detects encoded script tag injection',
                'enabled': True,
                'false_positive_rate': 0.04
            },
            
            # Command Injection
            {
                'id': 'CMD_INJECTION_001',
                'name': 'Command Injection - Shell Metacharacters',
                'severity': 'high',
                'type': 'command_injection',
                'pattern': r"[;&|`$\(\)<>\\]",
                'description': 'Detects shell metacharacter usage in inputs',
                'enabled': True,
                'false_positive_rate': 0.08
            },
            {
                'id': 'CMD_INJECTION_002',
                'name': 'Command Injection - Pipe Chain',
                'severity': 'high',
                'type': 'command_injection',
                'pattern': r"\|\s*cat\s+/etc/passwd",
                'description': 'Detects password file access via pipes',
                'enabled': True,
                'false_positive_rate': 0.01
            },
            
            # DDoS Detection
            {
                'id': 'DDOS_001',
                'name': 'DDoS - HTTP Flood Detection',
                'severity': 'high',
                'type': 'ddos',
                'pattern': r"excessive_http_requests",
                'description': 'Detects HTTP request flooding attacks',
                'enabled': True,
                'false_positive_rate': 0.05
            },
            {
                'id': 'DDOS_002',
                'name': 'DDoS - SYN Flood Detection',
                'severity': 'high',
                'type': 'ddos',
                'pattern': r"excessive_syn_packets",
                'description': 'Detects SYN flood attacks',
                'enabled': True,
                'false_positive_rate': 0.04
            },
            {
                'id': 'DDOS_003',
                'name': 'DDoS - UDP Flood Detection',
                'severity': 'high',
                'type': 'ddos',
                'pattern': r"excessive_udp_packets",
                'description': 'Detects UDP flood attacks',
                'enabled': True,
                'false_positive_rate': 0.06
            },
            
            # Brute Force Detection
            {
                'id': 'BRUTE_FORCE_001',
                'name': 'Brute Force - SSH Login Attempts',
                'severity': 'medium',
                'type': 'brute_force',
                'pattern': r"repeated_ssh_failures",
                'description': 'Detects repeated SSH authentication failures',
                'enabled': True,
                'false_positive_rate': 0.03
            },
            {
                'id': 'BRUTE_FORCE_002',
                'name': 'Brute Force - HTTP Basic Auth',
                'severity': 'medium',
                'type': 'brute_force',
                'pattern': r"repeated_401_responses",
                'description': 'Detects repeated HTTP 401 responses',
                'enabled': True,
                'false_positive_rate': 0.04
            },
            
            # Malware Signatures
            {
                'id': 'MALWARE_001',
                'name': 'Malware - Suspicious Binary Execution',
                'severity': 'high',
                'type': 'malware',
                'pattern': r"(?i)(mimikatz|psexec|cobalt strike|metasploit)",
                'description': 'Detects known malware signatures',
                'enabled': True,
                'false_positive_rate': 0.01
            },
            {
                'id': 'MALWARE_002',
                'name': 'Malware - Lateral Movement',
                'severity': 'high',
                'type': 'malware',
                'pattern': r"(?i)(psexec|wmiexec|smbexec)",
                'description': 'Detects lateral movement attempts',
                'enabled': True,
                'false_positive_rate': 0.02
            },
            
            # Protocol Anomalies
            {
                'id': 'PROTOCOL_001',
                'name': 'Protocol Violation - Oversized Packet',
                'severity': 'medium',
                'type': 'protocol_violation',
                'pattern': r"packet_size_exceeds_limit",
                'description': 'Detects oversized network packets',
                'enabled': True,
                'false_positive_rate': 0.02
            },
            {
                'id': 'PROTOCOL_002',
                'name': 'Protocol Violation - Invalid TCP Flags',
                'severity': 'medium',
                'type': 'protocol_violation',
                'pattern': r"invalid_tcp_flags",
                'description': 'Detects invalid TCP flag combinations',
                'enabled': True,
                'false_positive_rate': 0.03
            },
            
            # Reconnaissance
            {
                'id': 'RECON_001',
                'name': 'Reconnaissance - DNS Enumeration',
                'severity': 'low',
                'type': 'reconnaissance',
                'pattern': r"repeated_dns_queries",
                'description': 'Detects DNS enumeration attempts',
                'enabled': True,
                'false_positive_rate': 0.10
            },
            {
                'id': 'RECON_002',
                'name': 'Reconnaissance - Network Mapping',
                'severity': 'low',
                'type': 'reconnaissance',
                'pattern': r"icmp_sweep_pattern",
                'description': 'Detects ICMP network sweeps',
                'enabled': True,
                'false_positive_rate': 0.07
            },
            
            # Path Traversal
            {
                'id': 'PATH_TRAVERSAL_001',
                'name': 'Path Traversal - Unix',
                'severity': 'high',
                'type': 'path_traversal',
                'pattern': r"(\.\./)+",
                'description': 'Detects ../../../ path traversal',
                'enabled': True,
                'false_positive_rate': 0.05
            },
            {
                'id': 'PATH_TRAVERSAL_002',
                'name': 'Path Traversal - Windows',
                'severity': 'high',
                'type': 'path_traversal',
                'pattern': r"(?i)(\.\.\\)+",
                'description': 'Detects ...\ path traversal',
                'enabled': True,
                'false_positive_rate': 0.04
            },
            
            # Data Exfiltration
            {
                'id': 'EXFIL_001',
                'name': 'Data Exfiltration - DNS Tunnel',
                'severity': 'high',
                'type': 'data_exfiltration',
                'pattern': r"suspicious_dns_txt_record",
                'description': 'Detects DNS tunneling for data exfiltration',
                'enabled': True,
                'false_positive_rate': 0.03
            },
            {
                'id': 'EXFIL_002',
                'name': 'Data Exfiltration - Large Data Transfer',
                'severity': 'medium',
                'type': 'data_exfiltration',
                'pattern': r"unusual_large_transfer",
                'description': 'Detects unusual large outbound transfers',
                'enabled': True,
                'false_positive_rate': 0.06
            }
        ]
    
    def detect(self, packet_data: Dict) -> List[Dict]:
        """Detect threats in packet data"""
        alerts = []
        
        if not packet_data or 'layers' not in packet_data:
            return alerts
        
        payload = packet_data.get('layers', {}).get('payload', b'')
        
        # Convert payload to string for pattern matching
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except:
            payload_str = ""
        
        ip_info = packet_data.get('layers', {}).get('ip', {})
        tcp_info = packet_data.get('layers', {}).get('tcp', {})
        
        # Check each enabled rule
        for rule in self.rules:
            if not rule['enabled']:
                continue
            
            try:
                # For simple pattern matching
                if rule['type'] in ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'malware']:
                    if re.search(rule['pattern'], payload_str):
                        alert = self._create_alert(rule, packet_data)
                        alerts.append(alert)
                
                # For statistical detection (simplified here)
                elif rule['type'] == 'ddos':
                    if 'port_scan' in payload_str.lower() or 'flood' in payload_str.lower():
                        alert = self._create_alert(rule, packet_data)
                        alerts.append(alert)
                
                elif rule['type'] == 'port_scan':
                    if 'scan' in payload_str.lower():
                        alert = self._create_alert(rule, packet_data)
                        alerts.append(alert)
                
                elif rule['type'] == 'protocol_violation':
                    if packet_data.get('size', 0) > 65535:
                        alert = self._create_alert(rule, packet_data)
                        alerts.append(alert)
            
            except Exception as e:
                logger.error(f"Error checking rule {rule['id']}: {e}")
        
        return alerts
    
    def _create_alert(self, rule: Dict, packet_data: Dict) -> Dict:
        """Create alert from rule match"""
        ip_info = packet_data.get('layers', {}).get('ip', {})
        tcp_info = packet_data.get('layers', {}).get('tcp', {})
        udp_info = packet_data.get('layers', {}).get('udp', {})
        
        return {
            'rule_id': rule['id'],
            'rule_name': rule['name'],
            'severity': rule['severity'],
            'alert_type': rule['type'],
            'timestamp': packet_data.get('timestamp', datetime.utcnow().isoformat()),
            'source_ip': ip_info.get('src', 'unknown'),
            'destination_ip': ip_info.get('dst', 'unknown'),
            'source_port': tcp_info.get('src_port') or udp_info.get('src_port'),
            'destination_port': tcp_info.get('dst_port') or udp_info.get('dst_port'),
            'protocol': 'TCP' if tcp_info else ('UDP' if udp_info else 'IP'),
            'description': rule['description'],
            'packet_size': packet_data.get('size', 0),
            'payload_sample': packet_data.get('layers', {}).get('payload', b'')[:100]
        }
    
    def get_enabled_rules(self) -> List[Dict]:
        """Get all enabled detection rules"""
        return [r for r in self.rules if r['enabled']]
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a detection rule"""
        for rule in self.rules:
            if rule['id'] == rule_id:
                rule['enabled'] = True
                return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a detection rule"""
        for rule in self.rules:
            if rule['id'] == rule_id:
                rule['enabled'] = False
                return True
        return False
    
    def get_rules_by_type(self, threat_type: str) -> List[Dict]:
        """Get rules by threat type"""
        return [r for r in self.rules if r['type'] == threat_type]
    
    def get_rules_by_severity(self, severity: str) -> List[Dict]:
        """Get rules by severity level"""
        return [r for r in self.rules if r['severity'] == severity]
