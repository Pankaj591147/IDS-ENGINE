"""
Core IDS Engine - Packet Capture & Analysis Module
Captures network packets in real-time using Scapy
"""

import threading
import logging
from typing import List, Callable, Optional
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import queue

logger = logging.getLogger(__name__)


class PacketCaptureEngine:
    """Real-time packet capture engine using Scapy"""
    
    def __init__(self, interface: str = None, packet_callback: Callable = None, 
                 max_packet_size: int = 65535, filter_rules: str = ""):
        """
        Initialize packet capture engine
        
        Args:
            interface: Network interface to capture on (auto-detect if None)
            packet_callback: Function to call for each captured packet
            max_packet_size: Maximum packet size to capture
            filter_rules: BPF filter rules (e.g., "tcp port 80")
        """
        self.interface = interface or self._get_default_interface()
        self.packet_callback = packet_callback
        self.max_packet_size = max_packet_size
        self.filter_rules = filter_rules
        self.is_capturing = False
        self.capture_thread = None
        self.packet_queue = queue.Queue(maxsize=10000)
        self.packet_count = 0
        self.start_time = None
        
    def _get_default_interface(self) -> str:
        """Auto-detect default network interface"""
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            # Skip loopback and return first available
            for iface in interfaces:
                if iface not in ['lo', 'lo0']:
                    return iface
            return interfaces[0] if interfaces else 'eth0'
        except Exception as e:
            logger.error(f"Error detecting interface: {e}")
            return 'eth0'
    
    def _packet_handler(self, packet):
        """Handle captured packet"""
        try:
            self.packet_count += 1
            
            packet_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'packet_num': self.packet_count,
                'size': len(packet),
                'raw_packet': bytes(packet),
                'layers': self._extract_packet_info(packet)
            }
            
            # Add to queue
            try:
                self.packet_queue.put(packet_data, timeout=1)
            except queue.Full:
                logger.warning("Packet queue full, dropping oldest packet")
                try:
                    self.packet_queue.get_nowait()
                    self.packet_queue.put(packet_data)
                except:
                    pass
            
            # Call external callback if provided
            if self.packet_callback:
                self.packet_callback(packet_data)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> dict:
        """Extract packet information from layers"""
        info = {
            'protocols': [],
            'ip': {},
            'tcp': {},
            'udp': {},
            'icmp': {},
            'payload': b''
        }
        
        # IP Layer
        if IP in packet:
            ip_layer = packet[IP]
            info['ip'] = {
                'src': ip_layer.src,
                'dst': ip_layer.dst,
                'version': ip_layer.version,
                'ihl': ip_layer.ihl,
                'tos': ip_layer.tos,
                'length': ip_layer.len,
                'id': ip_layer.id,
                'flags': ip_layer.flags,
                'ttl': ip_layer.ttl,
                'protocol': ip_layer.proto
            }
            info['protocols'].append('IP')
        
        # TCP Layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            info['tcp'] = {
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'seq': tcp_layer.seq,
                'ack': tcp_layer.ack,
                'flags': self._parse_tcp_flags(tcp_layer.flags),
                'window_size': tcp_layer.window,
                'urgp': tcp_layer.urgp
            }
            info['protocols'].append('TCP')
        
        # UDP Layer
        if UDP in packet:
            udp_layer = packet[UDP]
            info['udp'] = {
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport,
                'length': udp_layer.len,
                'checksum': udp_layer.chksum
            }
            info['protocols'].append('UDP')
        
        # ICMP Layer
        if ICMP in packet:
            icmp_layer = packet[ICMP]
            info['icmp'] = {
                'type': icmp_layer.type,
                'code': icmp_layer.code,
                'checksum': icmp_layer.chksum
            }
            info['protocols'].append('ICMP')
        
        # Payload
        if Raw in packet:
            info['payload'] = bytes(packet[Raw].load)[:512]  # First 512 bytes
        
        return info
    
    def _parse_tcp_flags(self, flags: int) -> dict:
        """Parse TCP flags"""
        flag_names = {
            0x01: 'FIN',
            0x02: 'SYN',
            0x04: 'RST',
            0x08: 'PSH',
            0x10: 'ACK',
            0x20: 'URG',
            0x40: 'ECE',
            0x80: 'CWR'
        }
        return {name: bool(flags & flag) for flag, name in flag_names.items()}
    
    def start_capture(self):
        """Start packet capture in background thread"""
        if self.is_capturing:
            logger.warning("Capture already running")
            return
        
        self.is_capturing = True
        self.start_time = datetime.utcnow()
        self.packet_count = 0
        
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self.capture_thread.start()
        logger.info(f"Started packet capture on {self.interface}")
    
    def _capture_loop(self):
        """Background capture loop"""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=self.filter_rules if self.filter_rules else "",
                store=False,
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            logger.error(f"Capture loop error: {e}")
            self.is_capturing = False
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Stopped packet capture")
    
    def get_packet(self, timeout: float = 1.0) -> Optional[dict]:
        """Get next packet from queue"""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_statistics(self) -> dict:
        """Get capture statistics"""
        elapsed = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0
        pps = self.packet_count / elapsed if elapsed > 0 else 0
        
        return {
            'interface': self.interface,
            'packets_captured': self.packet_count,
            'packets_per_second': round(pps, 2),
            'queue_size': self.packet_queue.qsize(),
            'elapsed_seconds': round(elapsed, 2),
            'is_capturing': self.is_capturing
        }


class PacketSimulator:
    """Simulate network packets for testing (no actual network required)"""
    
    def __init__(self, callback: Callable = None):
        self.callback = callback
        self.is_running = False
        self.simulate_thread = None
        self.packet_count = 0
    
    def start_simulation(self, packets_per_second: int = 100):
        """Start packet simulation"""
        import time
        import random
        
        self.is_running = True
        self.simulate_thread = threading.Thread(
            target=self._simulate_loop,
            args=(packets_per_second,),
            daemon=True
        )
        self.simulate_thread.start()
    
    def _simulate_loop(self, pps: int):
        """Simulation loop"""
        import time
        import random
        
        interval = 1.0 / pps if pps > 0 else 0.01
        
        while self.is_running:
            packet = self._generate_synthetic_packet()
            if self.callback:
                self.callback(packet)
            self.packet_count += 1
            time.sleep(interval)
    
    def _generate_synthetic_packet(self) -> dict:
        """Generate synthetic packet for testing"""
        import random
        
        src_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        dst_ip = f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"
        
        packet = {
            'timestamp': datetime.utcnow().isoformat(),
            'packet_num': self.packet_count,
            'size': random.randint(64, 1500),
            'raw_packet': bytes(random.getrandbits(8) for _ in range(100)),
            'layers': {
                'protocols': ['IP', 'TCP'],
                'ip': {
                    'src': src_ip,
                    'dst': dst_ip,
                    'version': 4,
                    'ttl': random.randint(32, 128),
                    'protocol': 6
                },
                'tcp': {
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([80, 443, 22, 3306, 5432]),
                    'flags': {'SYN': random.random() < 0.1, 'ACK': True},
                    'window_size': 65535
                },
                'payload': b'test_payload'
            }
        }
        
        return packet
    
    def stop_simulation(self):
        """Stop simulation"""
        self.is_running = False
        if self.simulate_thread:
            self.simulate_thread.join(timeout=5)
