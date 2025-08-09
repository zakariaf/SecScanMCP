"""Data exfiltration detection service."""

import re
import logging
from typing import Dict, List, Any
from collections import defaultdict

from ..models import DataExfiltrationIndicator, ExfiltrationMethod

logger = logging.getLogger(__name__)


class ExfiltrationDetectionService:
    """Detects data exfiltration patterns in network traffic."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize data exfiltration patterns."""
        self.exfiltration_patterns = {
            'base64_data': r'[A-Za-z0-9+/]{20,}={0,2}',
            'hex_data': r'[0-9a-fA-F]{32,}',
            'jwt_token': r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'api_key': r'[Aa][Pp][Ii][_]?[Kk][Ee][Yy][=:\s]*[A-Za-z0-9]{20,}',
            'password_hash': r'\$[a-z0-9]+\$[^$]*\$[A-Za-z0-9/.]{20,}',
            'email_data': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
        }
    
    def detect_patterns(self, data: str) -> List[DataExfiltrationIndicator]:
        """Detect data exfiltration patterns in network data."""
        indicators = []
        
        try:
            for pattern_name, pattern in self.exfiltration_patterns.items():
                matches = re.findall(pattern, data)
                
                if matches:
                    confidence = min(len(matches) * 0.2, 1.0)
                    
                    indicator = DataExfiltrationIndicator(
                        method=self._classify_method(pattern_name),
                        confidence=confidence,
                        data_pattern=pattern_name,
                        destination="unknown",
                        volume=sum(len(match) for match in matches),
                        frequency=len(matches),
                        description=f"Detected {pattern_name} pattern"
                    )
                    indicators.append(indicator)
        
        except Exception as e:
            self.logger.error(f"Pattern detection failed: {e}")
        
        return indicators
    
    def analyze_volume_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze data volume patterns for anomalies."""
        anomalies = []
        
        try:
            # Group events by destination
            dest_volumes = defaultdict(list)
            for event in events:
                dest = event.get('destination', 'unknown')
                size = event.get('size', 0)
                dest_volumes[dest].append(size)
            
            # Check for volume spikes
            for dest, volumes in dest_volumes.items():
                if len(volumes) < 3:
                    continue
                
                avg_volume = sum(volumes) / len(volumes)
                max_volume = max(volumes)
                
                # Flag if max is >5x average and >1MB
                if max_volume > avg_volume * 5 and max_volume > 1_000_000:
                    anomalies.append({
                        'type': 'volume_spike',
                        'destination': dest,
                        'max_volume': max_volume,
                        'avg_volume': avg_volume,
                        'spike_ratio': max_volume / avg_volume,
                        'confidence': min(max_volume / 10_000_000, 1.0)
                    })
        
        except Exception as e:
            self.logger.error(f"Volume analysis failed: {e}")
        
        return anomalies
    
    def analyze_frequency_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze frequency patterns for exfiltration."""
        anomalies = []
        
        try:
            # Group events by destination and time windows
            time_windows = {}
            window_size = 60  # 1 minute windows
            
            for event in events:
                dest = event.get('destination', 'unknown')
                timestamp = event.get('timestamp', 0)
                window = int(timestamp // window_size)
                
                key = f"{dest}_{window}"
                if key not in time_windows:
                    time_windows[key] = []
                time_windows[key].append(event)
            
            # Check for high-frequency patterns
            for key, window_events in time_windows.items():
                if len(window_events) > 50:  # >50 events per minute
                    dest = key.split('_')[0]
                    anomalies.append({
                        'type': 'high_frequency',
                        'destination': dest,
                        'events_per_minute': len(window_events),
                        'confidence': min(len(window_events) / 100, 1.0)
                    })
        
        except Exception as e:
            self.logger.error(f"Frequency analysis failed: {e}")
        
        return anomalies
    
    def analyze_encoding_patterns(self, data: str) -> Dict[str, Any]:
        """Analyze data for encoding patterns."""
        encoding_info = {
            'base64_detected': False,
            'hex_encoded': False,
            'url_encoded': False,
            'compression_detected': False,
            'encryption_suspected': False,
            'entropy': 0.0
        }
        
        try:
            # Check for Base64
            if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', data):
                encoding_info['base64_detected'] = True
            
            # Check for hex encoding
            if re.search(r'[0-9a-fA-F]{64,}', data):
                encoding_info['hex_encoded'] = True
            
            # Check for URL encoding
            if '%' in data and re.search(r'%[0-9a-fA-F]{2}', data):
                encoding_info['url_encoded'] = True
            
            # Calculate entropy
            encoding_info['entropy'] = self._calculate_entropy(data)
            
            # High entropy suggests compression/encryption
            if encoding_info['entropy'] > 7.5:
                encoding_info['compression_detected'] = True
            if encoding_info['entropy'] > 7.8:
                encoding_info['encryption_suspected'] = True
        
        except Exception as e:
            self.logger.error(f"Encoding analysis failed: {e}")
        
        return encoding_info
    
    def detect_steganography(self, data: str) -> Dict[str, Any]:
        """Detect potential steganography in network data."""
        steg_indicators = {
            'detected': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        try:
            indicators = []
            
            # Check for image data in unusual contexts
            if b'\xff\xd8\xff' in data.encode('utf-8', errors='ignore'):
                indicators.append('jpeg_header_in_data')
            
            if b'PNG\r\n' in data.encode('utf-8', errors='ignore'):
                indicators.append('png_header_in_data')
            
            # Check for unusual padding patterns
            if data.count('=') > len(data) * 0.05:  # >5% padding
                indicators.append('excessive_padding')
            
            # Check for unusual character distribution
            entropy = self._calculate_entropy(data)
            if 6.0 < entropy < 7.0:  # Sweet spot for hidden data
                indicators.append('suspicious_entropy_range')
            
            if indicators:
                steg_indicators['detected'] = True
                steg_indicators['confidence'] = min(len(indicators) * 0.3, 1.0)
                steg_indicators['indicators'] = indicators
        
        except Exception as e:
            self.logger.error(f"Steganography detection failed: {e}")
        
        return steg_indicators
    
    def _classify_method(self, pattern_name: str) -> ExfiltrationMethod:
        """Classify exfiltration method from pattern."""
        method_map = {
            'base64_data': ExfiltrationMethod.CUSTOM_PROTOCOL,
            'hex_data': ExfiltrationMethod.CUSTOM_PROTOCOL,
            'jwt_token': ExfiltrationMethod.HTTP,
            'api_key': ExfiltrationMethod.HTTPS,
            'email_data': ExfiltrationMethod.EMAIL,
        }
        
        return method_map.get(pattern_name, ExfiltrationMethod.CUSTOM_PROTOCOL)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        import math
        from collections import Counter
        
        if not text:
            return 0.0
        
        counts = Counter(text)
        entropy = 0.0
        length = len(text)
        
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy