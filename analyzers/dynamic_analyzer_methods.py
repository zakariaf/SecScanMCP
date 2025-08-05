"""
Remaining advanced methods for Dynamic Analyzer
Traffic analysis, ML detection, and cleanup methods
"""

import asyncio
import time
import logging
from typing import List, Dict, Any
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class DynamicAnalyzerMethods:
    """
    Additional advanced methods for Dynamic Analyzer
    """
    
    async def _analyze_network_traffic(self) -> List[Finding]:
        """Analyze network traffic for suspicious patterns"""
        findings = []
        
        if not self.traffic_analyzer:
            return findings
        
        try:
            self.logger.info("📡 Analyzing network traffic patterns...")
            
            # Stop traffic monitoring and get results
            self.traffic_analyzer.stop_monitoring()
            
            # Get traffic summary
            traffic_summary = self.traffic_analyzer.get_traffic_summary()
            
            # Check for high-risk network activity
            if traffic_summary['risk_score'] > 70:
                finding = self.create_finding(
                    vulnerability_type=VulnerabilityType.NETWORK_SECURITY,
                    severity=SeverityLevel.HIGH,
                    confidence=0.8,
                    title="High-Risk Network Activity Detected",
                    description=f"Network risk score: {traffic_summary['risk_score']:.1f}%",
                    location="network:traffic",
                    recommendation="Investigate suspicious network connections and data transfers",
                    evidence=traffic_summary
                )
                findings.append(finding)
            
            # Check for suspicious activities
            suspicious_activities = self.traffic_analyzer.get_suspicious_activities()
            
            for activity in suspicious_activities[:10]:  # Limit to top 10
                severity = SeverityLevel.HIGH if activity['severity'] == 'high' else SeverityLevel.MEDIUM
                
                finding = self.create_finding(
                    vulnerability_type=VulnerabilityType.NETWORK_SECURITY,
                    severity=severity,
                    confidence=0.7,
                    title=f"Suspicious Network Activity: {activity['type']}",
                    description=activity['description'],
                    location="network:activity",
                    recommendation="Review network activity patterns and validate legitimacy",
                    evidence=activity
                )
                findings.append(finding)
            
            self.logger.info(f"📊 Network analysis found {len(findings)} issues")
            
        except Exception as e:
            self.logger.error(f"Network traffic analysis failed: {e}")
        
        return findings
    
    async def _detect_data_exfiltration(self) -> List[Finding]:
        """Detect potential data exfiltration attempts"""
        findings = []
        
        try:
            self.logger.info("🕵️ Scanning for data exfiltration patterns...")
            
            # Get all network events and analyze for data patterns
            if self.traffic_analyzer:
                network_events = self.traffic_analyzer.network_events
                
                for event in network_events:
                    if event.data:
                        # Scan for sensitive data patterns
                        sensitive_findings = self.data_leakage_detector.scan_for_sensitive_data(event.data)
                        
                        for sensitive_finding in sensitive_findings:
                            if sensitive_finding['confidence'] > 0.7:
                                finding = self.create_finding(
                                    vulnerability_type=VulnerabilityType.DATA_LEAKAGE,
                                    severity=SeverityLevel.CRITICAL,
                                    confidence=sensitive_finding['confidence'],
                                    title=f"Sensitive Data Exposure: {sensitive_finding['type']}",
                                    description=f"Detected {sensitive_finding['type']} in network traffic",
                                    location=f"network:{event.destination}",
                                    recommendation="Prevent sensitive data from being transmitted over network",
                                    evidence={
                                        'data_type': sensitive_finding['type'],
                                        'masked_value': sensitive_finding['value'],
                                        'entropy': sensitive_finding['entropy'],
                                        'context': sensitive_finding['context']
                                    }
                                )
                                findings.append(finding)
            
            self.logger.info(f"🔍 Data exfiltration detection found {len(findings)} issues")
            
        except Exception as e:
            self.logger.error(f"Data exfiltration detection failed: {e}")
        
        return findings
    
    async def _run_ml_anomaly_detection(self) -> List[Finding]:
        """Run ML-based anomaly detection on behavioral data"""
        findings = []
        
        try:
            metrics_history = self.analysis_session.get('metrics_history', [])
            
            if len(metrics_history) < 10:
                self.logger.info("🤖 Insufficient data for ML anomaly detection")
                return findings
            
            self.logger.info("🤖 Running ML-based anomaly detection...")
            
            # Train ML model on recent behavior (if not already trained)
            if not self.ml_detector.is_trained:
                # Use first 70% as training data
                training_size = int(len(metrics_history) * 0.7)
                training_data = metrics_history[:training_size]
                
                self.ml_detector.train(training_data)
            
            # Detect anomalies in remaining data
            test_data = metrics_history[int(len(metrics_history) * 0.7):]
            
            for metrics in test_data:
                anomalies = self.ml_detector.detect_anomalies(metrics)
                
                for anomaly in anomalies:
                    # Convert ML anomaly to finding
                    severity_map = {
                        'critical': SeverityLevel.CRITICAL,
                        'high': SeverityLevel.HIGH,
                        'medium': SeverityLevel.MEDIUM,
                        'low': SeverityLevel.LOW
                    }
                    
                    severity = severity_map.get(anomaly.severity.value, SeverityLevel.MEDIUM)
                    
                    finding = self.create_finding(
                        vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
                        severity=severity,
                        confidence=anomaly.confidence,
                        title=f"ML Anomaly Detection: {anomaly.anomaly_type.value}",
                        description=anomaly.description,
                        location="runtime:behavior",
                        recommendation=anomaly.recommendation,
                        evidence={
                            'anomaly_type': anomaly.anomaly_type.value,
                            'affected_features': anomaly.affected_features,
                            'baseline_deviation': anomaly.baseline_deviation,
                            'timestamp': anomaly.timestamp,
                            'metrics': anomaly.metrics
                        }
                    )
                    findings.append(finding)
            
            self.logger.info(f"🤖 ML anomaly detection found {len(findings)} anomalies")
            
        except Exception as e:
            self.logger.error(f"ML anomaly detection failed: {e}")
        
        return findings
    
    async def _analyze_performance_patterns(self) -> List[Finding]:
        """Analyze performance patterns for issues"""
        findings = []
        
        try:
            metrics_history = self.analysis_session.get('metrics_history', [])
            
            if not metrics_history:
                return findings
            
            self.logger.info("⚡ Analyzing performance patterns...")
            
            # Calculate performance statistics
            cpu_values = [m.get('cpu_percent', 0) for m in metrics_history]
            memory_values = [m.get('memory_mb', 0) for m in metrics_history]
            
            # Check for performance issues
            avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0
            max_cpu = max(cpu_values) if cpu_values else 0
            avg_memory = sum(memory_values) / len(memory_values) if memory_values else 0
            max_memory = max(memory_values) if memory_values else 0
            
            # High CPU usage
            if avg_cpu > 80:
                finding = self.create_finding(
                    vulnerability_type=VulnerabilityType.RESOURCE_ABUSE,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                    title="High CPU Usage Pattern",
                    description=f"Average CPU usage: {avg_cpu:.1f}% (max: {max_cpu:.1f}%)",
                    location="runtime:cpu",
                    recommendation="Investigate CPU-intensive operations that may indicate DoS or inefficient code",
                    evidence={'avg_cpu': avg_cpu, 'max_cpu': max_cpu}
                )
                findings.append(finding)
            
            # High memory usage
            if avg_memory > 800:  # 800MB threshold
                finding = self.create_finding(
                    vulnerability_type=VulnerabilityType.RESOURCE_ABUSE,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                    title="High Memory Usage Pattern",
                    description=f"Average memory usage: {avg_memory:.1f}MB (max: {max_memory:.1f}MB)",
                    location="runtime:memory",
                    recommendation="Check for memory leaks or excessive memory allocation",
                    evidence={'avg_memory': avg_memory, 'max_memory': max_memory}
                )
                findings.append(finding)
            
            # Resource usage spikes
            cpu_spikes = sum(1 for cpu in cpu_values if cpu > avg_cpu * 2)
            if cpu_spikes > len(cpu_values) * 0.1:  # More than 10% spikes
                finding = self.create_finding(
                    vulnerability_type=VulnerabilityType.RESOURCE_ABUSE,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.7,
                    title="CPU Usage Spikes Detected",
                    description=f"Detected {cpu_spikes} CPU spikes out of {len(cpu_values)} measurements",
                    location="runtime:cpu_spikes",
                    recommendation="Investigate irregular CPU usage patterns",
                    evidence={'spike_count': cpu_spikes, 'total_measurements': len(cpu_values)}
                )
                findings.append(finding)
            
            self.logger.info(f"⚡ Performance analysis found {len(findings)} issues")
            
        except Exception as e:
            self.logger.error(f"Performance analysis failed: {e}")
        
        return findings
    
    async def _detect_behavioral_anomalies(self, behavior_metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Detect behavioral anomalies in collected metrics"""
        findings = []
        
        try:
            if len(behavior_metrics) < 5:
                return findings
            
            # Statistical anomaly detection
            cpu_values = [m.get('cpu_percent', 0) for m in behavior_metrics]
            network_values = [m.get('network_connections', 0) for m in behavior_metrics]
            process_values = [m.get('process_count', 0) for m in behavior_metrics]
            
            # Calculate z-scores for anomaly detection
            import statistics
            
            def detect_outliers(values, threshold=2.0):
                if len(values) < 3:
                    return []
                mean = statistics.mean(values)
                stdev = statistics.stdev(values) if len(values) > 1 else 0
                if stdev == 0:
                    return []
                outliers = []
                for i, value in enumerate(values):
                    z_score = abs(value - mean) / stdev
                    if z_score > threshold:
                        outliers.append((i, value, z_score))
                return outliers
            
            # Check for CPU anomalies
            cpu_outliers = detect_outliers(cpu_values)
            if cpu_outliers:
                finding = self.create_finding(
                    vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.7,
                    title="CPU Usage Anomaly Detected",
                    description=f"Detected {len(cpu_outliers)} CPU usage anomalies",
                    location="runtime:cpu_behavior",
                    recommendation="Investigate unusual CPU usage patterns",
                    evidence={'outliers': cpu_outliers, 'cpu_values': cpu_values}
                )
                findings.append(finding)
            
            # Check for network anomalies
            network_outliers = detect_outliers(network_values)
            if network_outliers:
                finding = self.create_finding(
                    vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
                    severity=SeverityLevel.HIGH,
                    confidence=0.8,
                    title="Network Behavior Anomaly Detected",
                    description=f"Detected {len(network_outliers)} network connection anomalies",
                    location="runtime:network_behavior",
                    recommendation="Investigate unusual network connection patterns",
                    evidence={'outliers': network_outliers, 'network_values': network_values}
                )
                findings.append(finding)
            
            # Check for process anomalies
            process_outliers = detect_outliers(process_values)
            if process_outliers:
                finding = self.create_finding(
                    vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
                    severity=SeverityLevel.HIGH,
                    confidence=0.8,
                    title="Process Behavior Anomaly Detected",
                    description=f"Detected {len(process_outliers)} process count anomalies",
                    location="runtime:process_behavior",
                    recommendation="Investigate unusual process creation patterns",
                    evidence={'outliers': process_outliers, 'process_values': process_values}
                )
                findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Behavioral anomaly detection failed: {e}")
        
        return findings
    
    async def _cleanup_analysis_session(self, container):
        """Cleanup analysis session with comprehensive reporting"""
        try:
            self.logger.info("🧹 Cleaning up analysis session...")
            
            # Stop traffic monitoring
            if self.traffic_analyzer:
                self.traffic_analyzer.stop_monitoring()
            
            # Disconnect MCP client
            if self.analysis_session.get('mcp_client'):
                await self.analysis_session['mcp_client'].disconnect()
            
            # Get final container logs
            try:
                logs = container.logs(tail=100).decode('utf-8', errors='ignore')
                if logs:
                    self.logger.debug(f"Container logs:\n{logs}")
            except Exception as e:
                self.logger.debug(f"Could not retrieve container logs: {e}")
            
            # Stop and remove container
            try:
                container.stop(timeout=10)
                container.remove()
                self.logger.info("🗑️ Container cleaned up successfully")
            except Exception as e:
                self.logger.warning(f"Container cleanup warning: {e}")
            
            # Mark analysis as complete
            self.analysis_session['analysis_complete'] = True
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
    
    async def _handle_analysis_failure(self, error: Exception):
        """Handle analysis failure and save partial results"""
        try:
            self.logger.error(f"🚨 Analysis failed: {error}")
            
            # Save partial results if any
            if self.analysis_session.get('vulnerabilities_found'):
                self.logger.info(f"💾 Saving {len(self.analysis_session['vulnerabilities_found'])} partial results")
            
            # Save metrics history for debugging
            if self.analysis_session.get('metrics_history'):
                self.logger.info(f"📊 Collected {len(self.analysis_session['metrics_history'])} metrics data points")
            
        except Exception as cleanup_error:
            self.logger.error(f"Failed to handle analysis failure: {cleanup_error}")
    
    def _generate_analysis_summary(self, findings: List[Finding]) -> str:
        """Generate comprehensive analysis summary"""
        try:
            if not findings:
                return "No vulnerabilities detected"
            
            # Count by severity
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            # Count by type
            type_counts = {}
            
            for finding in findings:
                severity = finding.severity.value.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                vuln_type = finding.vulnerability_type.value
                type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
            # Calculate analysis duration
            duration = time.time() - (self.analysis_session.get('start_time', time.time()))
            
            # Generate summary
            total = len(findings)
            critical = severity_counts['critical']
            high = severity_counts['high']
            medium = severity_counts['medium']
            low = severity_counts['low']
            
            summary = f"{total} findings ({critical} critical, {high} high, {medium} medium, {low} low) in {duration:.1f}s"
            
            # Add top vulnerability types
            if type_counts:
                top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
                top_types_str = ", ".join([f"{t[0]}({t[1]})" for t in top_types])
                summary += f". Top types: {top_types_str}"
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to generate analysis summary: {e}")
            return f"{len(findings)} findings detected"
    
    def _calculate_cpu_percent(self, stats: Dict[str, Any]) -> float:
        """Calculate CPU usage percentage from Docker stats"""
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']

            if system_delta > 0 and cpu_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * 100.0
                return round(cpu_percent, 2)
        except:
            pass

        return 0.0