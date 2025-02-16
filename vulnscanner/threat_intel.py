import requests
import json
from datetime import datetime, timedelta
import logging
from typing import List, Dict, Optional
import trafilatura
from bs4 import BeautifulSoup
from app import db
from .models import ThreatIntelligence, ThreatIndicator, Report

class ThreatIntelligenceManager:
    def __init__(self):
        self.last_update = None
        self.update_interval = timedelta(hours=1)  # Update threat feeds every hour

    def _fetch_public_vulnerabilities(self, days_back: int = 30) -> List[Dict]:
        """Fetch recent vulnerabilities from public sources"""
        try:
            # Fetch from NIST NVD public feed
            url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                return data.get('CVE_Items', [])
            else:
                logging.error(f"Failed to fetch public vulnerability data: {response.status_code}")
                return []
        except Exception as e:
            logging.error(f"Error fetching public vulnerabilities: {str(e)}")
            return []

    def _fetch_public_threat_indicators(self) -> List[Dict]:
        """Fetch threat indicators from public sources"""
        try:
            indicators = []

            # Fetch from abuse.ch SSL Blacklist
            url = "https://sslbl.abuse.ch/blacklist/"
            downloaded = trafilatura.fetch_url(url)
            if downloaded:
                text = trafilatura.extract(downloaded)
                if text:
                    # Process the text to extract indicators
                    for line in text.split('\n'):
                        if line.strip() and not line.startswith('#'):
                            indicators.append({
                                'type': 'ssl_fingerprint',
                                'value': line.strip(),
                                'source': 'abuse.ch',
                                'confidence': 0.8,
                                'threat_type': 'malware'
                            })

            return indicators
        except Exception as e:
            logging.error(f"Error fetching public threat indicators: {str(e)}")
            return []

    def _process_public_vulnerability(self, vuln_data: Dict) -> Optional[Dict]:
        """Process and normalize public vulnerability data"""
        try:
            return {
                'cve_id': vuln_data.get('cve', {}).get('CVE_data_meta', {}).get('ID'),
                'title': vuln_data.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'Unknown'),
                'description': vuln_data.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', ''),
                'severity': vuln_data.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'UNKNOWN'),
                'cvss_score': float(vuln_data.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0.0)),
                'published_date': datetime.strptime(vuln_data.get('publishedDate', ''), "%Y-%m-%dT%H:%M:%SZ"),
                'last_modified': datetime.strptime(vuln_data.get('lastModifiedDate', ''), "%Y-%m-%dT%H:%M:%SZ"),
                'affected_products': vuln_data.get('configurations', {}),
                'references': vuln_data.get('cve', {}).get('references', {}).get('reference_data', []),
                'source': 'NVD-Public'
            }
        except Exception as e:
            logging.error(f"Error processing public vulnerability: {str(e)}")
            return None

    def _process_threat_indicator(self, indicator_data: Dict) -> Optional[Dict]:
        """Process and normalize threat indicator data"""
        try:
            now = datetime.utcnow()
            return {
                'indicator_type': indicator_data['type'],
                'value': indicator_data['value'],
                'confidence_score': float(indicator_data['confidence']),
                'threat_type': indicator_data['threat_type'],
                'first_seen': now,
                'last_seen': now,
                'source': indicator_data['source'],
                'additional_data': {}  # Changed from metadata to additional_data
            }
        except Exception as e:
            logging.error(f"Error processing threat indicator: {str(e)}")
            return None

    def update_threat_feeds(self) -> bool:
        """Update threat intelligence data from public sources"""
        if self.last_update and datetime.utcnow() - self.last_update < self.update_interval:
            return False

        try:
            # Update vulnerabilities from public sources
            public_vulns = self._fetch_public_vulnerabilities()
            for vuln_data in public_vulns:
                processed_vuln = self._process_public_vulnerability(vuln_data)
                if processed_vuln:
                    existing_vuln = ThreatIntelligence.query.filter_by(
                        cve_id=processed_vuln['cve_id']
                    ).first()

                    if existing_vuln:
                        # Update existing vulnerability
                        for key, value in processed_vuln.items():
                            setattr(existing_vuln, key, value)
                    else:
                        # Create new vulnerability
                        new_vuln = ThreatIntelligence(**processed_vuln)
                        db.session.add(new_vuln)

            # Update threat indicators from public sources
            public_indicators = self._fetch_public_threat_indicators()
            for indicator_data in public_indicators:
                processed_indicator = self._process_threat_indicator(indicator_data)
                if processed_indicator:
                    existing_indicator = ThreatIndicator.query.filter_by(
                        indicator_type=processed_indicator['indicator_type'],
                        value=processed_indicator['value']
                    ).first()

                    if existing_indicator:
                        # Update existing indicator
                        for key, value in processed_indicator.items():
                            setattr(existing_indicator, key, value)
                    else:
                        # Create new indicator
                        new_indicator = ThreatIndicator(**processed_indicator)
                        db.session.add(new_indicator)

            db.session.commit()
            self.last_update = datetime.utcnow()
            logging.info("Successfully updated threat feeds from public sources")
            return True

        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating threat feeds: {str(e)}")
            return False

    def get_relevant_threats(self, target: str, scan_results: List[Dict]) -> List[Dict]:
        """Get relevant threat intelligence data for a specific target and scan results"""
        relevant_threats = []

        try:
            # Update threat feeds if needed
            self.update_threat_feeds()

            # Extract potential indicators from scan results
            for vuln in scan_results:
                # Match CVEs if present in vulnerability details
                if 'cve' in vuln.get('details', '').lower():
                    cve_matches = ThreatIntelligence.query.filter(
                        ThreatIntelligence.description.ilike(f"%{vuln['details']}%")
                    ).all()

                    for match in cve_matches:
                        relevant_threats.append({
                            'type': 'cve',
                            'source': match.source,
                            'severity': match.severity,
                            'title': match.title,
                            'description': match.description,
                            'cvss_score': match.cvss_score,
                            'published_date': match.published_date.isoformat(),
                            'mitigations': match.mitigations
                        })

                # Check for IP addresses, domains, or other indicators
                indicators = ThreatIndicator.query.filter_by(
                    value=target
                ).all()

                for indicator in indicators:
                    relevant_threats.append({
                        'type': 'indicator',
                        'source': indicator.source,
                        'indicator_type': indicator.indicator_type,
                        'threat_type': indicator.threat_type,
                        'confidence_score': indicator.confidence_score,
                        'first_seen': indicator.first_seen.isoformat(),
                        'last_seen': indicator.last_seen.isoformat(),
                        'additional_data': indicator.additional_data  # Changed from metadata
                    })

        except Exception as e:
            logging.error(f"Error getting relevant threats: {str(e)}")

        return relevant_threats

    def enrich_scan_report(self, report_id: int) -> bool:
        """Enrich a scan report with threat intelligence data"""
        try:
            report = Report.query.get(report_id)
            if not report:
                return False

            # Get threat intelligence for the scan
            threats = self.get_relevant_threats(
                report.scan.target,
                report.vulnerabilities
            )

            # Update report with threat intelligence data
            report.threat_intel = threats
            db.session.commit()
            logging.info(f"Successfully enriched report {report_id} with threat intelligence")
            return True

        except Exception as e:
            logging.error(f"Error enriching report with threat intelligence: {str(e)}")
            db.session.rollback()
            return False

# Create a global instance
threat_intel_manager = ThreatIntelligenceManager()