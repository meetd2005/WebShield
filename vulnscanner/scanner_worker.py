import concurrent.futures
import threading
from datetime import datetime
import logging
from typing import Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] ScanWorker: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)

class ScanWorkerPool:
    def __init__(self, max_workers=3):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.active_scans: Dict[int, concurrent.futures.Future] = {}
        self.scan_status: Dict[int, str] = {}
        self._lock = threading.Lock()
        self.scan_events: Dict[int, list] = {}
        self.scan_results: Dict[int, Dict] = {}  # Store scan results
        self.completed_scans = set()  # Track completed scans

    def submit_scan(self, scan_id: int, scanner, scan_type: str, target: str, options: Optional[dict] = None):
        """Submit a new scan to the worker pool"""
        with self._lock:
            if scan_id in self.active_scans:
                logger.warning(f"Scan {scan_id} is already running")
                return False

            try:
                # Initialize scan status, events and results
                self.scan_status[scan_id] = "initializing"
                self.scan_events[scan_id] = []
                self.scan_results[scan_id] = None  # Initialize result storage
                logger.debug(f"Initialized scan {scan_id} events and status")

                # Submit scan to worker pool
                logger.info(f"Starting scan {scan_id} for target {target}")
                future = self.executor.submit(
                    self._run_scan, scan_id, scanner, scan_type, target, options or {}
                )
                self.active_scans[scan_id] = future
                future.add_done_callback(lambda f: self._cleanup_scan(scan_id))
                return True
            except Exception as e:
                logger.error(f"Failed to submit scan {scan_id}: {str(e)}")
                return False

    def _run_scan(self, scan_id: int, scanner, scan_type: str, target: str, options: dict):
        """Execute scan with event tracking"""
        try:
            logger.info(f"Running {scan_type} scan for target {target}")

            # Select scan type and initialize generator
            if scan_type == 'quick':
                scan_generator = scanner.quick_scan(target, options)
            elif scan_type == 'full':
                scan_generator = scanner.full_scan(target, options)
            else:
                scan_generator = scanner.custom_scan(target, options)

            # Initialize result structure
            result = {
                'vulnerabilities': [],
                'status': 'completed',
                'target': target,
                'scan_type': scan_type,
                'timestamp': datetime.utcnow().isoformat()
            }

            try:
                for item in scan_generator:
                    if isinstance(item, dict) and 'vulnerabilities' in item:
                        # Add each vulnerability to events and results
                        for vuln in item['vulnerabilities']:
                            result['vulnerabilities'].append(vuln)
                            with self._lock:
                                logger.debug(f"New vulnerability found for scan {scan_id}: {vuln['type']}")
                                self.scan_events[scan_id].append({
                                    'event': 'vulnerability_found',
                                    'data': vuln
                                })

            except Exception as e:
                logger.error(f"Error during scan execution: {str(e)}")
                raise

            # Store the final result before completion
            with self._lock:
                self.scan_results[scan_id] = result
                logger.info(f"Scan {scan_id} completed, stored results with {len(result['vulnerabilities'])} vulnerabilities")
                self.scan_events[scan_id].append({
                    'event': 'scan_completed',
                    'data': {
                        'total_vulnerabilities': len(result['vulnerabilities'])
                    }
                })

            return result

        except Exception as e:
            error_msg = f"Scan {scan_id} failed: {str(e)}"
            logger.error(error_msg)
            with self._lock:
                failed_result = {
                    'status': 'failed',
                    'error': str(e),
                    'vulnerabilities': []
                }
                self.scan_results[scan_id] = failed_result
                self.scan_events[scan_id].append({
                    'event': 'scan_error',
                    'data': {'error': str(e)}
                })
            return failed_result

    def get_scan_result(self, scan_id: int) -> Optional[Dict]:
        """Get stored scan result"""
        with self._lock:
            return self.scan_results.get(scan_id)

    def get_scan_status(self, scan_id: int) -> dict:
        """Get current scan status"""
        with self._lock:
            if scan_id not in self.active_scans:
                return {"status": self.scan_status.get(scan_id, "not_found")}

            future = self.active_scans[scan_id]
            if future.done():
                try:
                    result = future.result()
                    if not result:
                        return {
                            "status": "failed",
                            "error": "No results returned"
                        }
                    return {
                        "status": result.get('status', 'completed'),
                        "error": result.get('error')
                    }
                except Exception as e:
                    return {
                        "status": "failed",
                        "error": str(e)
                    }
            return {
                "status": "in_progress"
            }

    def get_events(self, scan_id: int, last_event_id: int = 0) -> list:
        """Get new events for a scan since the last event ID"""
        with self._lock:
            if scan_id in self.completed_scans and last_event_id >= len(self.scan_events.get(scan_id, [])):
                logger.debug(f"Scan {scan_id} is completed and all events sent, stopping event stream")
                return []

            events = self.scan_events.get(scan_id, [])
            if last_event_id < len(events):
                new_events = events[last_event_id:]
                logger.debug(f"Returning {len(new_events)} new events for scan {scan_id}")
                return new_events
            return []

    def cancel_scan(self, scan_id: int) -> bool:
        """Cancel a running scan"""
        with self._lock:
            if scan_id not in self.active_scans:
                return False

            future = self.active_scans[scan_id]
            cancelled = future.cancel()
            if cancelled:
                self.scan_status[scan_id] = "cancelled"
                self.scan_results[scan_id] = {
                    'status': 'cancelled',
                    'vulnerabilities': [],
                    'timestamp': datetime.utcnow().isoformat()
                }
                self.scan_events[scan_id].append({
                    'event': 'scan_cancelled',
                    'data': {}
                })
                logger.info(f"Scan {scan_id} cancelled successfully")
            return cancelled

    def _cleanup_scan(self, scan_id: int):
        """Clean up completed scan data but preserve results"""
        with self._lock:
            if scan_id in self.active_scans:
                future = self.active_scans[scan_id]
                if future.done():
                    try:
                        result = future.result()
                        if result and isinstance(result, dict):
                            # Only update status if not already in a final state
                            current_status = self.scan_status.get(scan_id)
                            if current_status not in ['completed', 'failed', 'cancelled']:
                                self.scan_status[scan_id] = result.get('status', 'completed')
                                logger.info(f"Scan {scan_id} completed with status: {self.scan_status[scan_id]}")

                            # Keep the result in scan_results
                            if scan_id not in self.scan_results:
                                self.scan_results[scan_id] = result

                            # Mark scan as completed
                            self.completed_scans.add(scan_id)
                            del self.active_scans[scan_id]
                            # Schedule event cleanup but keep results
                            threading.Timer(300, lambda: self._remove_scan_events(scan_id)).start()
                        else:
                            raise Exception("Invalid scan result format")
                    except Exception as e:
                        logger.error(f"Scan {scan_id} failed: {str(e)}")
                        if self.scan_status.get(scan_id) not in ['completed', 'cancelled']:
                            self.scan_status[scan_id] = "failed"
                            self.scan_results[scan_id] = {
                                'status': 'failed',
                                'error': str(e),
                                'vulnerabilities': []
                            }
                            if not any(e['event'] == 'scan_error' for e in self.scan_events.get(scan_id, [])):
                                self.scan_events[scan_id].append({
                                    'event': 'scan_error',
                                    'data': {'error': str(e)}
                                })
                            self.completed_scans.add(scan_id)
                            if scan_id in self.active_scans:
                                del self.active_scans[scan_id]
                                threading.Timer(300, lambda: self._remove_scan_events(scan_id)).start()

    def _remove_scan_events(self, scan_id: int):
        """Remove scan events after timeout but preserve results"""
        with self._lock:
            self.scan_events.pop(scan_id, None)
            self.completed_scans.discard(scan_id)
            logger.debug(f"Cleaned up events for scan {scan_id}")

    def _add_event(self, scan_id: int, event_type: str, event_data: dict):
        """Add a new event to the scan events list"""
        with self._lock:
            if scan_id in self.scan_events:
                self.scan_events[scan_id].append({
                    'event': event_type,
                    'data': event_data,
                    'timestamp': datetime.utcnow().isoformat()
                })

# Global worker pool instance
scan_worker_pool = ScanWorkerPool()