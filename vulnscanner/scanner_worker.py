import concurrent.futures
import threading
from queue import Queue
import logging
from datetime import datetime
from typing import Dict, Optional

class ScanWorkerPool:
    def __init__(self, max_workers=3):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.active_scans: Dict[int, concurrent.futures.Future] = {}
        self.scan_progress: Dict[int, float] = {}
        self._lock = threading.Lock()
        
    def submit_scan(self, scan_id: int, scanner, scan_type: str, target: str, options: Optional[dict] = None):
        """Submit a new scan to the worker pool"""
        with self._lock:
            if scan_id in self.active_scans:
                logging.warning(f"Scan {scan_id} is already running")
                return
            
            self.scan_progress[scan_id] = 0.0
            future = self.executor.submit(self._run_scan, scan_id, scanner, scan_type, target, options)
            self.active_scans[scan_id] = future
            
            # Add callback for scan completion
            future.add_done_callback(lambda f: self._cleanup_scan(scan_id))
    
    def _run_scan(self, scan_id: int, scanner, scan_type: str, target: str, options: Optional[dict] = None):
        """Execute the scan in a worker thread"""
        try:
            if scan_type == 'quick':
                result = scanner.quick_scan(target)
            elif scan_type == 'full':
                result = scanner.full_scan(target)
            else:
                result = scanner.custom_scan(target, options or {})
            
            # Update progress periodically
            self.update_progress(scan_id, 100)
            return result
            
        except Exception as e:
            logging.error(f"Scan {scan_id} failed: {str(e)}")
            raise
    
    def _cleanup_scan(self, scan_id: int):
        """Clean up completed or failed scans"""
        with self._lock:
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            if scan_id in self.scan_progress:
                del self.scan_progress[scan_id]
    
    def get_scan_status(self, scan_id: int) -> dict:
        """Get the current status of a scan"""
        with self._lock:
            if scan_id in self.active_scans:
                future = self.active_scans[scan_id]
                if future.done():
                    if future.exception():
                        return {"status": "failed", "error": str(future.exception())}
                    return {"status": "completed", "progress": 100}
                return {
                    "status": "in_progress",
                    "progress": self.scan_progress.get(scan_id, 0)
                }
            return {"status": "not_found"}
    
    def update_progress(self, scan_id: int, progress: float):
        """Update the progress of a scan"""
        with self._lock:
            self.scan_progress[scan_id] = min(100, max(0, progress))
    
    def cancel_scan(self, scan_id: int) -> bool:
        """Cancel a running scan"""
        with self._lock:
            if scan_id in self.active_scans:
                future = self.active_scans[scan_id]
                return future.cancel()
            return False

# Create a global worker pool instance
scan_worker_pool = ScanWorkerPool()
