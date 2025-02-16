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
            # Initialize progress tracking
            self.update_progress(scan_id, 5.0)  # Started
            logging.info(f"Starting scan {scan_id} for target {target}")

            # Select scan type
            if scan_type == 'quick':
                scan_generator = scanner.quick_scan(target)
            elif scan_type == 'full':
                scan_generator = scanner.full_scan(target)
            else:
                scan_generator = scanner.custom_scan(target, options or {})

            # Process the scan generator to get progress updates
            result = None
            last_progress = 5.0

            try:
                for progress in scan_generator:
                    if isinstance(progress, dict):  # Final result
                        result = progress
                        self.update_progress(scan_id, 100.0)  # Completed
                        break
                    else:  # Progress update
                        # Ensure progress is between 5 and 95 during scanning
                        current_progress = min(95.0, max(5.0, float(progress)))
                        if current_progress > last_progress:
                            self.update_progress(scan_id, current_progress)
                            last_progress = current_progress
                            logging.debug(f"Scan {scan_id} progress: {current_progress}%")
            except StopIteration:
                pass

            if result is None:
                raise Exception("Scan completed but no results were returned")

            logging.info(f"Scan {scan_id} completed successfully")
            return result

        except Exception as e:
            error_msg = f"Scan {scan_id} failed: {str(e)}"
            logging.error(error_msg)
            # Ensure progress is updated even on failure
            self.update_progress(scan_id, 100.0)
            raise

    def _cleanup_scan(self, scan_id: int):
        """Clean up completed or failed scans"""
        with self._lock:
            if scan_id in self.active_scans:
                future = self.active_scans[scan_id]
                if future.done():
                    try:
                        # Check if there was an exception
                        future.result()
                    except Exception as e:
                        logging.error(f"Scan {scan_id} failed during cleanup: {str(e)}")
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
                        return {
                            "status": "failed",
                            "error": str(future.exception()),
                            "progress": 100
                        }
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
                cancelled = future.cancel()
                if cancelled:
                    self.update_progress(scan_id, 100.0)
                    logging.info(f"Scan {scan_id} cancelled successfully")
                return cancelled
            return False

# Create a global worker pool instance
scan_worker_pool = ScanWorkerPool()