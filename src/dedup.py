"""
Deduplication Module
Tracks processed CVE IDs in a JSON file to avoid sending duplicate advisories.
Auto-prunes entries older than 30 days.
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import List, Set

logger = logging.getLogger(__name__)

DEFAULT_DATA_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "processed_cves.json",
)


class DeduplicationTracker:
    """Tracks which CVEs have already been processed to avoid duplicates."""

    def __init__(self, data_file: str = DEFAULT_DATA_FILE):
        self.data_file = data_file
        self.processed: dict = {}
        self._load()

    def _load(self):
        """Load processed CVE IDs from the JSON file."""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.processed = data.get("processed", {})
                logger.info(f"Loaded {len(self.processed)} previously processed CVE IDs")
            else:
                logger.info("No existing processed CVEs file found, starting fresh")
                self.processed = {}
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Error loading processed CVEs file: {e}. Starting fresh.")
            self.processed = {}

    def save(self):
        """Save the current state to the JSON file."""
        os.makedirs(os.path.dirname(self.data_file), exist_ok=True)

        data = {
            "processed": self.processed,
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_count": len(self.processed),
        }

        with open(self.data_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(self.processed)} processed CVE IDs")

    def is_duplicate(self, cve_id: str) -> bool:
        """Check if a CVE has already been processed."""
        return cve_id in self.processed

    def get_processed_ids(self) -> Set[str]:
        """Return the set of all processed CVE IDs."""
        return set(self.processed.keys())

    def mark_processed(self, cve_id: str):
        """Mark a CVE as processed with the current timestamp."""
        self.processed[cve_id] = datetime.now(timezone.utc).isoformat()

    def mark_batch_processed(self, cve_ids: List[str]):
        """Mark multiple CVEs as processed."""
        now = datetime.now(timezone.utc).isoformat()
        for cve_id in cve_ids:
            self.processed[cve_id] = now

    def filter_new(self, cve_ids: List[str]) -> List[str]:
        """Return only CVE IDs that haven't been processed yet."""
        new_ids = [cve_id for cve_id in cve_ids if cve_id not in self.processed]
        logger.info(f"Filtered {len(cve_ids)} CVEs → {len(new_ids)} new, {len(cve_ids) - len(new_ids)} duplicates")
        return new_ids

    def prune_old_entries(self, max_age_days: int = 30):
        """Remove processed entries older than max_age_days to keep the file small."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        original_count = len(self.processed)

        pruned = {}
        for cve_id, timestamp_str in self.processed.items():
            try:
                ts = datetime.fromisoformat(timestamp_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    pruned[cve_id] = timestamp_str
            except (ValueError, TypeError):
                # Keep entries with unparseable timestamps
                pruned[cve_id] = timestamp_str

        removed = original_count - len(pruned)
        if removed > 0:
            logger.info(f"Pruned {removed} entries older than {max_age_days} days")
        self.processed = pruned
