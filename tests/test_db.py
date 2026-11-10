import os
import tempfile
from analyzer.db import init_db, save_scan, get_recent_scans


def test_db_save_and_retrieve():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        init_db(db_path)
        scan_id = "test-uuid-1234"
        scanned_at = "2025-01-01T12:00:00Z"
        url = "http://example.com"
        signals = [{"id": "LEX_TEST", "points": 10, "source": "URL", "name": "Test"}]
        limitations = ["Test limitation notice"]

        save_scan(
            scan_id=scan_id,
            scanned_at=scanned_at,
            submitted_url=url,
            score=10,
            risk_band="Lower risk",
            fetch_status="Fetched successfully",
            signals=signals,
            limitations=limitations,
            db_path=db_path,
        )

        history = get_recent_scans(limit=10, db_path=db_path)
        assert len(history) == 1
        item = history[0]
        assert item["scan_id"] == scan_id
        assert item["submitted_url"] == url
        assert item["score"] == 10
        assert item["risk_band"] == "Lower risk"
        assert item["fetch_status"] == "Fetched successfully"
        assert len(item["signals"]) == 1
        assert item["signals"][0]["id"] == "LEX_TEST"
        assert item["limitations"] == limitations
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
