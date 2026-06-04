# -*- coding: utf-8 -*-
import sys
import os
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import drift_monitor


class TestDriftMonitor:
    @patch("app.elastic_client.is_connected", return_value=False)
    @pytest.mark.asyncio
    async def test_drift_check_skipped_when_es_disconnected(self, mock_connected):
        """Verify drift monitor returns early and logs warning when ES is not connected."""
        with patch("app.drift_monitor.logger.warning") as mock_log:
            await drift_monitor.check_model_drift_and_trigger()
            mock_log.assert_any_call("[Drift Monitor] Elasticsearch not connected — skipping check")

    @pytest.mark.asyncio
    async def test_drift_check_no_hits(self):
        """Verify drift check when ES search returns empty/no hits."""
        mock_es = MagicMock()
        mock_es.search.return_value = {"hits": {"hits": []}}

        with patch("app.elastic_client.is_connected", return_value=True), \
             patch("app.elastic_client._es", mock_es), \
             patch("app.drift_monitor.logger.info") as mock_log:
            await drift_monitor.check_model_drift_and_trigger()
            mock_log.assert_any_call("[Drift Monitor] No resolved threat records found in ES")

    @pytest.mark.asyncio
    async def test_drift_check_below_threshold(self):
        """Verify no trigger when FPR is below threshold."""
        mock_es = MagicMock()
        # 4 approved (TP), 1 rejected (FP) -> FPR = 0.20 but total is 5, threshold is 0.15. Wait, 0.20 is above 0.15.
        # Let's do: 4 approved (TP), 0 rejected (FP) -> FPR = 0.0
        hits = [
            {"_source": {"resolution": "approved"}},
            {"_source": {"resolution": "approved"}},
            {"_source": {"resolution": "approved"}},
            {"_source": {"resolution": "approved"}},
            {"_source": {"resolution": "approved"}},
        ]
        mock_es.search.return_value = {"hits": {"hits": hits}}

        with patch("app.elastic_client.is_connected", return_value=True), \
             patch("app.elastic_client._es", mock_es), \
             patch("app.drift_monitor.trigger_github_retraining") as mock_trigger:
            await drift_monitor.check_model_drift_and_trigger()
            mock_trigger.assert_not_called()

    @pytest.mark.asyncio
    async def test_drift_check_above_threshold_triggers_retraining(self):
        """Verify dispatch triggers when FPR exceeds 15% and has enough samples."""
        mock_es = MagicMock()
        # 3 approved, 2 rejected -> 2/5 = 40% FPR (above 15%)
        hits = [
            {"_source": {"resolution": "approved"}},
            {"_source": {"resolution": "approved"}},
            {"_source": {"resolution": "approved"}},
            {"_source": {"resolution": "rejected"}},
            {"_source": {"resolution": "rejected"}},
        ]
        mock_es.search.return_value = {"hits": {"hits": hits}}

        with patch("app.elastic_client.is_connected", return_value=True), \
             patch("app.elastic_client._es", mock_es), \
             patch("app.drift_monitor.trigger_github_retraining") as mock_trigger:
            await drift_monitor.check_model_drift_and_trigger()
            mock_trigger.assert_called_once_with(0.40, 5)

    @pytest.mark.asyncio
    async def test_trigger_github_retraining_success(self):
        """Verify GitHub API repository dispatch trigger with mock urllib response."""
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.read.return_value = b""

        with patch("app.vault_client.get_github_pat", return_value="mock-token"), \
             patch("app.drift_monitor._send_dispatch", return_value=(204, b"")) as mock_send, \
             patch("app.drift_monitor.logger.warning") as mock_log:
            await drift_monitor.trigger_github_retraining(0.25, 8)
            mock_send.assert_called_once()
            args, kwargs = mock_send.call_args
            assert args[0] == "https://api.github.com/repos/Prasadadi18/hp/dispatches"
            assert "Authorization" in args[1]
            assert args[1]["Authorization"] == "Bearer mock-token"
            assert args[2]["event_type"] == "ml_drift_detected"
            assert args[2]["client_payload"]["false_positive_rate"] == 0.25
            mock_log.assert_any_call("[Drift Monitor] Successfully triggered GitHub retraining workflow!")
