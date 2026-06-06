"""
elastic_client.py — Real Elasticsearch client for audit logging and threat indexing.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from elasticsearch import Elasticsearch
from app.config import ELASTICSEARCH_URL, ES_AUDIT_INDEX, ES_THREATS_INDEX

logger = logging.getLogger("hpe.elastic")

_es: Optional[Elasticsearch] = None
_connected = False


# ── Index mappings ─────────────────────────────────────────────────────────────
AUDIT_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "event_id": {"type": "keyword"},
            "pipeline_stage": {"type": "keyword"},
            "action_taken": {"type": "keyword"},
            "threat_score": {"type": "float"},
            "is_threat": {"type": "boolean"},
            "source_ip": {"type": "ip", "ignore_malformed": True},
            "destination_ip": {"type": "ip", "ignore_malformed": True},
            "user": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "process_name": {"type": "keyword"},
            "details": {"type": "object", "enabled": False},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    }
}

THREATS_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "event_id": {"type": "keyword"},
            "threat_score": {"type": "float"},
            "threat_action": {"type": "keyword"},
            "attack_type": {"type": "keyword"},
            "source_ip": {"type": "ip", "ignore_malformed": True},
            "destination_ip": {"type": "ip", "ignore_malformed": True},
            "user": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "xgb_score": {"type": "float"},
            "lgb_score": {"type": "float"},
            "ensemble_score": {"type": "float"},
            "vault_rotation_triggered": {"type": "boolean"},
            "credentials_rotated": {"type": "boolean"},
            "resolution": {"type": "keyword"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    }
}


def connect_elasticsearch() -> bool:
    """Initialize Elasticsearch connection and create indices."""
    global _es, _connected

    try:
        _es = Elasticsearch(
            ELASTICSEARCH_URL,
            request_timeout=10,
            max_retries=3,
            retry_on_timeout=True,
        )

        # Check connection
        info = _es.info()
        logger.info(f"Elasticsearch connected: {info['version']['number']}")

        # Create indices if they don't exist
        for index_name, mapping in [(ES_AUDIT_INDEX, AUDIT_MAPPING), (ES_THREATS_INDEX, THREATS_MAPPING)]:
            if not _es.indices.exists(index=index_name):
                _es.indices.create(index=index_name, body=mapping)
                logger.info(f"Created ES index: {index_name}")
            else:
                logger.info(f"ES index exists: {index_name}")

        _connected = True
        return True

    except Exception as e:
        logger.error(f"Elasticsearch connection failed: {e}")
        _connected = False
        return False


def is_connected() -> bool:
    """Check if Elasticsearch is connected."""
    return _connected


def index_audit_log(event_id: str, stage: str, action: str, threat_score: float,
                    is_threat: bool, event_data: Dict[str, Any]) -> bool:
    """Index an audit log entry into Elasticsearch."""
    if not _es or not _connected:
        return False

    try:
        doc = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": event_id,
            "pipeline_stage": stage,
            "action_taken": action,
            "threat_score": threat_score,
            "is_threat": is_threat,
            "source_ip": event_data.get("source_ip", "0.0.0.0"),
            "destination_ip": event_data.get("destination_ip", "0.0.0.0"),
            "user": event_data.get("user", "unknown"),
            "event_type": event_data.get("event_type", "unknown"),
            "process_name": event_data.get("process_name", ""),
            "details": event_data,
        }
        _es.index(index=ES_AUDIT_INDEX, document=doc)
        return True
    except Exception as e:
        logger.error(f"ES index audit error: {e}")
        return False


def index_threat(event_id: str, threat_data: Dict[str, Any]) -> bool:
    """Index a threat detection entry."""
    if not _es or not _connected:
        return False

    try:
        doc = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **threat_data,
        }
        _es.index(index=ES_THREATS_INDEX, document=doc)
        return True
    except Exception as e:
        logger.error(f"ES index threat error: {e}")
        return False


def search_recent_threats(size: int = 20) -> List[Dict[str, Any]]:
    """Fetch recent threat detections from Elasticsearch."""
    if not _es or not _connected:
        return []

    try:
        result = _es.search(
            index=ES_THREATS_INDEX,
            body={
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": size,
            }
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]
    except Exception as e:
        logger.error(f"ES search error: {e}")
        return []


def get_threat_stats() -> Dict[str, int]:
    """Get aggregated threat statistics from Elasticsearch."""
    if not _es or not _connected:
        return {}

    try:
        result = _es.search(
            index=ES_THREATS_INDEX,
            body={
                "size": 0,
                "aggs": {
                    "by_action": {
                        "terms": {"field": "threat_action"}
                    },
                    "by_attack_type": {
                        "terms": {"field": "attack_type", "size": 20}
                    }
                }
            }
        )
        aggs = result.get("aggregations", {})
        stats = {}
        for bucket in aggs.get("by_action", {}).get("buckets", []):
            stats[bucket["key"]] = bucket["doc_count"]
        return stats
    except Exception as e:
        logger.error(f"ES stats error: {e}")
        return {}


def disconnect_elasticsearch():
    """Close the Elasticsearch connection."""
    global _es, _connected
    if _es:
        _es.close()
    _connected = False
    logger.info("Elasticsearch disconnected")


def update_threat_resolution(event_id: str, resolution: str) -> bool:
    """Update a threat record with the admin resolution status (approved / rejected)."""
    if not _es or not _connected:
        return False
    try:
        res = _es.search(
            index=ES_THREATS_INDEX,
            body={
                "query": {"term": {"event_id.keyword": event_id}},
                "size": 1
            }
        )
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            doc_id = hits[0]["_id"]
            _es.update(
                index=ES_THREATS_INDEX,
                id=doc_id,
                body={"doc": {"resolution": resolution}}
            )
            logger.info(f"Updated ES threat resolution for event {event_id} to '{resolution}'")
            return True
        else:
            logger.warning(f"Threat record for event {event_id} not found in ES")
            return False
    except Exception as e:
        logger.error(f"Failed to update ES threat resolution: {e}")
        return False
