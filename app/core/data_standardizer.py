"""
Data Standardizer — transforms raw flow data into CIC-IDS feature DataFrames.

Provides helpers for three ingest paths:

1. ``from_redis_flow(flow_hash)`` — for live SSE (reads Redis HGETALL dict)
2. ``from_csv(file_path)`` — for batch upload of CIC-IDS CSVs
3. ``from_pcap(file_path)`` — for PCAP upload via CICFlowMeter (offline)

All paths produce a ``pd.DataFrame`` with columns matching the ordered
feature list expected by the LightGBM model.
"""

from __future__ import annotations

import os
import tempfile
import threading
from typing import Any

import numpy as np
import pandas as pd

# IANA protocol number -> short name, mirroring the PROTO_MAP table the
# routes layer uses to format the response. Kept here so the NFStream PCAP
# extractor can fill a `protocol_name` column on each flow row.
_PROTO_NUM_TO_NAME = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 132: "SCTP"}

# ---------------------------------------------------------------------------
# CICFlowMeter: correct CWR flag count (upstream duplicates fwd_urg_flags).
# Applied once; safe for concurrent ``from_pcap`` calls.
# ---------------------------------------------------------------------------
_cf_flow_get_data_orig: Any = None
_cf_cwr_patch_lock = threading.Lock()


def _ensure_cicflowmeter_cwr_patch() -> None:
    global _cf_flow_get_data_orig
    with _cf_cwr_patch_lock:
        if _cf_flow_get_data_orig is not None:
            return
        import cicflowmeter.flow as cf_flow_module
        from cicflowmeter.features.flag_count import FlagCount

        _cf_flow_get_data_orig = cf_flow_module.Flow.get_data

        def _patched_get_data(self: Any, include_fields: Any = None) -> dict[str, Any]:
            data = _cf_flow_get_data_orig(self, include_fields)
            data["cwr_flag_count"] = FlagCount(self).count("CWR")
            return data

        cf_flow_module.Flow.get_data = _patched_get_data  # type: ignore[method-assign]


class DataStandardizer:
    """Prepare data for the CIC-IDS LightGBM multiclass model."""

    def __init__(self, selected_features: list[str]) -> None:
        self.selected_features = selected_features

    # ------------------------------------------------------------------
    # Ingest helpers
    # ------------------------------------------------------------------

    # Map from snake_case Redis keys → CIC-IDS feature names
    _REDIS_TO_CIC: dict[str, str] = {
        "dst_port": "Dst Port",
        "protocol": "Protocol",
        "flow_duration": "Flow Duration",
        "fwd_packet_length_max": "Fwd Packet Length Max",
        "fwd_packet_length_min": "Fwd Packet Length Min",
        "fwd_packet_length_mean": "Fwd Packet Length Mean",
        "fwd_packet_length_std": "Fwd Packet Length Std",
        "bwd_packet_length_max": "Bwd Packet Length Max",
        "bwd_packet_length_min": "Bwd Packet Length Min",
        "bwd_packet_length_mean": "Bwd Packet Length Mean",
        "bwd_packet_length_std": "Bwd Packet Length Std",
        "packet_length_max": "Packet Length Max",
        "packet_length_min": "Packet Length Min",
        "packet_length_mean": "Packet Length Mean",
        "packet_length_std": "Packet Length Std",
        "packet_length_variance": "Packet Length Variance",
        "fwd_header_length": "Fwd Header Length",
        "bwd_header_length": "Bwd Header Length",
        "min_seg_size_forward": "Fwd Seg Size Min",
        "act_data_pkt_fwd": "Fwd Act Data Pkts",
        "flow_iat_mean": "Flow IAT Mean",
        "flow_iat_max": "Flow IAT Max",
        "flow_iat_min": "Flow IAT Min",
        "flow_iat_std": "Flow IAT Std",
        "fwd_iat_total": "Fwd IAT Total",
        "fwd_iat_max": "Fwd IAT Max",
        "fwd_iat_min": "Fwd IAT Min",
        "fwd_iat_mean": "Fwd IAT Mean",
        "fwd_iat_std": "Fwd IAT Std",
        "bwd_iat_total": "Bwd IAT Total",
        "bwd_iat_max": "Bwd IAT Max",
        "bwd_iat_min": "Bwd IAT Min",
        "bwd_iat_mean": "Bwd IAT Mean",
        "bwd_iat_std": "Bwd IAT Std",
        "subflow_fwd_packets": "Subflow Fwd Packets",
        "subflow_fwd_bytes": "Subflow Fwd Bytes",
        "subflow_bwd_packets": "Subflow Bwd Packets",
        "subflow_bwd_bytes": "Subflow Bwd Bytes",
        "fin_flag_count": "FIN Flag Count",
        "syn_flag_count": "SYN Flag Count",
        "rst_flag_count": "RST Flag Count",
        "psh_flag_count": "PSH Flag Count",
        "ack_flag_count": "ACK Flag Count",
        "urg_flag_count": "URG Flag Count",
        "fwd_psh_flags": "Fwd PSH Flags",
        "bwd_psh_flags": "Bwd PSH Flags",
        "fwd_urg_flags": "Fwd URG Flags",
        "bwd_urg_flags": "Bwd URG Flags",
        "down_up_ratio": "Down/Up Ratio",
        "avg_fwd_segment_size": "Fwd Segment Size Avg",
        "avg_bwd_segment_size": "Bwd Segment Size Avg",
        "avg_packet_size": "Average Packet Size",
        "flow_bytes_per_sec": "Flow Bytes/s",
        "flow_packets_per_sec": "Flow Packets/s",
        "fwd_packets_per_sec": "Fwd Packets/s",
        "bwd_packets_per_sec": "Bwd Packets/s",
        "total_fwd_packets": "Total Fwd Packets",
        "total_bwd_packets": "Total Backward Packets",
        "total_length_fwd_packets": "Total Length of Fwd Packets",
        "total_length_bwd_packets": "Total Length of Bwd Packets",
        "init_win_bytes_forward": "FWD Init Win Bytes",
        "init_win_bytes_backward": "Bwd Init Win Bytes",
        "active_max": "Active Max",
        "active_min": "Active Min",
        "active_mean": "Active Mean",
        "active_std": "Active Std",
        "idle_max": "Idle Max",
        "idle_min": "Idle Min",
        "idle_mean": "Idle Mean",
        "idle_std": "Idle Std",
        "fwd_avg_bytes_per_bulk": "Fwd Bytes/Bulk Avg",
        "fwd_avg_packets_per_bulk": "Fwd Packet/Bulk Avg",
        "fwd_avg_bulk_rate": "Fwd Bulk Rate Avg",
        "bwd_avg_bytes_per_bulk": "Bwd Bytes/Bulk Avg",
        "bwd_avg_packets_per_bulk": "Bwd Packet/Bulk Avg",
        "bwd_avg_bulk_rate": "Bwd Bulk Rate Avg",
    }

    # Reverse mapping: CIC name → redis key
    _CIC_TO_REDIS: dict[str, str] = {v: k for k, v in _REDIS_TO_CIC.items()}

    def from_redis_flow(self, flow_hash: dict[str, str]) -> pd.DataFrame:
        """Build a single-row DataFrame from a Redis ``HGETALL`` result.

        All values coming from Redis are strings; this method casts them
        to ``float64`` and ensures the column order matches the model.

        The flow_meter_worker stores features with snake_case names.
        This method maps them to the CIC-IDS feature names the model expects.
        """
        row: dict[str, float] = {}
        for feat in self.selected_features:
            # Try CIC name directly, then mapped redis key
            redis_key = self._CIC_TO_REDIS.get(feat, feat)
            raw = flow_hash.get(redis_key) or flow_hash.get(feat, "0")
            try:
                row[feat] = float(raw)
            except (ValueError, TypeError):
                row[feat] = 0.0

        df = pd.DataFrame([row])
        return self._clean(df)

    def from_records(self, records: list[dict]) -> pd.DataFrame:
        """Build a feature DataFrame from a list of plain dicts.

        Used by the ``/analyze/manual`` endpoint where the analyst types
        a handful of flow features into the form. Keys may use the
        snake_case Redis names (``sbytes``, ``sttl``…) or the CIC-IDS
        column names directly; both are accepted by ``from_redis_flow``'s
        mapping so we reuse it row-by-row.
        """
        if not records:
            return pd.DataFrame(columns=list(self.selected_features))
        rows: list[pd.DataFrame] = [
            self.from_redis_flow({k: str(v) for k, v in r.items()})
            for r in records
        ]
        df = pd.concat(rows, ignore_index=True)
        return df

    def from_excel(self, file_path: str) -> pd.DataFrame:
        """Load a CIC-IDS formatted Excel workbook (first sheet)."""
        self._validate_file(file_path)
        df = pd.read_excel(file_path)
        df.columns = df.columns.str.strip()
        return self._process(df)

    def from_csv(self, file_path: str) -> pd.DataFrame:
        """Load a CIC-IDS formatted CSV.

        Handles column-name whitespace and missing features.
        """
        self._validate_file(file_path)
        df = pd.read_csv(file_path)
        df.columns = df.columns.str.strip()
        return self._process(df)

    def from_pcap(self, file_path: str, progress_cb: Any = None) -> pd.DataFrame:
        """Convert a PCAP to CIC-IDS features via NFStream (offline).

        Aligned with the live capture worker (``flow_meter_worker.py``) so
        both paths produce identical feature values for the same flow —
        previously upload used CICFlowMeter/Scapy which both differed in
        IAT semantics from NFStream and took 8-12 min on a 400 MB PCAP.
        NFStream is C-backed via libpcap+nDPI and processes the same file
        in well under a minute.

        ``progress_cb(stage, info)`` is an optional callable invoked at each
        milestone so callers can stream progress events. Stages are:
        ``"nfstream:start"``, ``"nfstream:flow"``, ``"nfstream:done"``.
        """
        self._validate_file(file_path)

        try:
            df_raw = self._nfstream_pcap_to_raw_df(file_path, progress_cb=progress_cb)
        except ImportError as exc:
            raise ImportError(
                "PCAP feature extraction requires nfstream. "
                "Install with: pip install nfstream"
            ) from exc

        if df_raw is None or df_raw.empty:
            raise ValueError(
                "No TCP/UDP flows extracted from the PCAP. NFStream only "
                "analyses IPv4/IPv6 TCP and UDP traffic."
            )

        df = self._map_nfstream_to_cic(df_raw)
        return self._process(df)

    @staticmethod
    def _nfstream_pcap_to_raw_df(file_path: str, progress_cb: Any = None) -> pd.DataFrame:
        """Run NFStream offline against the PCAP and return a DataFrame keyed
        on raw NFStream attribute names (the same column set the live worker
        emits, ready for ``_map_nfstream_to_cic``).

        Iterates ``for flow in streamer`` instead of calling
        ``streamer.to_pandas()`` to keep NFStream's multiprocessing manager
        out of the FastAPI worker process — ``to_pandas()`` spawns helpers
        that misbehave on Windows under uvicorn's reload watcher.
        """
        from nfstream import NFStreamer

        # Attribute set required by _map_nfstream_to_cic + routes.py response
        # builder. Captured once per flow so we don't pay attribute-lookup
        # overhead on millions of getattr calls.
        attr_names = (
            "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "ip_version",
            # Wall-clock of the flow's first packet (epoch ms). Carried
            # through so the API can stamp predictions with the capture
            # time instead of the upload time — needed for the analytics
            # timeline to reflect when the attack actually happened in
            # the PCAP, not when the analyst uploaded it.
            "bidirectional_first_seen_ms",
            "bidirectional_duration_ms", "bidirectional_packets",
            "bidirectional_bytes", "bidirectional_min_ps", "bidirectional_max_ps",
            "bidirectional_mean_ps", "bidirectional_stddev_ps",
            "bidirectional_min_piat_ms", "bidirectional_max_piat_ms",
            "bidirectional_mean_piat_ms", "bidirectional_stddev_piat_ms",
            "src2dst_duration_ms", "src2dst_packets", "src2dst_bytes",
            "src2dst_min_ps", "src2dst_max_ps", "src2dst_mean_ps",
            "src2dst_stddev_ps", "src2dst_min_piat_ms", "src2dst_max_piat_ms",
            "src2dst_mean_piat_ms", "src2dst_stddev_piat_ms",
            "dst2src_duration_ms", "dst2src_packets", "dst2src_bytes",
            "dst2src_min_ps", "dst2src_max_ps", "dst2src_mean_ps",
            "dst2src_stddev_ps", "dst2src_min_piat_ms", "dst2src_max_piat_ms",
            "dst2src_mean_piat_ms", "dst2src_stddev_piat_ms",
            "src2dst_syn_packets", "src2dst_fin_packets", "src2dst_rst_packets",
            "src2dst_psh_packets", "src2dst_ack_packets", "src2dst_urg_packets",
            "src2dst_cwr_packets", "src2dst_ece_packets",
            "dst2src_syn_packets", "dst2src_fin_packets", "dst2src_rst_packets",
            "dst2src_psh_packets", "dst2src_ack_packets", "dst2src_urg_packets",
            "dst2src_cwr_packets", "dst2src_ece_packets",
        )

        streamer = NFStreamer(
            source=file_path,
            # Disable DPI — we don't use the service field at inference time
            # and it adds ~30% to per-flow cost.
            n_dissections=0,
            statistical_analysis=True,
            # Tight idle_timeout (30s) chosen empirically — see
            # .tmp/sweep_nfstream_timeouts.py: of the candidates tested,
            # idle=30 / active=1800 maximised ML-solo precision (0.9770)
            # and recall (0.9721) on the CIC-IDS Wednesday slices.
            # Shorter flows keep benign/attack packets from being mixed
            # into one ambiguous row, which is exactly what was hurting
            # `ml_only` precision under the previous idle=120 default.
            idle_timeout=30,
            active_timeout=1800,
        )

        if progress_cb is not None:
            try:
                progress_cb("nfstream:start", {"file": file_path})
            except Exception:
                pass

        rows: list[dict] = []
        for flow in streamer:
            row = {name: getattr(flow, name, 0) for name in attr_names}
            # Routes look this field up by name for the response; NFStream
            # exposes a numeric protocol but no human-readable name in
            # offline mode when n_dissections=0, so synthesize it from the
            # IANA number used by the rest of the app.
            row["protocol_name"] = _PROTO_NUM_TO_NAME.get(int(row["protocol"]), "")
            rows.append(row)
            if progress_cb is not None and len(rows) % 500 == 0:
                try:
                    progress_cb("nfstream:flow", {"count": len(rows)})
                except Exception:
                    pass

        if progress_cb is not None:
            try:
                progress_cb("nfstream:done", {"count": len(rows)})
            except Exception:
                pass

        return pd.DataFrame(rows) if rows else pd.DataFrame()

    @staticmethod
    def _cicflowmeter_pcap_to_raw_df(file_path: str) -> pd.DataFrame:
        """Run CICFlowMeter offline extraction; return raw CSV columns."""
        _ensure_cicflowmeter_cwr_patch()

        from cicflowmeter.flow_session import FlowSession
        from scapy.sendrecv import sniff

        fd, csv_path = tempfile.mkstemp(suffix=".csv", prefix="cicflowmeter-")
        os.close(fd)
        try:
            session = FlowSession(
                output_mode="csv",
                output=csv_path,
                fields=None,
                verbose=False,
            )
            # Avoid BPF filters: on Windows, Scapy may require tcpdump for filtered offline sniff.
            sniff_kw: dict[str, Any] = {
                "offline": file_path,
                "prn": session.process,
                "store": False,
            }
            max_pk = os.environ.get("CICFLOWMETER_SNIFF_MAX_PACKETS")
            if max_pk is not None and str(max_pk).strip() != "":
                sniff_kw["count"] = int(max_pk)
            sniff(**sniff_kw)
            session.flush_flows()

            if not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0:
                return pd.DataFrame()

            df = pd.read_csv(csv_path, low_memory=False)
        finally:
            try:
                os.unlink(csv_path)
            except OSError:
                pass

        df.columns = df.columns.str.strip()
        return df

    @staticmethod
    def _map_cicflowmeter_to_cic(df: pd.DataFrame) -> pd.DataFrame:
        """Map cicflowmeter CSV columns to CIC-IDS feature names.

        CICFlowMeter reports durations and inter-arrival statistics in
        **seconds**; the rest of this app (NFStream / Redis) uses
        **milliseconds** for the same CIC column names — scale before rename.
        """
        sec_to_ms_cols = {
            "flow_duration",
            "flow_iat_mean",
            "flow_iat_max",
            "flow_iat_min",
            "flow_iat_std",
            "fwd_iat_tot",
            "fwd_iat_max",
            "fwd_iat_min",
            "fwd_iat_mean",
            "fwd_iat_std",
            "bwd_iat_tot",
            "bwd_iat_max",
            "bwd_iat_min",
            "bwd_iat_mean",
            "bwd_iat_std",
            "active_max",
            "active_min",
            "active_mean",
            "active_std",
            "idle_max",
            "idle_min",
            "idle_mean",
            "idle_std",
        }
        for col in sec_to_ms_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0) * 1000.0

        rename_map = {
            "dst_port": "Dst Port",
            "protocol": "Protocol",
            "flow_duration": "Flow Duration",
            "fwd_pkt_len_max": "Fwd Packet Length Max",
            "fwd_pkt_len_min": "Fwd Packet Length Min",
            "fwd_pkt_len_mean": "Fwd Packet Length Mean",
            "fwd_pkt_len_std": "Fwd Packet Length Std",
            "bwd_pkt_len_max": "Bwd Packet Length Max",
            "bwd_pkt_len_min": "Bwd Packet Length Min",
            "bwd_pkt_len_mean": "Bwd Packet Length Mean",
            "bwd_pkt_len_std": "Bwd Packet Length Std",
            "pkt_len_max": "Packet Length Max",
            "pkt_len_min": "Packet Length Min",
            "pkt_len_mean": "Packet Length Mean",
            "pkt_len_std": "Packet Length Std",
            "pkt_len_var": "Packet Length Variance",
            "fwd_header_len": "Fwd Header Length",
            "bwd_header_len": "Bwd Header Length",
            "fwd_seg_size_min": "Fwd Seg Size Min",
            "fwd_act_data_pkts": "Fwd Act Data Pkts",
            "flow_iat_mean": "Flow IAT Mean",
            "flow_iat_max": "Flow IAT Max",
            "flow_iat_min": "Flow IAT Min",
            "flow_iat_std": "Flow IAT Std",
            "fwd_iat_tot": "Fwd IAT Total",
            "fwd_iat_max": "Fwd IAT Max",
            "fwd_iat_min": "Fwd IAT Min",
            "fwd_iat_mean": "Fwd IAT Mean",
            "fwd_iat_std": "Fwd IAT Std",
            "bwd_iat_tot": "Bwd IAT Total",
            "bwd_iat_max": "Bwd IAT Max",
            "bwd_iat_min": "Bwd IAT Min",
            "bwd_iat_mean": "Bwd IAT Mean",
            "bwd_iat_std": "Bwd IAT Std",
            "fwd_psh_flags": "Fwd PSH Flags",
            "bwd_psh_flags": "Bwd PSH Flags",
            "fwd_urg_flags": "Fwd URG Flags",
            "bwd_urg_flags": "Bwd URG Flags",
            "fin_flag_cnt": "FIN Flag Count",
            "syn_flag_cnt": "SYN Flag Count",
            "rst_flag_cnt": "RST Flag Count",
            "psh_flag_cnt": "PSH Flag Count",
            "ack_flag_cnt": "ACK Flag Count",
            "urg_flag_cnt": "URG Flag Count",
            "cwr_flag_count": "CWR Flag Count",
            "ece_flag_cnt": "ECE Flag Count",
            "down_up_ratio": "Down/Up Ratio",
            "pkt_size_avg": "Average Packet Size",
            "fwd_seg_size_avg": "Fwd Segment Size Avg",
            "bwd_seg_size_avg": "Bwd Segment Size Avg",
            "fwd_byts_b_avg": "Fwd Bytes/Bulk Avg",
            "fwd_pkts_b_avg": "Fwd Packet/Bulk Avg",
            "fwd_blk_rate_avg": "Fwd Bulk Rate Avg",
            "bwd_byts_b_avg": "Bwd Bytes/Bulk Avg",
            "bwd_pkts_b_avg": "Bwd Packet/Bulk Avg",
            "bwd_blk_rate_avg": "Bwd Bulk Rate Avg",
            "subflow_fwd_pkts": "Subflow Fwd Packets",
            "subflow_fwd_byts": "Subflow Fwd Bytes",
            "subflow_bwd_pkts": "Subflow Bwd Packets",
            "subflow_bwd_byts": "Subflow Bwd Bytes",
            "init_fwd_win_byts": "FWD Init Win Bytes",
            "init_bwd_win_byts": "Bwd Init Win Bytes",
            "active_mean": "Active Mean",
            "active_std": "Active Std",
            "active_max": "Active Max",
            "active_min": "Active Min",
            "idle_mean": "Idle Mean",
            "idle_std": "Idle Std",
            "idle_max": "Idle Max",
            "idle_min": "Idle Min",
        }

        existing = {k: v for k, v in rename_map.items() if k in df.columns}
        df = df.rename(columns=existing)
        return df

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_file(file_path: str) -> None:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        _, ext = os.path.splitext(file_path)
        valid = {".csv", ".xlsx", ".xls", ".pcap", ".pcapng"}
        if ext.lower() not in valid:
            raise ValueError(
                f"Unsupported extension: {ext}. Supported: {sorted(valid)}"
            )

    def _process(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ensure every selected feature exists and clean numeric issues."""
        for col in self.selected_features:
            if col not in df.columns:
                df[col] = 0

        return self._clean(df)

    def _clean(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replace inf/NaN and ensure float dtype for selected features."""
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        # Ensure selected columns are numeric and have no NaNs
        for col in self.selected_features:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

        # Also fill NaN with 0 for any other remaining columns just in case, but keep strings intact
        for col in df.columns:
            if col not in self.selected_features and df[col].dtype.kind in 'bifc':
                df[col] = df[col].fillna(0)

        return df

    # ------------------------------------------------------------------
    # NFStream → CIC-IDS column mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _map_nfstream_to_cic(df: pd.DataFrame) -> pd.DataFrame:
        """Best-effort mapping from NFStream attribute names to CIC-IDS
        feature names used by the training dataset.

        NFStream and CIC-IDS use different naming conventions.  This
        mapping covers the features that have direct or close equivalents.
        Missing features are filled with 0 in ``_process()``.
        """
        mapping = {
            "dst_port": "Dst Port",
            "protocol": "Protocol",
            "bidirectional_duration_ms": "Flow Duration",
            "src2dst_max_ps": "Fwd Packet Length Max",
            "src2dst_min_ps": "Fwd Packet Length Min",
            "src2dst_mean_ps": "Fwd Packet Length Mean",
            "src2dst_stddev_ps": "Fwd Packet Length Std",
            "dst2src_max_ps": "Bwd Packet Length Max",
            "dst2src_min_ps": "Bwd Packet Length Min",
            "dst2src_mean_ps": "Bwd Packet Length Mean",
            "dst2src_stddev_ps": "Bwd Packet Length Std",
            "bidirectional_max_ps": "Packet Length Max",
            "bidirectional_min_ps": "Packet Length Min",
            "bidirectional_mean_ps": "Packet Length Mean",
            "bidirectional_stddev_ps": "Packet Length Std",
            "bidirectional_mean_piat_ms": "Flow IAT Mean",
            "bidirectional_max_piat_ms": "Flow IAT Max",
            "bidirectional_min_piat_ms": "Flow IAT Min",
            "bidirectional_stddev_piat_ms": "Flow IAT Std",
            "src2dst_duration_ms": "Fwd IAT Total",
            "src2dst_max_piat_ms": "Fwd IAT Max",
            "src2dst_min_piat_ms": "Fwd IAT Min",
            "src2dst_mean_piat_ms": "Fwd IAT Mean",
            "src2dst_stddev_piat_ms": "Fwd IAT Std",
            "dst2src_duration_ms": "Bwd IAT Total",
            "dst2src_max_piat_ms": "Bwd IAT Max",
            "dst2src_min_piat_ms": "Bwd IAT Min",
            "dst2src_mean_piat_ms": "Bwd IAT Mean",
            "dst2src_stddev_piat_ms": "Bwd IAT Std",
            "src2dst_packets": "Subflow Fwd Packets",
            "src2dst_bytes": "Subflow Fwd Bytes",
            "dst2src_packets": "Subflow Bwd Packets",
            "dst2src_bytes": "Subflow Bwd Bytes",
        }
        # pyrefly: ignore [missing-attribute]
        df = df.rename(columns=mapping)

        # Computed features
        if "Packet Length Std" in df.columns:
            df["Packet Length Variance"] = df["Packet Length Std"] ** 2

        if "Fwd Packet Length Mean" in df.columns:
            df["Fwd Segment Size Avg"] = df["Fwd Packet Length Mean"]
        if "Bwd Packet Length Mean" in df.columns:
            df["Bwd Segment Size Avg"] = df["Bwd Packet Length Mean"]
        if "Packet Length Mean" in df.columns:
            df["Average Packet Size"] = df["Packet Length Mean"]

        if "Fwd Packet Length Min" in df.columns:
            df["Fwd Seg Size Min"] = df["Fwd Packet Length Min"]
        if "Subflow Fwd Packets" in df.columns:
            df["Fwd Act Data Pkts"] = df["Subflow Fwd Packets"]

        # TCP flag aggregates
        for flag in ["fin", "syn", "rst", "psh", "ack", "urg", "cwr", "ece"]:
            src_col = f"src2dst_{flag}_packets"
            dst_col = f"dst2src_{flag}_packets"
            cic_col = f"{flag.upper()} Flag Count"
            if src_col in df.columns and dst_col in df.columns:
                df[cic_col] = df[src_col] + df[dst_col]

        # Directional flag counts
        if "src2dst_psh_packets" in df.columns:
            df["Fwd PSH Flags"] = df["src2dst_psh_packets"]
        if "dst2src_psh_packets" in df.columns:
            df["Bwd PSH Flags"] = df["dst2src_psh_packets"]
        if "src2dst_urg_packets" in df.columns:
            df["Fwd URG Flags"] = df["src2dst_urg_packets"]
        if "dst2src_urg_packets" in df.columns:
            df["Bwd URG Flags"] = df["dst2src_urg_packets"]

        # Header length estimates
        if "Subflow Fwd Packets" in df.columns:
            df["Fwd Header Length"] = df["Subflow Fwd Packets"] * 20
        if "Subflow Bwd Packets" in df.columns:
            df["Bwd Header Length"] = df["Subflow Bwd Packets"] * 20

        # Down/Up Ratio
        if "Subflow Fwd Packets" in df.columns and "Subflow Bwd Packets" in df.columns:
            df["Down/Up Ratio"] = df["Subflow Bwd Packets"] / (
                df["Subflow Fwd Packets"].replace(0, 1)
            )

        return df
