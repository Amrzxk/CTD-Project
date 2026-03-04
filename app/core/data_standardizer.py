import pandas as pd
import numpy as np
import os
from app.utils.feature_mapping import NFSTREAM_TO_MODEL

DROP_COLUMNS = ["id", "srcip", "dstip", "stime", "ltime", "attack_cat", "label"]

class DataStandardizer:

    def __init__(self, selected_features):
        self.selected_features = selected_features

    def validate_file(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        valid_extensions = ['.csv', '.xlsx', '.xls', '.pcap', '.pcapng']
        _, ext = os.path.splitext(file_path)
        if ext.lower() not in valid_extensions:
            raise ValueError(f"Unsupported file extension: {ext}. Supported: {valid_extensions}")
        return True

    def from_csv(self, file_path):
        self.validate_file(file_path)
        df = pd.read_csv(file_path)
        return self._process_dataframe(df)

    def from_excel(self, file_path):
        self.validate_file(file_path)
        df = pd.read_excel(file_path)
        return self._process_dataframe(df)

    def from_records(self, records: list[dict]):
        """
        Creates a DataFrame from a list of dictionaries (manual input).
        Calculates derived features from the basic input.
        """
        df = pd.DataFrame(records)
        
        # Calculate derived features (rates, means, etc.)
        # Note: Manual input assumes 'dur' is already in seconds, so we don't divide by 1000 here.
        # _calculate_derived_features handles the rest.
        df = self._calculate_derived_features(df)
        
        return self._process_dataframe(df)

    def from_pcap(self, file_path):
        self.validate_file(file_path)
        
        # Import nfstream only when needed
        try:
            from nfstream import NFStreamer
        except ImportError as e:
            if "DLL load failed" in str(e):
                raise ImportError(
                    "NFStream failed to load. This usually means Npcap is missing.\n"
                    "Please install Npcap from https://npcap.com/#download\n"
                    "IMPORTANT: During installation, check 'Install Npcap in WinPcap API-compatible Mode'."
                ) from e
            raise e
        
        # 1. Faster: Use to_pandas() directly instead of looping
        streamer = NFStreamer(source=file_path)
        df = streamer.to_pandas()

        # 2. Rename columns to match model expectations
        # Map NFStream names to Model names (e.g. src_port -> sport)
        df = df.rename(columns=NFSTREAM_TO_MODEL)
        
        # Map IPs manually for consistency (NFStream uses src_ip, we use srcip in internal logic)
        df = df.rename(columns={'src_ip': 'srcip', 'dst_ip': 'dstip'})
        
        # Convert duration from ms to seconds for rate calculations (NFStream gives ms)
        if 'dur' in df.columns:
             df['dur'] = df['dur'] / 1000.0
        
        # 3. Calculate derived features (State, Rates, CT_ stats)
        df = self._calculate_derived_features(df)
        
        return self._process_dataframe(df)

    def _derive_state(self, row):
        """
        Derives the connection state (CON, FIN, REQ, RST, INT) from TCP flags.
        """
        # 1. Identify Protocol
        proto = row.get('proto')
        is_tcp = False
        if isinstance(proto, str):
            is_tcp = (proto.lower() == 'tcp')
        else:
            is_tcp = (proto == 6) # NFStream uses 6 for TCP

        if not is_tcp:
            return 'INT' # Generic for UDP/Others

        # 2. Check TCP Flags (using NFStream default column names)
        # Summing src->dst and dst->src to get total flow behavior
        s_syn = row.get('src2dst_tcp_syn', 0)
        d_syn = row.get('dst2src_tcp_syn', 0)
        s_fin = row.get('src2dst_tcp_fin', 0)
        d_fin = row.get('dst2src_tcp_fin', 0)
        s_rst = row.get('src2dst_tcp_rst', 0)
        d_rst = row.get('dst2src_tcp_rst', 0)
        s_ack = row.get('src2dst_tcp_ack', 0)
        d_ack = row.get('dst2src_tcp_ack', 0)

        syn = s_syn + d_syn
        fin = s_fin + d_fin
        rst = s_rst + d_rst
        ack = s_ack + d_ack

        # 3. Determine State
        if rst > 0:
            return 'RST'
        if fin > 0:
            return 'FIN'
        if syn > 0 and ack > 0:
            return 'CON'
        if syn > 0:
            return 'REQ'
        
        # Fallback
        return 'CON'

    def _calculate_derived_features(self, df):
        """
        Calculates derived features like sload, dload, and ct_ stats.
        This is primarily for PCAP inputs where these are not pre-calculated.
        """
        # Avoid division by zero
        epsilon = 1e-6

        # Note: 'dur' unit handling (ms vs s) is done in caller (from_pcap vs from_records)

        # Fix Protocol (Int -> String)
        # Common mapping: 6->tcp, 17->udp, 1->icmp
        proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
        if 'proto' in df.columns and pd.api.types.is_numeric_dtype(df['proto']):
             df['proto'] = df['proto'].map(proto_map).fillna('others')

        # Calculate State (only if flags are present, otherwise keep existing state)
        # If 'state' is missing or empty, try to derive it.
        # But _derive_state relies on NFStream specific columns (src2dst_tcp_syn etc.)
        # If manual input provides 'state', we keep it.
        if 'state' not in df.columns:
             # Try to derive if we have flags, else default
             # Check if we have at least one flag column
             if 'src2dst_tcp_syn' in df.columns:
                 df['state'] = df.apply(self._derive_state, axis=1)
             else:
                 df['state'] = 'CON' # Default fallback

        # Basic Rates
        if 'sbytes' in df.columns and 'dur' in df.columns:
            df['sload'] = (df['sbytes'] * 8) / (df['dur'] + epsilon)
        
        if 'dbytes' in df.columns and 'dur' in df.columns:
            df['dload'] = (df['dbytes'] * 8) / (df['dur'] + epsilon)

        # Mean packet sizes
        if 'sbytes' in df.columns and 'spkts' in df.columns:
            df['smeansz'] = df['sbytes'] / (df['spkts'] + epsilon)
            
        if 'dbytes' in df.columns and 'dpkts' in df.columns:
            df['dmeansz'] = df['dbytes'] / (df['dpkts'] + epsilon)

        # TCP RTT (if available, else 0)
        if 'synack' not in df.columns: df['synack'] = 0
        if 'ackdat' not in df.columns: df['ackdat'] = 0
        df['tcprtt'] = df['synack'] + df['ackdat']

        # Identity check
        if 'srcip' in df.columns and 'dstip' in df.columns and 'sport' in df.columns and 'dsport' in df.columns:
             df['is_sm_ips_ports'] = ((df['srcip'] == df['dstip']) & (df['sport'] == df['dsport'])).astype(int)
        else:
             df['is_sm_ips_ports'] = 0

        # CT (Count) Features - Window based / Group based
        
        # ct_srv_src
        if 'service' in df.columns and 'srcip' in df.columns:
            df['ct_srv_src'] = df.groupby(['service', 'srcip'])['service'].transform('count')
        else:
            df['ct_srv_src'] = 0

        # ct_srv_dst
        if 'service' in df.columns and 'dstip' in df.columns:
             df['ct_srv_dst'] = df.groupby(['service', 'dstip'])['service'].transform('count')
        else:
             df['ct_srv_dst'] = 0

        # ct_dst_ltm
        if 'dstip' in df.columns:
            df['ct_dst_ltm'] = df.groupby('dstip')['dstip'].transform('count')
        else:
             df['ct_dst_ltm'] = 0
        
        # ct_src_ltm
        if 'srcip' in df.columns:
            df['ct_src_ltm'] = df.groupby('srcip')['srcip'].transform('count')
        else:
             df['ct_src_ltm'] = 0

        # ct_src_dport_ltm
        if 'srcip' in df.columns and 'dsport' in df.columns:
            df['ct_src_dport_ltm'] = df.groupby(['srcip', 'dsport'])['srcip'].transform('count')
        else:
            df['ct_src_dport_ltm'] = 0

        # ct_dst_sport_ltm
        if 'dstip' in df.columns and 'sport' in df.columns:
            df['ct_dst_sport_ltm'] = df.groupby(['dstip', 'sport'])['dstip'].transform('count')
        else:
            df['ct_dst_sport_ltm'] = 0

        # ct_dst_src_ltm
        if 'srcip' in df.columns and 'dstip' in df.columns:
            df['ct_dst_src_ltm'] = df.groupby(['srcip', 'dstip'])['srcip'].transform('count')
        else:
            df['ct_dst_src_ltm'] = 0
            
        # ct_state_ttl
        if 'state' in df.columns and 'sttl' in df.columns:
             df['ct_state_ttl'] = df.groupby(['state', 'sttl'])['state'].transform('count')
        else:
             df['ct_state_ttl'] = 0
             
        # ct_flw_http_mthd
        if 'trans_depth' in df.columns:
             df['ct_flw_http_mthd'] = df['trans_depth'].apply(lambda x: 1 if x > 0 else 0)
        else:
             df['ct_flw_http_mthd'] = 0
             
        # is_ftp_login
        if 'service' in df.columns:
             df['is_ftp_login'] = df['service'].apply(lambda x: 1 if x == 'ftp' else 0)
        else:
             df['is_ftp_login'] = 0

        # Fill NaNs created by calculations
        df = df.fillna(0)
        
        return df

    def _process_dataframe(self, df):
        
        # 1. Drop identifiers and non-feature columns
        df = df.drop(columns=[col for col in DROP_COLUMNS if col in df.columns], errors="ignore")

        # 2. Handle missing columns (fill with 0 for numeric, 'unknown' for categorical if needed)
        for col in self.selected_features:
            if col not in df.columns:
                if col in ['proto', 'service', 'state']:
                    df[col] = 'unknown' 
                else:
                    df[col] = 0

        # 3. Ensure correct data types for categorical features
        categorical_cols = ['proto', 'service', 'state']
        for col in categorical_cols:
            if col in df.columns:
                df[col] = df[col].astype(str)

        # 4. Feature ordering
        df = df[self.selected_features]

        return df
