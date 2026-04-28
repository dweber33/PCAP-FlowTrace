"""
engine_logic.py - The Brains of the Operation
---------------------------------------------
This file contains the core logic and complex "thinking" of the application.
It manages how PCAP files are processed, synchronized, and exported.

Because processing large network files can take a long time, most of the 
tasks here are run in 'Threads' (QThread). This allows the application 
to stay responsive (not 'freeze') while it works in the background.
"""

import os
import subprocess
import hashlib
import time
import re
import io
from multiprocessing import Pool
from PyQt6.QtCore import QThread, pyqtSignal
from config_manager import ConfigManager
import utils
from logger import get_logger

# Initialize the global logger so we can record what's happening
logger = get_logger()

# A list of interesting network fields we want to extract for analysis
MASTER_FORENSIC_MAP = [
    "frame.number", "frame.time", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.comment",
    "_ws.col.Protocol", "_ws.col.Info", "eth.src", "eth.dst", "vlan.id",
    "ip.src", "ip.dst", "ip.proto", "ip.id", "ip.ttl", "ip.flags",
    "ipv6.src", "ipv6.dst", "icmp.type", "icmp.code",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq", "tcp.ack", "tcp.len",
    "tcp.flags.str", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
    "tcp.window_size_value", "tcp.analysis.initial_rtt", "tcp.analysis.retransmission",
    "udp.srcport", "udp.dstport", "udp.stream", "udp.length",
    "tls.handshake.extensions_server_name", "tls.handshake.type", "tls.record.version",
    "http.host", "http.request.method", "http.request.uri", "http.response.code",
    "dns.qry.name", "dns.a", "dns.aaaa", "dns.qry.type",
    "f5etrail.peer_id", "f5etrail.slot", "f5etrail.tmm", "f5etrail.vip"
]

class WorkflowController:
    """
    The Orchestrator: Manages the high-level steps of the diagnostic workflow.
    """
    @staticmethod
    def run_stage_1_alignment(file_paths):
        """Finds the shared time window across multiple files."""
        logger.log("INFO", "Workflow: Initiating Stage 1 (Time Alignment)...")
        windows = []
        for f in file_paths:
            start, end = utils.get_lean_times(f)
            if start: windows.append((start, end))
        
        if not windows: return None
        # The 'Sync Window' is from the latest start time to the earliest end time
        return {
            "global_start": max(w[0] for w in windows),
            "global_end": min(w[1] for w in windows)
        }

    @staticmethod
    def run_stage_2_summary(file_path):
        """Identifies the top protocols used in a file."""
        logger.log("INFO", f"Workflow: Initiating Stage 2 (Analysis Summary) for {os.path.basename(file_path)}...")
        protos = utils.scout_protocols(file_path, limit=5000)
        return protos

    @staticmethod
    def execute_utility_extraction(file_path, output_path, format_type, detailed=True, progress_callback=None):
        """
        Prepares a list of valid data fields to extract from a PCAP.
        It checks which of our 'MASTER_FORENSIC_MAP' fields actually exist in the file.
        """
        try:
            if progress_callback: progress_callback("Scouting Protocols...", 10)
            logger.log("INFO", "Workflow: Discovery Phase (Deep Protocol Scout)...")
            
            if progress_callback: progress_callback("Mapping Forensic Fields...", 30)
            logger.log("INFO", f"Workflow: Mapping Phase (High-Fidelity Alignment)...")
            
            tshark = ConfigManager.get_tshark_path()
            valid_fields = []
            
            # These basic fields are always included
            base_fields = ["frame.number", "frame.time_epoch", "_ws.col.Protocol", "_ws.col.Info"]
            valid_fields.extend(base_fields)
            
            candidate_fields = [f for f in MASTER_FORENSIC_MAP if f not in base_fields]
            
            # Fast Bulk Validation: We ask TShark if all these fields are 'real' in this file.
            test_cmd = [tshark, "-r", file_path, "-c", "1", "-T", "fields"]
            for f in candidate_fields: test_cmd.extend(["-e", f])
            
            test_res = subprocess.run(test_cmd, capture_output=True, text=True)
            if test_res.returncode == 0:
                valid_fields.extend(candidate_fields)
            else:
                # If some fields are invalid, we filter them out to avoid TShark errors later
                invalid_fields = set()
                if "aren't valid" in test_res.stderr:
                    for line in test_res.stderr.splitlines():
                        field = line.strip()
                        if field and not field.startswith("tshark:"):
                            invalid_fields.add(field)
                
                for f in candidate_fields:
                    if f not in invalid_fields:
                        valid_fields.append(f)
            
            if progress_callback: progress_callback("Preparing Data Stream...", 50)
            logger.log("INFO", f"Workflow: Mapping Complete. Using {len(valid_fields)} forensic fields.")
            return valid_fields
        except Exception as e:
            logger.log("ERROR", f"Workflow Extraction Failure: {str(e)}")
            return None

def harvest_dna_worker(args):
    """
    Worker function for parallel processing. 
    It 'harvests' unique identifiers (DNA) from packets to help match them 
    between two different capture files.
    """
    file_path, protocol, display_filter, dna_fields = args
    tshark = ConfigManager.get_tshark_path()
    
    cmd = [tshark, "-r", file_path, "-T", "fields"]
    if display_filter:
        cmd.extend(["-Y", f"{display_filter} && {protocol.lower()}"])
    else:
        cmd.extend(["-Y", protocol.lower()])
    
    for f in dna_fields:
        cmd.extend(["-e", f])
    
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        dna_map = {} # stream_id -> set of DNA strings
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 2: continue
            sid = parts[0]
            dna = "|".join(parts[1:])
            # For UDP, we use a hash of the first 64 bytes of data as DNA
            if protocol == "UDP" and len(parts) > 1:
                dna = hashlib.sha1(parts[1][:64].encode()).hexdigest()
            
            if sid not in dna_map:
                dna_map[sid] = set()
            dna_map[sid].add(dna)
        return dna_map
    except Exception:
        return {"error": "DNA Harvest Failed"}

class MultiNodeCropThread(QThread):
    """
    BACKGROUND TASK: Normalizes multiple PCAP files.
    It crops them all to the same shared time window so they align perfectly 
    on a timeline.
    """
    log_signal = pyqtSignal(str, str)
    overlap_info = pyqtSignal(dict) 
    finished_signal = pyqtSignal(bool, str, dict) 

    def __init__(self, file_paths, dry_run=False, prefix="FLOWTRACE"):
        super().__init__()
        self.file_paths = file_paths
        self.dry_run = dry_run
        self.prefix = prefix

    def run(self):
        try:
            # Step 1: Find out when these files overlap
            logger.log("INFO", f"Stage 1: Lean Temporal Sync for {len(self.file_paths)} files...")
            overlap_data = WorkflowController.run_stage_1_alignment(self.file_paths)
            
            if not overlap_data:
                self.finished_signal.emit(False, "Could not extract temporal window.", {})
                return

            global_start = overlap_data["global_start"]
            global_end = overlap_data["global_end"]

            # If there is no overlap, we can't sync them!
            if global_start >= global_end:
                logger.log("WARN", "0% temporal overlap detected.")
                self.finished_signal.emit(False, "No shared overlap.", {})
                return

            info = {"overlap_start": global_start, "overlap_end": global_end, "duration": global_end - global_start}
            self.overlap_info.emit(info)

            output_dir = os.path.abspath("output")
            if not os.path.exists(output_dir): os.makedirs(output_dir)
            
            cropped_map = {}
            new_summaries = []
            for i, f in enumerate(self.file_paths):
                base_name = os.path.basename(f)
                name_part, _ = os.path.splitext(base_name)
                # Save the new normalized file with a 'NORM_' prefix
                out_name = f"NORM_{self.prefix}_{i}_{name_part}.pcapng"
                out_path = os.path.join(output_dir, out_name)
                
                if os.path.exists(out_path): os.remove(out_path)
                
                # Use the 'utils' tool to actually cut the file
                if not utils.execute_crop(f, out_path, global_start, global_end):
                    self.finished_signal.emit(False, f"Failed to crop {base_name}", {})
                    return
                
                # Get a fresh summary of the newly created file
                summary = utils.get_pcap_summary(out_path, log_fn=lambda lvl, msg: logger.log(lvl, msg))
                if summary:
                    summary["protocols"] = WorkflowController.run_stage_2_summary(out_path)
                    summary["filename"] = os.path.basename(out_path)
                    summary["path"] = out_path
                    new_summaries.append(summary)
                    logger.log("SUCCESS", f"{base_name}: Aligned -> {int(summary['packets']):,} packets.")
                cropped_map[f] = out_path

            # Tell the UI that we are done
            self.finished_signal.emit(True, "Alignment complete.", {"map": cropped_map, "summaries": new_summaries})
        except Exception as e:
            logger.log("ERROR", f"Stage 1 Failure: {str(e)}")
            self.finished_signal.emit(False, str(e), {})

class SessionSummaryThread(QThread):
    """
    BACKGROUND TASK: Gathers basic information (metadata) for a list of files.
    """
    summary_signal = pyqtSignal(list)
    def __init__(self, file_paths):
        super().__init__()
        self.file_paths = file_paths
    def run(self):
        results = []
        for f in self.file_paths:
            summary = utils.get_pcap_summary(f, log_fn=lambda lvl, msg: logger.log(lvl, msg))
            if summary:
                summary["protocols"] = WorkflowController.run_stage_2_summary(f)
                summary["filename"] = os.path.basename(f)
                summary["path"] = f
                results.append(summary)
        self.summary_signal.emit(results)

class Stage2DiscoveryThread(QThread):
    """
    BACKGROUND TASK: Finds unique TCP or UDP conversations in a file.
    """
    flows_signal = pyqtSignal(list)
    def __init__(self, file_path, protocol):
        super().__init__()
        self.file_path = file_path
        self.protocol = protocol.lower()
    def run(self):
        try:
            tshark = ConfigManager.get_tshark_path()
            # -z conv: TShark's conversation list command
            cmd = [tshark, "-r", self.file_path, "-z", f"conv,{self.protocol}", "-q"]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            flows = []
            lines = out.splitlines()
            capture = False
            for line in lines:
                if "=================================" in line:
                    capture = not capture # Conversations are wrapped in these lines
                    continue
                if capture and "<->" in line:
                    parts = line.split()
                    if len(parts) < 4: continue
                    src_ip, src_port = self.split_host_port(parts[0])
                    dst_ip, dst_port = self.split_host_port(parts[2])
                    flows.append({"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port, "pkts": parts[3]})
            self.flows_signal.emit(flows[:50]) # Limit to top 50 for performance
        except Exception: self.flows_signal.emit([])
    def split_host_port(self, text):
        if ":" in text:
            idx = text.rfind(":")
            return text[:idx], text[idx+1:]
        return text, ""

class Stage2CorrelationThread(QThread):
    """
    BACKGROUND TASK: The 'Stream Matcher'.
    Matches specific packets from one file to another, even if the IP addresses 
    are different, by using unique packet fingerprints (DNA).
    """
    finished_signal = pyqtSignal(bool, str)
    def __init__(self, file_a, file_b, protocol, flex_tuple, options, output_configs):
        super().__init__()
        self.file_a = file_a
        self.file_b = file_b
        self.protocol = protocol.upper()
        self.flex_tuple = flex_tuple
        self.output_configs = output_configs 
    def run(self):
        try:
            logger.log("INFO", "S2S2S: Absolute Stream Reconstruction starting...")
            display_filter = self.parse_filter(self.flex_tuple)
            # DNA for TCP is sequence/ack numbers. For UDP, it's the payload itself.
            dna_fields = ["tcp.stream", "tcp.seq_raw", "tcp.ack_raw"] if self.protocol == "TCP" else ["udp.stream", "data"]
            
            # Use 'Multiprocessing' to work on both files at the same time using multiple CPU cores
            with Pool(processes=2) as pool:
                results = pool.map(harvest_dna_worker, [
                    (self.file_a, self.protocol, display_filter, dna_fields),
                    (self.file_b, self.protocol, None, dna_fields)
                ])
            
            dna_map_a, dna_map_b = results[0], results[1]
            seed_dna_pool = set().union(*dna_map_a.values())
            if not seed_dna_pool:
                self.finished_signal.emit(False, "No seed packets found."); return

            # Find which streams in File B contain ANY of the DNA fingerprints from File A
            target_pivot_set = {sid_b for sid_b, dna_set_b in dna_map_b.items() if not dna_set_b.isdisjoint(seed_dna_pool)}
            if not target_pivot_set:
                self.finished_signal.emit(False, "No matching streams in Target."); return

            # Export the results to new files
            if "seed_out" in self.output_configs:
                self.aggregated_export(self.file_a, self.output_configs["seed_out"], set(dna_map_a.keys()), self.protocol.lower())
            if "match_out" in self.output_configs:
                self.aggregated_export(self.file_b, self.output_configs["match_out"], target_pivot_set, self.protocol.lower())
            self.finished_signal.emit(True, "S2S2S Complete.")
        except Exception as e:
            logger.log("ERROR", f"Stage 2 Failure: {str(e)}")
            self.finished_signal.emit(False, str(e))

    def aggregated_export(self, input_file, output_file, stream_ids, proto):
        """Saves specific network streams to a new PCAP file."""
        tshark = ConfigManager.get_tshark_path()
        mergecap = ConfigManager.get_binary_path("mergecap")
        ids = sorted([str(sid) for sid in stream_ids])
        
        # We split the work into 'chunks' to avoid overloading the command line
        chunks = []; current_chunk = []; current_len = 0
        for sid in ids:
            if (current_len + len(sid) + 15) > 7000:
                chunks.append(current_chunk); current_chunk = [sid]; current_len = len(sid) + 15
            else:
                current_chunk.append(sid); current_len += len(sid) + 15
        if current_chunk: chunks.append(current_chunk)
        
        temp_files = []
        work_dir = os.path.dirname(os.path.abspath(output_file))
        try:
            for idx, chunk in enumerate(chunks):
                pass_output = os.path.join(work_dir, f"tmp_{idx}_{os.path.basename(output_file)}")
                filter_str = " || ".join([f"{proto}.stream == {sid}" for sid in chunk])
                cmd = [tshark, "-r", input_file, "-Y", filter_str, "-F", "pcapng", "-w", pass_output]
                subprocess.run(cmd, check=True, capture_output=True)
                temp_files.append(pass_output)
            
            # Merge all the chunks back into one final file
            if temp_files:
                if os.path.exists(output_file): os.remove(output_file)
                if len(temp_files) == 1: os.rename(temp_files[0], output_file)
                else: subprocess.run([mergecap, "-w", output_file] + temp_files, check=True)
        finally:
            # Clean up the temporary files we made
            for f in temp_files:
                if os.path.exists(f): os.remove(f)

    def parse_filter(self, text):
        """Converts user input (like an IP) into a valid Wireshark filter."""
        if "/" in text: return f"ip.addr == {text}"
        if ":" in text:
            ip, port = text.split(":")
            return f"ip.addr == {ip} && {self.protocol.lower()}.port == {port}"
        return f"ip.addr == {text}" if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text) else text

class MergePcapsThread(QThread):
    """
    BACKGROUND TASK: Combines multiple PCAP files into one.
    It can also 'label' packets so you know which file they came from.
    """
    finished_signal = pyqtSignal(bool, str)
    def __init__(self, input_data, output_file, add_origin=False):
        super().__init__()
        self.input_data = input_data; self.output_file = output_file; self.add_origin = add_origin
    def run(self):
        try:
            logger.log("INFO", f"Merging {len(self.input_data)} PCAPs...")
            mergecap = ConfigManager.get_binary_path("mergecap")
            editcap = ConfigManager.get_editcap_path()
            if not mergecap or not editcap: raise Exception("Wireshark utilities not found.")
            processed_files = []
            try:
                for entry in self.input_data:
                    path, alias = entry["path"], entry["alias"]
                    if self.add_origin:
                        # Add a comment to every packet: 'Origin=Server' or 'Origin=LB'
                        temp_labeled = os.path.join(os.path.dirname(self.output_file), f"label_{os.path.basename(path)}")
                        _, _, count = utils.get_pcap_times(path)
                        
                        if count > 0:
                            current_in = path
                            batch_size = 200 # Edit in small batches to avoid Windows command limits
                            
                            t1 = f"{temp_labeled}_p1.pcapng"
                            t2 = f"{temp_labeled}_p2.pcapng"
                            
                            for start_f in range(1, count + 1, batch_size):
                                end_f = min(start_f + batch_size - 1, count)
                                current_out = t2 if current_in == t1 or current_in == path else t1
                                
                                cmd = [editcap]
                                for f_idx in range(start_f, end_f + 1):
                                    cmd.extend(["-a", f"{f_idx}:Origin={alias}"])
                                cmd.extend([current_in, current_out])
                                subprocess.run(cmd, check=True, capture_output=True)
                                
                                if current_in != path and os.path.exists(current_in):
                                    try: os.remove(current_in)
                                    except Exception: pass
                                current_in = current_out
                            
                            if os.path.exists(temp_labeled): 
                                try: os.remove(temp_labeled)
                                except Exception: pass
                            os.rename(current_in, temp_labeled)
                            processed_files.append(temp_labeled)
                        else:
                            processed_files.append(path)
                    else: processed_files.append(path)
                
                # Finally merge the labeled files
                res = subprocess.run([mergecap, "-w", self.output_file] + processed_files, capture_output=True, text=True)
                if res.returncode != 0: raise Exception(f"Merge Error: {res.stderr}")
                logger.log("SUCCESS", f"Merge complete: {os.path.basename(self.output_file)}")
                self.finished_signal.emit(True, "Merge complete.")
            finally:
                if self.add_origin:
                    for f in processed_files:
                        if os.path.exists(f) and "label_" in os.path.basename(f):
                            try: os.remove(f)
                            except Exception: pass
        except Exception as e:
            logger.log("ERROR", f"Merge Failed: {str(e)}")
            self.finished_signal.emit(False, str(e))

class ExtractDataThread(QThread):
    """
    BACKGROUND TASK: The 'Converter'.
    Turns binary packet data into readable JSON, CSV, or Parquet tables.
    """
    finished_signal = pyqtSignal(bool, str)
    progress_signal = pyqtSignal(str, int) 

    def __init__(self, input_file, output_file, format_type, detailed=False):
        super().__init__()
        self.input_file = input_file; self.output_file = output_file
        self.format_type = format_type.lower(); self.detailed = detailed

    def run(self):
        try:
            logger.log("INFO", f"Extraction Suite: Starting {self.format_type.upper()} Workflow...")
            
            def update_progress(msg, val):
                self.progress_signal.emit(msg, val)

            # Find out which fields are available to extract
            valid_fields = WorkflowController.execute_utility_extraction(
                self.input_file, self.output_file, self.format_type, self.detailed, update_progress
            )
            
            if not valid_fields:
                self.finished_signal.emit(False, "Discovery/Mapping failed."); return

            update_progress("Initiating High-Speed Stream...", 60)
            tshark = ConfigManager.get_tshark_path()
            
            # FORMAT: JSON
            if self.format_type == "json":
                cmd = [tshark, "-r", self.input_file, "-T", "json"]
                if self.detailed: cmd.append("-x") # Include hex data
                with open(self.output_file, "w", encoding="utf-8") as f:
                    proc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
                    if proc.returncode != 0: raise Exception(f"TShark Error: {proc.stderr}")
            
            # FORMAT: CSV or PARQUET
            elif self.format_type == "parquet" or self.format_type == "csv":
                import pandas as pd
                sanitized_cols = [f.replace(".", "_").lstrip("_") for f in valid_fields]
                
                cmd = [tshark, "-r", self.input_file, "-T", "fields"]
                for f in valid_fields: cmd.extend(["-e", f])
                
                if self.format_type == "csv":
                    # Stream packets one by one to a CSV file to save memory
                    with open(self.output_file, "w", newline="", encoding="utf-8-sig") as f_out:
                        f_out.write(",".join(sanitized_cols) + "\n")
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
                        count = 0
                        for line in proc.stdout:
                            raw_line = line.rstrip('\n')
                            values = raw_line.split("\t")
                            if len(values) < len(sanitized_cols):
                                values += [""] * (len(sanitized_cols) - len(values))
                            
                            # Clean up values for CSV (escape quotes, etc.)
                            sanitized_values = [f'"{v.replace(",", ";").replace("\"", "\'")}"' for v in values]
                            f_out.write(",".join(sanitized_values) + "\n")
                            count += 1
                            if count % 25000 == 0:
                                update_progress(f"Streaming: {count:,} packets...", 80)
                        proc.stdout.close()
                        proc.wait()
                
                else: # Parquet
                    import pyarrow as pa
                    import pyarrow.parquet as pq
                    # Write in chunks of 100,000 packets to stay fast and stable
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
                    chunk_size = 100000; writer = None; count = 0
                    while True:
                        lines = []
                        for _ in range(chunk_size):
                            line = proc.stdout.readline()
                            if not line: break
                            lines.append(line.strip().split("\t"))
                        if not lines: break
                        df_chunk = pd.DataFrame(lines, columns=sanitized_cols[:len(lines[0])])
                        table = pa.Table.from_pandas(df_chunk)
                        if writer is None: writer = pq.ParquetWriter(self.output_file, table.schema)
                        writer.write_table(table)
                        count += len(lines)
                        update_progress(f"Writing Parquet: {count:,} packets...", 85)
                    if writer: writer.close()
                    proc.wait()

            update_progress("Finalizing File...", 100)
            self.finished_signal.emit(True, "Success.")
        except Exception as e:
            logger.log("ERROR", f"Extraction Failed: {str(e)}")
            self.finished_signal.emit(False, str(e))

class QueryParquetThread(QThread):
    """
    BACKGROUND TASK: Searches inside a Parquet file using database-like queries.
    """
    finished_signal = pyqtSignal(bool, object, str)
    def __init__(self, input_file, query_str):
        super().__init__()
        self.input_file = input_file
        self.query_str = query_str.replace(".", "_")
    def run(self):
        try:
            import pandas as pd
            df = pd.read_parquet(self.input_file)
            # Use Pandas .query() to filter the data
            results = df.query(self.query_str) if self.query_str.strip() else df
            self.finished_signal.emit(True, results, f"Found {len(results):,} packets.")
        except Exception as e:
            self.finished_signal.emit(False, None, str(e))

class QueryPcapThread(QThread):
    """
    BACKGROUND TASK: Searches inside a raw PCAP using TShark filters.
    """
    finished_signal = pyqtSignal(bool, object, str)
    def __init__(self, input_file, display_filter):
        super().__init__()
        self.input_file = input_file
        self.display_filter = display_filter

    def run(self):
        try:
            import pandas as pd
            tshark = ConfigManager.get_tshark_path()
            fields = ["frame.number", "frame.time", "ip.src", "ip.dst", "_ws.col.Protocol", "_ws.col.Info"]
            sanitized_cols = [f.replace(".", "_") for f in fields]
            
            cmd = [tshark, "-r", self.input_file, "-T", "fields"]
            if self.display_filter.strip(): cmd.extend(["-Y", self.display_filter])
            for f in fields: cmd.extend(["-e", f])
            cmd.extend(["-c", "1000"]) # Limit preview to 1,000 packets

            res = subprocess.run(cmd, capture_output=True, text=True)
            df = pd.read_csv(io.StringIO(res.stdout), sep='\t', names=sanitized_cols)
            self.finished_signal.emit(True, df, "PCAP Query Complete.")
        except Exception as e:
            self.finished_signal.emit(False, None, str(e))

class TokenCounterThread(QThread):
    """
    BACKGROUND TASK: Estimates the 'cost' of a file for AI analysis.
    It counts how many 'tokens' (chunks of text) are in the file.
    """
    finished_signal = pyqtSignal(bool, int, str)
    def __init__(self, input_file):
        super().__init__()
        self.input_file = input_file
    def run(self):
        try:
            import tiktoken
            # Use TShark to get a text summary of the file
            tshark = ConfigManager.get_tshark_path()
            cmd = [tshark, "-r", self.input_file, "-T", "text", "-c", "5000"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            text_content = res.stdout
            
            # Use the GPT-4 tokenizer to count tokens
            encoding = tiktoken.get_encoding("cl100k_base")
            count = len(encoding.encode(text_content))
            self.finished_signal.emit(True, count, f"Counted {count:,} tokens.")
        except Exception as e:
            self.finished_signal.emit(False, 0, str(e))
