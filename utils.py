"""
utils.py - The Helper Toolbox
-----------------------------
This file contains various helper functions that interact with Wireshark's 
command-line tools (tshark, capinfos, editcap). 

Think of this as the "Swiss Army Knife" for the application. It handles the 
heavy lifting of reading packet files, extracting timestamps, and identifying 
which network protocols are being used.
"""

import os
import subprocess
import re
import datetime
import csv
import io
from config_manager import ConfigManager

def get_pcap_metadata_raw(file_path):
    """
    Asks the 'capinfos' tool for a list of facts about a PCAP file.
    
    Inputs:
        file_path (str): The full path to the PCAP file.
        
    Returns:
        dict: A dictionary of facts (like packet count, duration, etc.) 
              or an empty dictionary if it fails.
    """
    # Find where 'capinfos' is installed on this computer
    capinfos = ConfigManager.get_binary_path("capinfos")
    if not capinfos: return {}
    
    try:
        # Run the command: capinfos -T -m -u ...
        # -T: Table format, -m: Machine readable, -u: UTC time
        cmd = [capinfos, "-T", "-m", "-u", "-c", "-a", "-e", "-d", file_path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0: return {}
        
        # Parse the output which looks like a CSV row
        lines = res.stdout.strip().splitlines()
        if len(lines) < 2: return {}
        
        # Detect if the tool used tabs or commas to separate information
        delim = "\t" if "\t" in lines[0] else ","
        f = io.StringIO(res.stdout.strip())
        reader = csv.DictReader(f, delimiter=delim)
        data = next(reader)
        
        # Clean up the names of the facts (lowercase and no extra spaces)
        return {k.strip().lower(): v.strip() for k, v in data.items()}
    except Exception:
        return {}

def to_epoch(ts_str):
    """
    Converts a human-readable date/time string into a computer-friendly 'epoch' number.
    
    Example: '2023-01-01 12:00:00' -> 1672574400.0
    
    Inputs:
        ts_str (str): A timestamp string.
        
    Returns:
        float: The number of seconds since 1970 (the Unix Epoch).
    """
    if not ts_str or ts_str == "N/A": return 0.0
    # Try different time formats until one works
    for fmt in ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']:
        try:
            dt = datetime.datetime.strptime(ts_str, fmt).replace(tzinfo=datetime.timezone.utc)
            return dt.timestamp()
        except Exception: continue
    return 0.0

def get_pcap_times(file_path):
    """
    Finds the exact start time, end time, and packet count for a file.
    
    This function is more accurate than basic metadata because it looks 
    at the actual first and last packets in the file.
    
    Inputs:
        file_path (str): Path to the PCAP file.
        
    Returns:
        tuple: (start_epoch, end_epoch, packet_count)
    """
    tshark = ConfigManager.get_tshark_path()
    if not tshark: return None, None, 0

    try:
        # First, get a quick count from the general metadata
        info = get_pcap_metadata_raw(file_path)
        if not info: return None, None, 0

        count_str = info.get("number of packets", "0")
        count = int(count_str)
        if count == 0: return 0.0, 0.0, 0

        # Now, ask TShark for the EXACT timestamp of the first packet (frame 1)
        cmd_s = [tshark, "-r", file_path, "-T", "fields", "-e", "frame.time_epoch", "-c", "1"]
        start_epoch = float(subprocess.check_output(cmd_s, text=True, stderr=subprocess.DEVNULL).splitlines()[0])

        # And ask TShark for the timestamp of the very last packet
        cmd_e = [tshark, "-r", file_path, "-Y", f"frame.number == {count}", "-T", "fields", "-e", "frame.time_epoch"]
        end_out = subprocess.check_output(cmd_e, text=True, stderr=subprocess.DEVNULL).strip()
        
        if end_out:
            end_epoch = float(end_out.splitlines()[0])
        else:
            # If seeking the last packet failed, fallback to using the duration
            dur_str = info.get("capture duration (seconds)", info.get("duration", "0"))
            try: end_epoch = start_epoch + float(dur_str.split()[0])
            except Exception: end_epoch = start_epoch

        return start_epoch, end_epoch, count
    except Exception:
        return None, None, 0

def get_pcap_summary(file_path, log_fn=None):
    """
    Creates a 'Snapshot' of a PCAP file for the user interface.
    
    This combines timing, counts, and protocol information into one 
    easy-to-read package.
    
    Inputs:
        file_path (str): Path to the file.
        log_fn (function, optional): A function to send log messages to.
        
    Returns:
        dict: A summary containing packets, start/end times, and protocols.
    """
    tshark = ConfigManager.get_tshark_path()
    if not tshark: return None
    
    try:
        # Get high-precision timing
        t_start, t_end, t_count = get_pcap_times(file_path)
        if t_start is None: return None

        # Helper to turn an epoch number back into a readable time
        def fmt_ts(ep):
            dt = datetime.datetime.fromtimestamp(ep, datetime.timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        summary = {
            "packets": str(t_count),
            "start": fmt_ts(t_start),
            "end": fmt_ts(t_end),
            "duration": f"{t_end - t_start:.6f}",
            "protocols": [],
            "start_epoch": t_start,
            "end_epoch": t_end,
            "filename": os.path.basename(file_path)
        }

        # Protocol Discovery: Find out what's inside (e.g., HTTP, TLS, TCP)
        try:
            # -z io,phs: TShark's 'Protocol Hierarchy Statistics' command
            cmd_proto = [tshark, "-r", file_path, "-z", "io,phs", "-q"]
            out_proto = subprocess.check_output(cmd_proto, text=True, stderr=subprocess.DEVNULL)
            proto_counts = {}
            for line in out_proto.splitlines():
                if "frames:" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        p = parts[0].upper()
                        # Ignore common boring protocols to find the interesting ones
                        blacklist = ['FILEINFO', 'CMDLINE', 'VERSION', 'HOSTNAME', 'ETHERNET', 'FRAME', 'ETH', 'IP', 'IPV6', 'TCP', 'UDP']
                        if p not in blacklist:
                            try: proto_counts[p] = int(parts[1].split(":")[-1])
                            except Exception: proto_counts[p] = 1
            # Sort by packet count to get the most used protocols
            sorted_protos = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)
            summary["protocols"] = [x[0] for x in sorted_protos[:3]] if sorted_protos else ["TCP/UDP"]
        except Exception:
            summary["protocols"] = ["TCP/UDP"]

        return summary
    except Exception as e:
        if log_fn: log_fn("ERROR", f"Summary Error: {str(e)}")
        return None

def get_lean_times(file_path):
    """
    An ultra-fast version of timing retrieval. 
    
    Only looks at the very first and very last packet timestamps 
    to see how long the file is.
    """
    tshark = ConfigManager.get_tshark_path()
    if not tshark: return None, None

    try:
        # Start Time
        cmd_s = [tshark, "-r", file_path, "-T", "fields", "-e", "frame.time_epoch", "-c", "1"]
        start_out = subprocess.check_output(cmd_s, text=True, stderr=subprocess.DEVNULL).strip()
        if not start_out: return None, None
        start_epoch = float(start_out.splitlines()[0])

        # End Time (using capinfos duration is usually faster than scanning the file)
        capinfos = ConfigManager.get_binary_path("capinfos")
        if capinfos:
            cmd_c = [capinfos, "-T", "-m", "-u", "-d", file_path]
            res = subprocess.run(cmd_c, capture_output=True, text=True)
            if res.returncode == 0:
                lines = res.stdout.strip().splitlines()
                if len(lines) >= 2:
                    delim = "\t" if "\t" in lines[0] else ","
                    reader = csv.DictReader(io.StringIO(res.stdout.strip()), delimiter=delim)
                    data = next(reader)
                    data = {k.strip().lower(): v.strip() for k, v in data.items()}
                    dur_str = data.get("capture duration (seconds)", data.get("duration", "0"))
                    try:
                        return start_epoch, start_epoch + float(dur_str)
                    except Exception: pass

        return start_epoch, start_epoch
    except Exception:
        return None, None

def scout_protocols(file_path, limit=10000):
    """
    Quickly peeks at the first few thousand packets to see which protocols are active.
    """
    tshark = ConfigManager.get_tshark_path()
    if not tshark: return []
    
    try:
        cmd = [tshark, "-r", file_path, "-c", str(limit), "-T", "fields", "-e", "_ws.col.Protocol"]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        
        proto_counts = {}
        blacklist = {'F5FILEINFO', 'LINUX_SLL', 'ETHERNET', 'ETH', 'IP', 'IPV6', 'FRAME'}
        
        for line in out.splitlines():
            p = line.strip().upper()
            if not p or p in blacklist: continue
            for sub_p in p.split(','):
                sub_p = sub_p.strip()
                if sub_p in blacklist: continue
                proto_counts[sub_p] = proto_counts.get(sub_p, 0) + 1
        
        sorted_protos = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)
        return [x[0] for x in sorted_protos[:5]] 
    except Exception:
        return []

def execute_crop(input_file, output_file, start_epoch, end_epoch):
    """
    Creates a new PCAP file containing only packets within a specific time window.
    
    Inputs:
        input_file (str): The source PCAP.
        output_file (str): Where to save the cropped version.
        start_epoch (float): The beginning of the window.
        end_epoch (float): The end of the window.
        
    Returns:
        bool: True if successful, False otherwise.
    """
    tshark = ConfigManager.get_tshark_path()
    if not tshark: return False
    
    # -Y: Display Filter. We use frame.time_epoch to select packets by time.
    filter_str = f"frame.time_epoch >= {start_epoch:.6f} && frame.time_epoch <= {end_epoch:.6f}"
    cmd = [tshark, "-r", input_file, "-Y", filter_str, "-F", "pcapng", "-w", output_file]
    try:
        subprocess.run(cmd, check=True, stderr=subprocess.DEVNULL)
        return True
    except Exception: return False
