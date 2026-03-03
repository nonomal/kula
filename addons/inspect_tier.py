#!/usr/bin/env python3

import struct
import sys
import os
import datetime
import json

MAGIC = b"KULASPIE"
HEADER_SIZE = 64

def inspect_tier(filepath):
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, 'rb') as f:
            buf = f.read(HEADER_SIZE)
            
            if len(buf) < HEADER_SIZE:
                print(f"Error: File too small ({len(buf)} bytes, expected {HEADER_SIZE} bytes)", file=sys.stderr)
                sys.exit(1)
                
            # Unpack the 64-byte header:
            # 0:8   magic (8 bytes string)
            # 8:16  version (uint64)
            # 16:24 max data size (uint64) -> we'll read as Q
            # 24:32 write offset (uint64) -> we'll read as Q
            # 32:40 total records written (uint64)
            # 40:48 oldest timestamp (int64, unix nano)
            # 48:56 newest timestamp (int64, unix nano)
            # 56:64 reserved (8 bytes)
            magic, version, max_data, write_off, count, oldest_nano, newest_nano, reserved = struct.unpack('<8sQQQQqq8s', buf)
            
            if magic != MAGIC:
                try:
                    magic_str = magic.decode('utf-8')
                except UnicodeDecodeError:
                    magic_str = repr(magic)
                print(f"Error: Invalid magic: {magic_str}", file=sys.stderr)
                sys.exit(1)

            wrapped = False
            if write_off > 0 and count > 0:
                if file_size >= HEADER_SIZE + max_data:
                    wrapped = True

            print(f"File: {filepath}")
            print(f"Version: {version}")
            
            current_data = max_data if wrapped else write_off
            pct = (current_data / max_data * 100) if max_data > 0 else 0.0
            print(f"Data Size: {current_data} / {max_data} bytes ({pct:.2f}%)")
            
            print(f"Write Offset: {write_off}")
            print(f"Total Records: {count}")
            
            # Using local timezone properly handling the nanoseconds
            oldest_ts = datetime.datetime.fromtimestamp(oldest_nano / 1e9).astimezone() if oldest_nano > 0 else None
            newest_ts = datetime.datetime.fromtimestamp(newest_nano / 1e9).astimezone() if newest_nano > 0 else None
            
            if oldest_ts:
                # Format to RFC3339 style if possible, or ISO8601
                print(f"Oldest Timestamp: {oldest_ts.isoformat()}")
            else:
                print(f"Oldest Timestamp: (none)")
                
            if newest_ts:
                print(f"Newest Timestamp: {newest_ts.isoformat()}")
            else:
                print(f"Newest Timestamp: (none)")
                
            print(f"Wrapped: {wrapped}")
            
            if oldest_ts and newest_ts:
                time_range = newest_ts - oldest_ts
                print(f"Time Range Covered: {time_range}")
                
            if count == 0:
                print("\nLatest Record: (none)")
                return

            segments = []
            if wrapped:
                segments.append((write_off, max_data - write_off))
                segments.append((0, write_off))
            else:
                segments.append((0, write_off))
                
            last_data = None
            for start, size in segments:
                f.seek(HEADER_SIZE + start)
                bytes_read = 0
                while bytes_read < size:
                    if size - bytes_read < 4:
                        break
                        
                    len_buf = f.read(4)
                    if len(len_buf) < 4:
                        break
                        
                    data_len = struct.unpack('<I', len_buf)[0]
                    if data_len == 0 or data_len > max_data:
                        break
                        
                    record_len = 4 + data_len
                    if bytes_read + record_len > size:
                        break
                        
                    data = f.read(data_len)
                    if len(data) < data_len:
                        break
                        
                    last_data = data
                    bytes_read += record_len

            if last_data:
                try:
                    parsed = json.loads(last_data.decode('utf-8'))
                    print("\nLatest Record:")
                    print(json.dumps(parsed, indent=2))
                except Exception as e:
                    print(f"\nLatest Record (failed to parse JSON): {last_data}")
            else:
                print("\nLatest Record: (none found)")

    except Exception as e:
        print(f"Error inspecting tier file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python inspect_tier.py <path-to-tier-file>", file=sys.stderr)
        sys.exit(1)
        
    inspect_tier(sys.argv[1])
