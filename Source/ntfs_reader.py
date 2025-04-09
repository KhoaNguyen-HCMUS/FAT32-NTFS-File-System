from datetime import datetime, timedelta #For NTFS timestamp parsing
from file_system_reader import FileSystemReader

class NTFSReader(FileSystemReader):
    def __init__(self, device):
        super().__init__(device)

    def get_signed_byte(value):
        """Chuyển byte không dấu sang có dấu (cho MFT record size)."""
        return value if value < 0x80 else value - 256

    @staticmethod    
    def read_ntfs_info(boot_sector):
        """
        Phân tích Boot Sector của NTFS.
        Lấy:
        - Bytes per Sector (offset 0x0B, 2 bytes)
        - Sectors per Cluster (offset 0x0D, 1 byte)
        - Total Sectors (offset 0x28, 8 bytes)
        - MFT Cluster Number (offset 0x30, 8 bytes)
        - MFT Record Size (offset 0x40, 1 byte; xử lý giá trị có dấu)
        - Volume Serial Number (offset 0x50, 8 bytes)
        """
        bytes_per_sector = FileSystemReader.read_little_endian(boot_sector, 0x0B, 2)
        sectors_per_cluster = FileSystemReader.read_little_endian(boot_sector, 0x0D, 1)
        total_sectors = FileSystemReader.read_little_endian(boot_sector, 0x28, 8)
        mft_cluster = FileSystemReader.read_little_endian(boot_sector, 0x30, 8)
        raw_mft_record_size = boot_sector[0x40]
        signed_mft_record_size = NTFSReader.get_signed_byte(raw_mft_record_size)
        if signed_mft_record_size < 0:
            mft_record_size = 2 ** abs(signed_mft_record_size)
        else:
            mft_record_size = signed_mft_record_size * sectors_per_cluster * bytes_per_sector

        volume_serial = FileSystemReader.read_little_endian(boot_sector, 0x50, 8)
        
        info = {
            "Bytes per Sector": bytes_per_sector,
            "Sectors per Cluster": sectors_per_cluster,
            "Total Sectors": total_sectors,
            "MFT Cluster Number": mft_cluster,
            "MFT Record Size": mft_record_size,
            "Volume Serial Number": volume_serial,
        }
        return info

    def parse_ntfs_timestamp(self, raw_timestamp):
        """Parse NTFS timestamp into a human-readable string."""
        timestamp = int.from_bytes(raw_timestamp, "little")
        if timestamp == 0:
            return "N/A"

        # NTFS epoch starts at 1601-01-01
        epoch = datetime(1601, 1, 1)
        utc_time = epoch + timedelta(microseconds=timestamp // 10)

        # Add time zone offset (e.g., UTC+7)
        timezone_offset = timedelta(hours=7)  # Adjust this value for your local time zone
        local_time = utc_time + timezone_offset

        return local_time.strftime("%Y-%m-%d %H:%M:%S")

    def parse_data_runs(self, data_run_bytes):
        runs = []
        offset = 0
        
        while offset < len(data_run_bytes):
            header = data_run_bytes[offset]
            if header == 0x00:
                break  # End of data runs
            
            len_bytes = (header & 0x0F)
            offset_bytes = (header >> 4) & 0x0F
            
            offset += 1
            
            # Đọc length và cluster offset
            run_length = int.from_bytes(data_run_bytes[offset:offset + len_bytes], byteorder="little", signed=False)
            offset += len_bytes
            
            cluster_offset = int.from_bytes(
                data_run_bytes[offset:offset + offset_bytes],
                byteorder="little",
                signed=True
            )
            offset += offset_bytes
            
            runs.append({
                "length": run_length,
                "start_cluster": cluster_offset
            })
        
        return runs

    def parse_ntfs_mft_record(self, record_data, record_number):
        """
        Parse an MFT record to extract:
        - Signature ("FILE")
        - Flags (to determine if the record is a directory)
        - FILE_NAME attribute: parent directory and file name
        - DATA attribute: file size
        """
        # Check for "FILE" signature
        if record_data[0:4] != b"FILE":
            return None

        mft_record = {
            "record_number": record_number,
            "name": None,
            "parent": None,
            "is_directory": None,
            "creation_time": None,
            "size": None,
            "allocated_size": None,
            "is_resident": None,
            "data": None,
            "data_runs": [],
            "children": []
        }

        flags = FileSystemReader.read_little_endian(record_data, 22, 2)
        mft_record["is_directory"] = bool(flags & 0x02)

        # Get the offset to the first attribute
        attr_offset = FileSystemReader.read_little_endian(record_data, 20, 2)
        offset = attr_offset

        # Initialize non_resident_flag to avoid undefined variable errors
        non_resident_flag = None

        while offset < len(record_data):
            # Each attribute has:
            # - Type (4 bytes). If 0xFFFFFFFF, it's the end of attributes.
            attr_type = int.from_bytes(record_data[offset:offset + 4], "little")
            if attr_type == 0xFFFFFFFF:
                break

            attr_length = int.from_bytes(record_data[offset + 4:offset + 8], "little")
            if attr_length == 0:
                break

            # STANDARD_INFORMATION attribute (type 0x10)
            if attr_type == 0x10:
                content_offset = int.from_bytes(record_data[offset + 20:offset + 22], "little")
                content = record_data[offset + content_offset:offset + content_offset + 48]
                mft_record["creation_time"] = self.parse_ntfs_timestamp(content[0:8])

            # FILE_NAME attribute (type 0x30)
            elif attr_type == 0x30 and mft_record["name"] is None:  # Only parse the first valid FILE_NAME
                # Read content length and offset from the attribute header
                content_length = int.from_bytes(record_data[offset + 16:offset + 20], "little")
                content_offset = int.from_bytes(record_data[offset + 20:offset + 22], "little")
                content = record_data[offset + content_offset:offset + content_offset + content_length]

                # Ensure the content is large enough to contain the required fields
                if len(content) < 66:
                    offset += attr_length
                    continue

                # Parse the parent reference (first 8 bytes)
                parent_ref_val = int.from_bytes(content[0:8], "little")
                mft_record["parent"] = parent_ref_val & 0xFFFFFFFFFFFF  # Extract the 48-bit record number

                # Parse the file name length (1 byte at offset 64)
                name_length = content[64]

                try:
                    # Decode the file name (UTF-16LE, starting at offset 66)
                    if name_length > 0:
                        mft_record["name"] = content[66:66 + name_length * 2].decode("utf-16le", errors="ignore").strip()
                        print(f"DEBUG: Parsed name for record {record_number}: {mft_record['name']}")
                    else:
                        mft_record["name"] = "<Empty Name>"
                        print(f"DEBUG: Empty name for record {record_number}")
                except Exception as e:
                    print(f"DEBUG: Error decoding FILE_NAME for record {record_number}: {e}")
                    mft_record["name"] = "<Error decoding>"

            # DATA attribute (type 0x80)
            elif attr_type == 0x80:
                non_resident_flag = record_data[offset + 8]
                mft_record["is_resident"] = non_resident_flag == 0

                if mft_record["is_resident"]:
                    # Resident data
                    content_length = int.from_bytes(record_data[offset + 16:offset + 20], "little")
                    mft_record["size"] = content_length
                    # Read resident data
                    content_offset = int.from_bytes(record_data[offset + 20:offset + 22], "little")
                    mft_record["data"] = record_data[offset + content_offset:offset + content_offset + content_length]
                else:
                    # Non-resident data
                    mft_record["allocated_size"] = int.from_bytes(record_data[offset + 40:offset + 48], "little")
                    mft_record["size"] = int.from_bytes(record_data[offset + 48:offset + 56], "little")
                    # Parse data runs for non-resident files
                    data_run_offset = int.from_bytes(record_data[offset + 32:offset + 34], "little")
                    if data_run_offset > 0:
                        data_run_data = record_data[offset + data_run_offset:offset + attr_length]
                        mft_record["data_runs"] = self.parse_data_runs(data_run_data)

            offset += attr_length

        if mft_record["name"] is None:
            mft_record["name"] = f"<Unknown_{record_number}>"

        print(f"DEBUG: Parsing $DATA attribute for record {record_number}")
        print(f"  Non-Resident Flag: {non_resident_flag}")
        print(f"  Resident: {mft_record['is_resident']}")
        if mft_record["is_resident"]:
            print(f"  Logical Size: {mft_record['size']}")
        else:
            print(f"  Logical Size: {mft_record['size']}")
            print(f"  Allocated Size: {mft_record['allocated_size']}")
            print(f"  Data Runs: {mft_record['data_runs']}")
        return mft_record

    # ------------------------------
    # Đọc một số MFT record từ NTFS (giả sử MFT nằm liền mạch)
    # ------------------------------
    def read_all_mft_records(self,device, ntfs_info, max_records=1000):
        """
        Đọc liên tiếp các MFT record từ vị trí MFT.
        Chú ý: Trong thực tế, MFT có thể bị phân mảnh; ví dụ này đơn giản giả sử MFT nằm liên tục.
        """
        records = {}
        bytes_per_sector = ntfs_info["Bytes per Sector"]
        sectors_per_cluster = ntfs_info["Sectors per Cluster"]
        mft_cluster = ntfs_info["MFT Cluster Number"]
        record_size = ntfs_info["MFT Record Size"]

        mft_offset = mft_cluster * sectors_per_cluster * bytes_per_sector

        try:
            with open(device, "rb") as disk:
                disk.seek(mft_offset)
                for i in range(max_records):
                    record_data = disk.read(record_size)
                    if len(record_data) < record_size:
                        break
                    rec = self.parse_ntfs_mft_record(record_data, i)
                    if rec:
                        records[i] = rec
        except Exception as e:
            print("❌ Lỗi khi đọc MFT:", e)
            sys.exit(1)
        return records

    # ------------------------------
    # Xây dựng cây thư mục từ danh sách MFT record (dựa trên parent reference)
    # ------------------------------
    def build_tree(self,records, root_record=5):
        """
        Xây dựng cây thư mục dựa vào:
        - Mỗi record có trường "parent" (lưu số record của thư mục chứa nó).
        - Root directory thường có record_number 5.
        Nếu một record có parent không có trong danh sách, bỏ qua hoặc ghép vào root.
        """
        # Khởi tạo trường children cho mọi record
        for rec in records.values():
            rec["children"] = []
        # Xây dựng cây: với mỗi record, nếu parent có trong danh sách thì thêm vào children của parent.
        for rec in records.values():
            parent = rec["parent"]
            if parent in records and parent != rec["record_number"]:
                records[parent]["children"].append(rec)
        # Trả về record gốc (nếu có)
        return records.get(root_record, None)

    def read_file_content(self, device, ntfs_info, mft_record):
        bytes_per_sector = ntfs_info["Bytes per Sector"]
        sectors_per_cluster = ntfs_info["Sectors per Cluster"]
        
        if mft_record.get("is_resident", False):
            return mft_record.get("data", b"")
        else:
            data_runs = mft_record.get("data_runs", [])
            file_size = mft_record.get("size", 0)
            
            file_data = b""
            with open(device, "rb") as disk:
                current_cluster = 0
                for run in data_runs:
                    # Tính toán offset vật lý
                    current_cluster += run["start_cluster"]
                    physical_offset = current_cluster * sectors_per_cluster * bytes_per_sector
                    bytes_to_read = run["length"] * sectors_per_cluster * bytes_per_sector
                    
                    disk.seek(physical_offset)
                    file_data += disk.read(bytes_to_read)
            
            return file_data[:file_size]  # Trim theo kích thước thực

    def menu_ntfs(self, device, ntfs_info, current_node):
        """
        Menu system for navigating NTFS directories and reading files.
        - device: Path to the device
        - ntfs_info: NTFS boot sector information
        - current_node: Current directory node
        """
        parent_stack = []  # Stack to track parent directories

        while True:
            # Display the current directory
            print("\n📂 Current Directory:")
            for child in current_node["children"]:
                icon = "📁" if child["is_directory"] else "📄"
                print(f"  {icon} {child['name']} (Created: {child['creation_time']}, Size: {child['size']})")

            # Prompt user for input
            user_input = input("\nEnter the name of a file or directory (or '..' to go back): ").strip()

            if user_input == "..":
                if not parent_stack:
                    print("❌ You are already at the root directory.")
                else:
                    # Go back to the parent directory
                    current_node = parent_stack.pop()
            else:
                # Search for the file or directory
                found_entry = None
                for child in current_node["children"]:
                    if child["name"].lower() == user_input.lower():
                        found_entry = child
                        break

                if found_entry:
                    if not found_entry["is_directory"]:
                        # Handle file
                        if found_entry["name"].endswith(".txt"):
                            # Read and display the content of the .txt file
                            file_data = self.read_file_content(device, ntfs_info, found_entry)
                            print("\n📄 File Content:\n")
                            print(file_data.decode("utf-8", errors="replace"))
                        else:
                            print(f"❌ Cannot read file '{found_entry['name']}'. Only .txt files are supported.")
                    else:
                        # Navigate into the directory
                        parent_stack.append(current_node)
                        current_node = found_entry
                else:
                    print(f"❌ '{user_input}' not found in the current directory.")
