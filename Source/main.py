import sys
from datetime import datetime, timedelta #For NTFS timestamp parsing

import customtkinter as ctk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import wmi
import pythoncom

class DiskManager:
    def count_partitions():
        c = wmi.WMI()
        partitions = c.Win32_LogicalDisk()
        print("Danh sách phân vùng:")
        for p in partitions:
            print(f"Ổ đĩa: {p.DeviceID}, Loại: {p.Description}, Hệ thống tập tin: {p.FileSystem}")
        print(f"\nTổng số phân vùng: {len(partitions)}")


    def get_device():
        """ Cho phép người dùng nhập ký tự ổ đĩa (Windows) hoặc đường dẫn thiết bị (Linux) """
        while True:
            drive_letter = input("Nhập ký tự ổ đĩa (F, G, ...): ").strip().upper()
            if len(drive_letter) == 1 and drive_letter.isalpha():
                return fr"\\.\{drive_letter}:"  # Windows
            else:
                print("❌ Vui lòng nhập đúng ký tự ổ đĩa (VD: F, G)")

    
class FileSystemReader:
    def __init__(self, device):
        self.device = device
        self.boot_sector = self.read_boot_sector()

    def read_boot_sector(self):
        """Đọc 512 byte đầu tiên (Boot Sector) của thiết bị."""
        try:
            with open(self.device, "rb") as disk:
                return disk.read(512)
        except PermissionError:
            print("❌ Không đủ quyền truy cập! Hãy chạy bằng quyền Administrator.")
            exit()
        except FileNotFoundError:
            print("❌ Ổ đĩa không tồn tại hoặc không thể truy cập.")
            exit()

    def detect_filesystem(self):
        """Xác định loại hệ thống tập tin (FAT32 / NTFS)."""
        fat32_signature = "".join(chr(self.boot_sector[i]) for i in range(0x52, 0x52 + 8)).strip()
        ntfs_signature = "".join(chr(self.boot_sector[i]) for i in range(0x03, 0x03 + 8)).strip()

        if "FAT32" in fat32_signature:
            return "FAT32"
        elif "NTFS" in ntfs_signature:
            return "NTFS"
        else:
            return "UNKNOWN"
    
    def read_little_endian(data, offset, length):
        """ Đọc dữ liệu theo kiểu Little Endian """
        value = 0
        for i in range(length): 
            value += data[offset + i] << (i * 8)
        return value


class FAT32Reader(FileSystemReader):
    def __init__(self, device):
        super().__init__(device)

    @staticmethod
    def read_fat32_info(boot_sector):
        """ Đọc thông tin từ Boot Sector nếu là FAT32 """
        info = {
            "Bytes per Sector": FileSystemReader.read_little_endian(boot_sector, 0x0B, 2),
            "Sectors per Cluster": FileSystemReader.read_little_endian(boot_sector, 0x0D, 1),
            "Reserved Sectors": FileSystemReader.read_little_endian(boot_sector, 0x0E, 2),
            "Number of FATs": FileSystemReader.read_little_endian(boot_sector, 0x10, 1),
            "Volume Size (sectors)": FileSystemReader.read_little_endian(boot_sector, 0x20, 4),
            "Sectors per FAT": FileSystemReader.read_little_endian(boot_sector, 0x24, 4),
            "Root Cluster Index": FileSystemReader.read_little_endian(boot_sector, 0x2C, 4),
            "FAT Type": "".join(chr(boot_sector[i]) for i in range(0x52, 0x52 + 8)).strip(),
        }
        return info

    def parse_short_name(self,entry):
        """ Giải mã tên file ngắn từ entry chính """
        name = entry[:8].decode("ascii", errors="ignore").strip()
        ext = entry[8:11].decode("ascii", errors="ignore").strip()
        return f"{name}.{ext}" if ext else name

    def clean_filename(self,name):
        """ Xóa ký tự NULL (0x00) và byte trống (0xFF) nhưng giữ nguyên Tiếng Việt """
        return name.split("\x00", 1)[0].replace("\xFF", "").strip()

    def parse_lfn(self,entries):
        """ Giải mã tên file dài từ danh sách entry phụ (LFN) """
        name_parts = []
        for entry in reversed(entries):  # Đọc từ dưới lên
            part1 = entry[1:11].decode("utf-16le", errors="ignore")
            part2 = entry[14:26].decode("utf-16le", errors="ignore")
            part3 = entry[28:32].decode("utf-16le", errors="ignore")
            name_parts.append(part1 + part2 + part3)

        full_name = self.clean_filename("".join(name_parts))
        return full_name

    def parse_date(self, raw_date):
        """Parse FAT32 date format into a human-readable string."""
        year = ((raw_date >> 9) & 0x7F) + 1980
        month = (raw_date >> 5) & 0x0F
        day = raw_date & 0x1F
        return f"{year:04d}-{month:02d}-{day:02d}"

    def parse_time(self, raw_time):
        """Parse FAT32 time format into a human-readable string."""
        hours = (raw_time >> 11) & 0x1F
        minutes = (raw_time >> 5) & 0x3F
        seconds = (raw_time & 0x1F) * 2
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def get_next_cluster(self,device, fat_offset, current_cluster, bytes_per_sector):
        """ Tìm cluster kế tiếp từ bảng FAT """
        if current_cluster < 2:  # FAT32 bỏ qua cluster 0 và 1
            print(f"❌ Lỗi: Cluster {current_cluster} không hợp lệ!")
            return None

        fat_entry_offset = fat_offset + (current_cluster * 4)  # Mỗi FAT entry có 4 byte

        try:
            with open(device, "rb") as disk:
                disk.seek(fat_entry_offset)
                fat_entry = disk.read(4)
                if len(fat_entry) < 4:
                    return None
                
                next_cluster = int.from_bytes(fat_entry, "little") & 0x0FFFFFFF  

                # Nếu cluster là giá trị EOF, không có cluster tiếp theo
                if next_cluster >= 0x0FFFFFF8:
                    return None
                return next_cluster

        except Exception as e:
            # print(f"❌ Lỗi khi đọc FAT cluster {current_cluster}: {e}")
            return None

    def read_directory(self,device, boot_sector, first_cluster):
        """ Đọc tất cả file trong một thư mục bằng cách duyệt hết các cluster """

        # Lấy thông tin từ Boot Sector
        fat32_info = self.read_fat32_info(boot_sector)
        bytes_per_sector = fat32_info["Bytes per Sector"]
        sectors_per_cluster = fat32_info["Sectors per Cluster"]
        reserved_sectors = fat32_info["Reserved Sectors"]
        number_of_fats = fat32_info["Number of FATs"]
        sectors_per_fat = fat32_info["Sectors per FAT"]
        fat_offset = reserved_sectors * bytes_per_sector
        first_data_sector = reserved_sectors + (number_of_fats * sectors_per_fat)
        entries = []

        current_cluster = first_cluster
        while current_cluster:
            directory_sector = first_data_sector + ((current_cluster - 2) * sectors_per_cluster)
            directory_offset = directory_sector * bytes_per_sector

            try:
                with open(device, "rb") as disk:
                    disk.seek(directory_offset)
                    data = disk.read(sectors_per_cluster * bytes_per_sector)

                    lfn_entries = []
                    for i in range(0, len(data), 32):
                        entry = data[i:i+32]
                        if entry[0] == 0x00:
                            break  # Entry trống -> kết thúc
                        if entry[0] == 0xE5:
                            continue  # Entry đã bị xóa

                        attr = entry[11]
                        if attr == 0x0F:
                            lfn_entries.append(entry)  # Entry phụ (LFN)
                        else:
                            name = self.parse_short_name(entry)
                            if lfn_entries:
                                name = self.parse_lfn(lfn_entries)  # Ghép tên dài
                                lfn_entries = []  # Reset danh sách entry phụ

                            first_cluster = (entry[26] + (entry[27] << 8)) + ((entry[20] + (entry[21] << 8)) << 16)
                            size = FileSystemReader.read_little_endian(entry, 28, 4)
                            entry_type = "Folder" if attr & 0x10 else "File"

                            creation_time = self.parse_time(FileSystemReader.read_little_endian(entry, 14, 2))
                            creation_date = self.parse_date(FileSystemReader.read_little_endian(entry, 16, 2))

                            entries.append({
                                "Name": name,
                                "Type": entry_type,
                                "First Cluster": first_cluster,
                                "Size": size if entry_type == "File" else "-",
                                "Creation Date": creation_date,
                                "Creation Time": creation_time
                            })
                
            except PermissionError:
                print("❌ Không đủ quyền truy cập! Hãy chạy bằng quyền Administrator.")
                exit()
            except FileNotFoundError:
                print("❌ Ổ đĩa không tồn tại hoặc không thể truy cập.")
                exit()
            
            current_cluster = self.get_next_cluster(device, fat_offset, current_cluster, bytes_per_sector)
        
        return entries
    
    def read_file_content(self, device, boot_sector, start_cluster, file_size):
        """
        Read the content of a file from the FAT32 file system.
        - device: Path to the device (e.g., \\.\E:)
        - boot_sector: Boot sector data
        - start_cluster: Starting cluster of the file
        - file_size: Size of the file in bytes
        """
        fat32_info = self.read_fat32_info(boot_sector)
        bytes_per_sector = fat32_info["Bytes per Sector"]
        sectors_per_cluster = fat32_info["Sectors per Cluster"]
        reserved_sectors = fat32_info["Reserved Sectors"]
        number_of_fats = fat32_info["Number of FATs"]
        sectors_per_fat = fat32_info["Sectors per FAT"]

        # Calculate offsets
        fat_offset = reserved_sectors * bytes_per_sector
        data_offset = (reserved_sectors + number_of_fats * sectors_per_fat) * bytes_per_sector
        cluster_size = bytes_per_sector * sectors_per_cluster

        file_data = b""
        current_cluster = start_cluster

        while current_cluster:
            # Calculate the offset of the current cluster in the data region
            cluster_offset = data_offset + (current_cluster - 2) * cluster_size
            with open(device, "rb") as disk:
                disk.seek(cluster_offset)
                data = disk.read(cluster_size)
                file_data += data

            # Stop reading if the file size has been reached
            if len(file_data) >= file_size:
                return file_data[:file_size]

            # Get the next cluster from the FAT table
            current_cluster = self.get_next_cluster(device, fat_offset, current_cluster, bytes_per_sector)

        return file_data

    def menu_fat32(fat32_reader, device, boot_sector, current_cluster):
        """
        Menu system for navigating FAT32 directories and reading files.
        - fat32_reader: Instance of FAT32Reader
        - device: Path to the device
        - boot_sector: Boot sector data
        - current_cluster: Current directory cluster
        """
        parent_stack = []  # Stack to track parent directories

        while True:
            # Read the current directory
            entries = fat32_reader.read_directory(device, boot_sector, current_cluster)
            print("\n📂 Current Directory:")
            for entry in entries:
                icon = "📁" if entry["Type"] == "Folder" else "📄"
                print(f"  {icon} {entry['Name']} (Created: {entry['Creation Date']} {entry['Creation Time']}, Size: {entry['Size']})")

            # Prompt user for input
            user_input = input("\nEnter the name of a file or directory (or '..' to go back): ").strip()

            if user_input == "..":
                if not parent_stack:
                    print("❌ You are already at the root directory.")
                else:
                    # Go back to the parent directory
                    current_cluster = parent_stack.pop()
            else:
                # Search for the file or directory
                found_entry = None
                for entry in entries:
                    if entry["Name"].lower() == user_input.lower():
                        found_entry = entry
                        break

                if found_entry:
                    if found_entry["Type"] == "File":
                        # Handle file
                        if found_entry["Name"].endswith(".txt") or found_entry["Name"].endswith(".TXT"):
                            # Read and display the content of the .txt file
                            file_data = fat32_reader.read_file_content(
                                device, boot_sector, found_entry["First Cluster"], found_entry["Size"]
                            )
                            print("\n📄 File Content:\n")
                            print(file_data.decode("utf-8", errors="replace"))
                        else:
                            print(f"❌ Cannot read file '{found_entry['Name']}'. Only .txt files are supported.")
                    elif found_entry["Type"] == "Folder":
                        # Navigate into the directory
                        parent_stack.append(current_cluster)
                        current_cluster = found_entry["First Cluster"]
                    else:
                        print(f"❌ Unknown entry type for '{found_entry['Name']}'.")
                else:
                    print(f"❌ '{user_input}' not found in the current directory.")



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

class DiskExplorerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Disk Explorer")
        self.geometry("1200x800")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.current_reader = None
        self.fs_type = None
        self.current_cluster_stack = []  # For FAT32 navigation
        self.current_node_stack = []     # For NTFS navigation
        self.ntfs_records = None
        self.ntfs_root = None

        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Disk selection frame
        self.disk_frame = ctk.CTkFrame(self)
        self.disk_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

        self.disk_combo = ctk.CTkComboBox(self.disk_frame, width=300)
        self.disk_combo.pack(side="left", padx=5, pady=5)

        self.refresh_btn = ctk.CTkButton(self.disk_frame, text="Refresh", command=self.refresh_disks)
        self.refresh_btn.pack(side="left", padx=5)

        self.select_btn = ctk.CTkButton(self.disk_frame, text="Select Disk", command=self.select_disk)
        self.select_btn.pack(side="left", padx=5)

        self.back_btn = ctk.CTkButton(self.disk_frame, text="← Back", command=self.navigate_back)
        self.back_btn.pack(side="left", padx=5)

        # Main content area
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # Treeview with scrollbar
        self.tree = ttk.Treeview(self.main_frame, columns=("Type", "Size", "Date"), show="tree")
        self.tree.grid(row=0, column=0, sticky="nsew")

        vsb = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)

        # File content viewer
        self.content_text = ScrolledText(self.main_frame, wrap="word", state="disabled")
        self.content_text.grid(row=0, column=2, sticky="nsew", padx=5)

        # Configure weights
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(2, weight=2)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # Bind double click event
        self.tree.bind("<Double-1>", self.on_item_double_click)

        # Initial disk refresh
        self.refresh_disks()

    def refresh_disks(self):
        def _refresh():
            pythoncom.CoInitialize()  # Initialize COM for this thread
            try:
                partitions = []
                c = wmi.WMI()
                for p in c.Win32_LogicalDisk():
                    if p.DriveType == 2:  # Removable drives
                        partitions.append({
                            "device_id": p.DeviceID,
                            "description": p.Description,
                            "filesystem": p.FileSystem
                        })
                self.disk_combo.configure(values=[f"{p['device_id']} ({p['filesystem']})" for p in partitions])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to get disks: {str(e)}")
            finally:
                pythoncom.CoUninitialize()  # Clean up COM

        threading.Thread(target=_refresh, daemon=True).start()

    def navigate_back(self):
        if self.fs_type == "FAT32":
            if len(self.current_cluster_stack) > 1:
                self.current_cluster_stack.pop()
                self.populate_fat32_tree(self.current_cluster_stack[-1])
        elif self.fs_type == "NTFS":
            if len(self.current_node_stack) > 1:
                self.current_node_stack.pop()
                self.populate_ntfs_tree(self.current_node_stack[-1])
        
        # Clear content viewer when navigating
        self.content_text.config(state="normal")
        self.content_text.delete(1.0, "end")
        self.content_text.config(state="disabled")

    def select_disk(self):
        selection = self.disk_combo.get()
        if not selection:
            return
            
        device_id = selection.split()[0]
        device = fr"\\.\{device_id}"

        def _load_disk():
            try:
                fs_reader = FileSystemReader(device)
                self.fs_type = fs_reader.detect_filesystem()
                
                if self.fs_type == "FAT32":
                    self.current_reader = FAT32Reader(device)
                    fat32_info = self.current_reader.read_fat32_info(fs_reader.boot_sector)
                    root_cluster = fat32_info["Root Cluster Index"]
                    self.current_cluster_stack = [root_cluster]
                    self.populate_fat32_tree(root_cluster)
                    
                elif self.fs_type == "NTFS":
                    self.current_reader = NTFSReader(device)
                    ntfs_info = self.current_reader.read_ntfs_info(fs_reader.boot_sector)
                    self.ntfs_records = self.current_reader.read_all_mft_records(device, ntfs_info)
                    self.ntfs_root = self.current_reader.build_tree(self.ntfs_records)
                    self.current_node_stack = [self.ntfs_root]
                    self.populate_ntfs_tree(self.ntfs_root)
                    
                else:
                    messagebox.showerror("Error", "Unsupported filesystem")
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read disk: {str(e)}")
        
        threading.Thread(target=_load_disk, daemon=True).start()

    def populate_fat32_tree(self, cluster):
        self.tree.delete(*self.tree.get_children())
        try:
            entries = self.current_reader.read_directory(
                self.current_reader.device, 
                self.current_reader.boot_sector, 
                cluster
            )
            
            # Add ".." entry for parent directory
            if len(self.current_cluster_stack) > 1:
                self.tree.insert("", "end", text="..", values=("Parent Folder", "", ""))
            
            for entry in entries:
                if entry["Type"] == "Folder":
                    item = self.tree.insert("", "end", text=entry["Name"], 
                                          values=("Folder", entry["Size"], entry["Creation Date"]))
                else:
                    self.tree.insert("", "end", text=entry["Name"], 
                                   values=("File", entry["Size"], entry["Creation Date"]))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load directory: {str(e)}")

    def populate_ntfs_tree(self, node):
        self.tree.delete(*self.tree.get_children())
        try:
            # Add ".." entry for parent directory
            if len(self.current_node_stack) > 1:
                self.tree.insert("", "end", text="..", values=("Parent Folder", "", ""))
            
            for child in node["children"]:
                if child["is_directory"]:
                    item = self.tree.insert("", "end", text=child["name"], 
                                          values=("Folder", child["size"], child["creation_time"]))
                else:
                    self.tree.insert("", "end", text=child["name"], 
                                   values=("File", child["size"], child["creation_time"]))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load directory: {str(e)}")

    def on_item_double_click(self, event):
        item = self.tree.selection()[0]
        name = self.tree.item(item, "text")
        entry_type = self.tree.item(item, "values")[0]

        if name == "..":
            self.navigate_back()
            return

        if entry_type == "Folder":
            if self.fs_type == "FAT32":
                entries = self.current_reader.read_directory(
                    self.current_reader.device,
                    self.current_reader.boot_sector,
                    self.current_cluster_stack[-1]
                )
                for entry in entries:
                    if entry["Name"] == name and entry["Type"] == "Folder":
                        self.current_cluster_stack.append(entry["First Cluster"])
                        self.populate_fat32_tree(entry["First Cluster"])
                        break
            elif self.fs_type == "NTFS":
                current_node = self.current_node_stack[-1]
                for child in current_node["children"]:
                    if child["name"] == name and child["is_directory"]:
                        self.current_node_stack.append(child)
                        self.populate_ntfs_tree(child)
                        break
        else:
            if name.lower().endswith(".txt"):
                self.display_file_content(name)
            else:
                messagebox.showinfo("Info", "Only .txt files can be previewed")

    def display_file_content(self, filename):
        self.content_text.config(state="normal")
        self.content_text.delete(1.0, "end")
        
        try:
            if self.fs_type == "FAT32":
                entries = self.current_reader.read_directory(
                    self.current_reader.device,
                    self.current_reader.boot_sector,
                    self.current_cluster_stack[-1]
                )
                for entry in entries:
                    if entry["Name"] == filename and entry["Type"] == "File":
                        content = self.current_reader.read_file_content(
                            self.current_reader.device,
                            self.current_reader.boot_sector,
                            entry["First Cluster"],
                            entry["Size"]
                        )
                        self.content_text.insert("end", content.decode("utf-8", errors="replace"))
                        break
            elif self.fs_type == "NTFS":
                current_node = self.current_node_stack[-1]
                for child in current_node["children"]:
                    if child["name"] == filename and not child["is_directory"]:
                        content = self.current_reader.read_file_content(
                            self.current_reader.device,
                            self.current_reader.ntfs_info,
                            child
                        )
                        self.content_text.insert("end", content.decode("utf-8", errors="replace"))
                        break
        except Exception as e:
            self.content_text.insert("end", f"Error reading file: {str(e)}")
            
        self.content_text.config(state="disabled")

if __name__ == "__main__":
    app = DiskExplorerApp()
    app.mainloop()
