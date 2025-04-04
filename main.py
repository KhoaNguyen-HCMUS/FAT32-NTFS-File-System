import sys
class DiskManager:
    @staticmethod
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

    def read_tree(self, device, boot_sector, first_cluster, indent=""):
        """
        Đọc đệ quy toàn bộ cây thư mục bắt đầu từ 'first_cluster'.
        'indent' là chuỗi để thụt lề khi in (giúp hiển thị cấu trúc cây).
        """
        entries = self.read_directory(device, boot_sector, first_cluster)
        for entry in entries:
            icon = "📁" if entry['Type'] == "Folder" else "📄"

            print(f"{indent} {icon} {entry['Name']} | {entry['Type']} | Cluster: {entry['First Cluster']} | Size: {entry['Size']}")

            # Kiểm tra nếu là Folder và không phải '.' hay '..' để tránh vòng lặp vô hạn
            if entry['Type'] == "Folder" and entry['Name'] not in [".", ".."]:
                self.read_tree(device, boot_sector, entry['First Cluster'], indent + "   ")

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

                            entries.append({
                                "Name": name,
                                "Type": entry_type,
                                "First Cluster": first_cluster,
                                "Size": size if entry_type == "File" else "-"
                            })
                
            except PermissionError:
                print("❌ Không đủ quyền truy cập! Hãy chạy bằng quyền Administrator.")
                exit()
            except FileNotFoundError:
                print("❌ Ổ đĩa không tồn tại hoặc không thể truy cập.")
                exit()
            
            current_cluster = self.get_next_cluster(device, fat_offset, current_cluster, bytes_per_sector)
        
        return entries
    
    def search_file_in_fat32(self, device, boot_sector, current_cluster, file_name):
        """
        Recursively search for a file in all directories starting from the given cluster.
        - device: Path to the device (e.g., \\.\E:)
        - boot_sector: Boot sector data
        - current_cluster: Starting cluster of the directory
        - file_name: Name of the file to search for
        """
        entries = self.read_directory(device, boot_sector, current_cluster)
        for entry in entries:
            if entry["Name"] == file_name and entry["Type"] == "File":
                # File found, return its details
                return entry
            elif entry["Type"] == "Folder" and entry["Name"] not in [".", ".."]:
                # Recursively search in subdirectory
                result = self.search_file_in_fat32(device, boot_sector, entry["First Cluster"], file_name)
                if result:
                    return result
        return None
    
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


    def parse_ntfs_mft_record(self,record_data, record_number):
        """
        Giải mã một MFT record để lấy:
        - Signature ("FILE")
        - Flags (để xác định nếu record là directory)
        - FILE_NAME attribute: lấy parent directory (8 byte, dùng lower 48 bit) và tên file (utf-16le)
        Nếu không tìm thấy FILE_NAME, trả về None.
        """
        # Kiểm tra chữ ký "FILE"
        if record_data[0:4] != b"FILE":
            return None
        flags = FileSystemReader.read_little_endian(record_data, 22, 2)
        is_directory = bool(flags & 0x02)
        # Lấy offset các attribute từ record header (offset 20, 2 bytes)
        attr_offset = FileSystemReader.read_little_endian(record_data, 20, 2)
        file_name = None
        parent_ref = None
        offset = attr_offset
        while offset < len(record_data):
            # Mỗi attribute có:
            #   - Type (4 bytes). Nếu = 0xFFFFFFFF thì kết thúc.
            attr_type = int.from_bytes(record_data[offset:offset+4], "little")
            if attr_type == 0xFFFFFFFF:
                break
            attr_length = int.from_bytes(record_data[offset+4:offset+8], "little")
            if attr_length == 0:
                break
            # Nếu attribute là FILE_NAME (type 0x30)
            if attr_type == 0x30:
                # Resident attribute: đọc content length và offset từ header
                content_length = int.from_bytes(record_data[offset+16:offset+20], "little")
                content_offset = int.from_bytes(record_data[offset+20:offset+22], "little")
                content = record_data[offset+content_offset : offset+content_offset+content_length]
                # Cấu trúc FILE_NAME: 8 byte Parent, sau đó 48 byte các timestamp, size,... sau đó:
                # - File name length (1 byte) tại offset 64
                # - File name namespace (1 byte) tại offset 65
                # - File name (variable, 2 bytes/char) bắt đầu từ offset 66
                if len(content) < 66:
                    offset += attr_length
                    continue
                parent_ref_val = int.from_bytes(content[0:8], "little")
                # Lấy 48-bit thấp cho số record
                parent_record = parent_ref_val & 0xFFFFFFFFFFFF
                name_length = content[64]
                try:
                    name = content[66:66+name_length*2].decode("utf-16le", errors="ignore")
                except Exception:
                    name = "<Error decoding>"
                file_name = name
                parent_ref = parent_record
                break
            offset += attr_length
        if file_name is None:
            return None
        return {
            "record_number": record_number,
            "name": file_name,
            "parent": parent_ref,
            "is_directory": is_directory,
            "children": []
        }

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

    def print_tree(self, node, indent=""):
        """ In cây thư mục dạng đệ quy """
        if node is None:
            return

        if isinstance(node, dict):
            icon = "📁" if node["is_directory"] else "📄"
            print(f"{indent}{icon} {node['name']} (Record {node['record_number']})")
            for child in sorted(node["children"], key=lambda x: x["name"]):
                self.print_tree(child, indent + "   ")
        else:
            print(f"❌ Lỗi: Node không phải là dictionary. Loại: {type(node)}")

    def read_file_content(self, device, ntfs_info, mft_record):
        """
        Read the content of a file from the NTFS file system.
        - device: Path to the device (e.g., \\.\E:)
        - ntfs_info: NTFS boot sector information
        - mft_record: MFT record of the file
        """
        bytes_per_sector = ntfs_info["Bytes per Sector"]
        sectors_per_cluster = ntfs_info["Sectors per Cluster"]

        # Check if the file is resident or non-resident
        if mft_record.get("is_resident", False):
            # Resident data: Content is stored directly in the MFT record
            file_data = mft_record.get("data", b"")
            return file_data
        else:
            # Non-resident data: Content is stored in clusters on the disk
            data_runs = mft_record.get("data_runs", [])
            file_size = mft_record.get("size", 0)

            if not data_runs:
                print("❌ No data runs found for the file.")
                return b""

            file_data = b""
            with open(device, "rb") as disk:
                for run in data_runs:
                    # Calculate the offset of the cluster in the data region
                    cluster_offset = run["start_cluster"] * sectors_per_cluster * bytes_per_sector
                    cluster_size = run["length"] * sectors_per_cluster * bytes_per_sector

                    # Read the data from the cluster
                    disk.seek(cluster_offset)
                    data = disk.read(cluster_size)
                    file_data += data

                    # Stop reading if the file size has been reached
                    if len(file_data) >= file_size:
                        return file_data[:file_size]

            return file_data


def main():
    device = DiskManager.get_device()
    print(f"✅ Bạn đã chọn ổ đĩa: {device}")

    # Phát hiện hệ thống tập tin
    fs_reader = FileSystemReader(device)
    filesystem = fs_reader.detect_filesystem()
    boot_sector = fs_reader.boot_sector

    if filesystem == "FAT32":
        print("✅ Detected File System: FAT32")
        fat32_reader = FAT32Reader(device)
        # In thông tin FAT32
        fat32_info = fat32_reader.read_fat32_info(boot_sector)

        for k, v in fat32_info.items():
            print(f"🔹 {k}: {v}")

        # Lấy Root Cluster Index từ Boot Sector
        root_cluster = fat32_info["Root Cluster Index"]

        print("\n📂 Directory Tree (FAT32):")
        # Đọc toàn bộ cây thư mục
        fat32_reader.read_tree(device, boot_sector, root_cluster)

        file_name = input("\nEnter the name of the file to read: ").strip()
        file_entry = fat32_reader.search_file_in_fat32(device, boot_sector, root_cluster, file_name)

        if file_entry:
            # File found, read its content
            file_data = fat32_reader.read_file_content(
                device, boot_sector, file_entry["First Cluster"], file_entry["Size"]
            )
            print("\n📄 File Content:\n")
            print(file_data.decode("utf-8", errors="replace"))
        else:
            print(f"❌ File '{file_name}' not found.")

    elif filesystem == "NTFS":
        print("✅ Detected File System: NTFS")

        # In thông tin NTFS
        ntfs_reader = NTFSReader(device)
        ntfs_info = ntfs_reader.read_ntfs_info(ntfs_reader.boot_sector)  # Gán giá trị cho ntfs_info
        for k, v in ntfs_info.items():
            print(f"🔹 {k}: {v}")

        print("\n📂 Directory Tree (NTFS):")
        # Đọc toàn bộ MFT records và xây dựng cây thư mục
        records = ntfs_reader.read_all_mft_records(device, ntfs_info)

        root = ntfs_reader.build_tree(records, root_record=5)
        if root is None:
            print("❌ Không tìm thấy root directory (record #5).")
            exit()

        # In cây thư mục
        ntfs_reader.print_tree(root)
            # Prompt user to read a file
        file_name = input("\nEnter the name of the file to read: ").strip()
        for record in records.values():
            if record["name"] == file_name and not record["is_directory"]:
                file_data = ntfs_reader.read_file_content(device, ntfs_info, record)
                print("\n📄 File Content:\n")
                print(file_data.decode("utf-8", errors="replace"))
                break
        else:
            print(f"❌ File '{file_name}' not found.")
    else:
        print("❌ Unknown File System")

if __name__ == "__main__":
    main()
