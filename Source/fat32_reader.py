from file_system_reader import FileSystemReader

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

        # Kiểm tra tại offset 12
        case_bits = entry[12]
        if case_bits & 0x08:  #  Viết thường tên nếu bit 3 được bật
            name = name.lower()
        if case_bits & 0x10:  # Viết thường phần mở rộng nếu bit 4 được bật
            ext = ext.lower()

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
        """Giải mã định dạng ngày FAT32 thành chuỗi YYYY-MM-DD."""
        year = ((raw_date >> 9) & 0x7F) + 1980
        month = (raw_date >> 5) & 0x0F
        day = raw_date & 0x1F
        return f"{year:04d}-{month:02d}-{day:02d}"

    def parse_time(self, raw_time):
        """Giải mã định dạng ngày FAT32 thành chuỗi HH-MM-SS."""
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
                                "Size": size if entry_type == "File" else "None",
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
        Đọc nội dung của một file từ hệ thống tập tin FAT32.
        - device: Đường dẫn đến thiết bị (ví dụ: \\.\E:)
        - boot_sector: Dữ liệu Boot Sector
        - start_cluster: Cluster bắt đầu của file
        - file_size: Kích thước của file (bytes)
        """
        fat32_info = self.read_fat32_info(boot_sector)
        bytes_per_sector = fat32_info["Bytes per Sector"]
        sectors_per_cluster = fat32_info["Sectors per Cluster"]
        reserved_sectors = fat32_info["Reserved Sectors"]
        number_of_fats = fat32_info["Number of FATs"]
        sectors_per_fat = fat32_info["Sectors per FAT"]

        # Tính toán các offset cần thiết
        fat_offset = reserved_sectors * bytes_per_sector
        data_offset = (reserved_sectors + number_of_fats * sectors_per_fat) * bytes_per_sector
        cluster_size = bytes_per_sector * sectors_per_cluster

        file_data = b""
        current_cluster = start_cluster

        while current_cluster:
            # Tính toán offset của cluster trong vùng dữ liệu
            cluster_offset = data_offset + (current_cluster - 2) * cluster_size
            with open(device, "rb") as disk:
                disk.seek(cluster_offset)
                data = disk.read(cluster_size)
                file_data += data

            # Kiểm tra xem đã đọc đủ kích thước file chưa
            if len(file_data) >= file_size:
                return file_data[:file_size]

            # Lấy cluster tiếp theo từ bảng FAT
            current_cluster = self.get_next_cluster(device, fat_offset, current_cluster, bytes_per_sector)

        return file_data

