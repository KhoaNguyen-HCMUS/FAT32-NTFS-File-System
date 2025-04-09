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
