def get_device():
    """ Cho phép người dùng nhập ký tự ổ đĩa (Windows) hoặc đường dẫn thiết bị (Linux) """
    while True:
        drive_letter = input("Nhập ký tự ổ đĩa (F, G, ...): ").strip().upper()
        if len(drive_letter) == 1 and drive_letter.isalpha():
            return fr"\\.\{drive_letter}:"  # Windows
        else:
            print("❌ Vui lòng nhập đúng ký tự ổ đĩa (VD: F, G)")

def read_boot_sector(device):
    """ Đọc 512 byte đầu tiên (Boot Sector) của thiết bị """
    try:
        with open(device, "rb") as disk:
            return disk.read(512)
    except PermissionError:
        print("❌ Không đủ quyền truy cập! Hãy chạy bằng quyền Administrator (Windows) hoặc sudo (Linux).")
        exit()
    except FileNotFoundError:
        print("❌ Ổ đĩa không tồn tại hoặc không thể truy cập.")
        exit()

def read_little_endian(data, offset, length):
    """ Đọc dữ liệu theo kiểu Little Endian """
    value = 0
    for i in range(length): 
        value += data[offset + i] << (i * 8)
    return value

def detect_filesystem(boot_sector):
    """ Xác định loại hệ thống tập tin (FAT32 / NTFS) """
    fat32_signature = "".join(chr(boot_sector[i]) for i in range(0x52, 0x52 + 8)).strip()
    ntfs_signature = "".join(chr(boot_sector[i]) for i in range(0x03, 0x03 + 8)).strip()

    if "FAT32" in fat32_signature:
        return "FAT32"
    elif "NTFS" in ntfs_signature:
        return "NTFS"
    else:
        return "UNKNOWN"

def read_fat32_info(boot_sector):
    """ Đọc thông tin từ Boot Sector nếu là FAT32 """
    info = {
        "Bytes per Sector": read_little_endian(boot_sector, 0x0B, 2),
        "Sectors per Cluster": read_little_endian(boot_sector, 0x0D, 1),
        "Reserved Sectors": read_little_endian(boot_sector, 0x0E, 2),
        "Number of FATs": read_little_endian(boot_sector, 0x10, 1),
        "Volume Size (sectors)": read_little_endian(boot_sector, 0x20, 4),
        "Sectors per FAT": read_little_endian(boot_sector, 0x24, 4),
        "Root Cluster Index": read_little_endian(boot_sector, 0x2C, 4),
        "FAT Type": "".join(chr(boot_sector[i]) for i in range(0x52, 0x52 + 8)).strip(),
    }
    return info

def read_ntfs_info(boot_sector):
    """ Đọc thông tin từ Boot Sector nếu là NTFS """
    info = {
        "Bytes per Sector": read_little_endian(boot_sector, 0x0B, 2),
        "Sectors per Cluster": read_little_endian(boot_sector, 0x0D, 1),
        "Total Sectors": read_little_endian(boot_sector, 0x28, 8),
        "MFT Cluster Index": read_little_endian(boot_sector, 0x30, 8),
        "MFT Mirror Cluster Index": read_little_endian(boot_sector, 0x38, 8),
        "MFT Record Size": boot_sector[0x40],
        "Index Buffer Size": boot_sector[0x48],
        "Volume Serial Number": read_little_endian(boot_sector, 0x50, 8),
    }
    return info

def parse_short_name(entry):
    """ Giải mã tên file ngắn từ entry chính """
    name = entry[:8].decode("ascii", errors="ignore").strip()
    ext = entry[8:11].decode("ascii", errors="ignore").strip()
    return f"{name}.{ext}" if ext else name

def clean_filename(name):
    """ Xóa ký tự NULL (0x00) và byte trống (0xFF) nhưng giữ nguyên Tiếng Việt """
    return name.split("\x00", 1)[0].replace("\xFF", "").strip()

def parse_lfn(entries):
    """ Giải mã tên file dài từ danh sách entry phụ (LFN) """
    name_parts = []
    for entry in reversed(entries):  # Đọc từ dưới lên
        part1 = entry[1:11].decode("utf-16le", errors="ignore")
        part2 = entry[14:26].decode("utf-16le", errors="ignore")
        part3 = entry[28:32].decode("utf-16le", errors="ignore")
        name_parts.append(part1 + part2 + part3)

    full_name = clean_filename("".join(name_parts))
    return full_name

def read_directory_entries(device, boot_sector):
    """ Đọc Root Directory Entries (RDET) của FAT32 """
    bytes_per_sector = read_little_endian(boot_sector, 0x0B, 2)
    sectors_per_cluster = read_little_endian(boot_sector, 0x0D, 1)
    reserved_sectors = read_little_endian(boot_sector, 0x0E, 2)
    number_of_fats = read_little_endian(boot_sector, 0x10, 1)
    sectors_per_fat = read_little_endian(boot_sector, 0x24, 4)
    root_cluster = read_little_endian(boot_sector, 0x2C, 4)

    # Tính toán vị trí của Root Directory
    first_data_sector = reserved_sectors + (number_of_fats * sectors_per_fat)
    root_directory_sector = first_data_sector + ((root_cluster - 2) * sectors_per_cluster)
    root_directory_offset = root_directory_sector * bytes_per_sector

    try:
        with open(device, "rb") as disk:
            disk.seek(root_directory_offset)
            data = disk.read(sectors_per_cluster * bytes_per_sector)

            entries = []
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
                    name = parse_short_name(entry)
                    if lfn_entries:
                        name = parse_lfn(lfn_entries)  # Ghép tên dài
                        lfn_entries = []  # Reset danh sách entry phụ

                    first_cluster = (entry[26] + (entry[27] << 8)) + ((entry[20] + (entry[21] << 8)) << 16)
                    size = read_little_endian(entry, 28, 4)
                    entry_type = "Folder" if attr & 0x10 else "File"

                    entries.append({
                        "Name": name,
                        "Type": entry_type,
                        "First Cluster": first_cluster,
                        "Size": size if entry_type == "File" else "-"
                    })
            
            return entries

    except PermissionError:
        print("❌ Không đủ quyền truy cập! Hãy chạy bằng quyền Administrator.")
        exit()
    except FileNotFoundError:
        print("❌ Ổ đĩa không tồn tại hoặc không thể truy cập.")
        exit()

def main():
    device = get_device()
    boot_sector = read_boot_sector(device)
    filesystem = detect_filesystem(boot_sector)

    if filesystem == "FAT32":
        print("✅ Detected File System: FAT32")
        entries = read_directory_entries(device, boot_sector)

        for data in read_fat32_info(boot_sector).items():
            print(f"🔹 {data[0]}: {data[1]}")

        print("\n📂 Root Directory Entries:")
        for entry in entries:
            print(f"📌 {entry['Name']} | {entry['Type']} | First Cluster: {entry['First Cluster']} | Size: {entry['Size']} bytes")
    else:
        print("❌ Unknown File System")

if __name__ == "__main__":
    main()
