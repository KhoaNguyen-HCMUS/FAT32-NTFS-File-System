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



def read_little_endian(data, offset, length):
    """ Đọc dữ liệu theo kiểu Little Endian """
    value = 0
    for i in range(length): 
        value += data[offset + i] << (i * 8)
    return value

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

def get_next_cluster(device, fat_offset, current_cluster, bytes_per_sector):
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

def read_tree(device, boot_sector, first_cluster, indent=""):
    """
    Đọc đệ quy toàn bộ cây thư mục bắt đầu từ 'first_cluster'.
    'indent' là chuỗi để thụt lề khi in (giúp hiển thị cấu trúc cây).
    """
    entries = read_directory(device, boot_sector, first_cluster)
    for entry in entries:
        icon = "📁" if entry['Type'] == "Folder" else "📄"

        print(f"{indent} {icon} {entry['Name']} | {entry['Type']} | Cluster: {entry['First Cluster']} | Size: {entry['Size']}")

        # Kiểm tra nếu là Folder và không phải '.' hay '..' để tránh vòng lặp vô hạn
        if entry['Type'] == "Folder" and entry['Name'] not in [".", ".."]:
            read_tree(device, boot_sector, entry['First Cluster'], indent + "   ")

def read_directory(device, boot_sector, first_cluster):
    """ Đọc tất cả file trong một thư mục bằng cách duyệt hết các cluster """
    bytes_per_sector = read_little_endian(boot_sector, 0x0B, 2)
    sectors_per_cluster = read_little_endian(boot_sector, 0x0D, 1)
    reserved_sectors = read_little_endian(boot_sector, 0x0E, 2)
    number_of_fats = read_little_endian(boot_sector, 0x10, 1)
    sectors_per_fat = read_little_endian(boot_sector, 0x24, 4)
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
            
        except PermissionError:
            print("❌ Không đủ quyền truy cập! Hãy chạy bằng quyền Administrator.")
            exit()
        except FileNotFoundError:
            print("❌ Ổ đĩa không tồn tại hoặc không thể truy cập.")
            exit()
        
        current_cluster = get_next_cluster(device, fat_offset, current_cluster, bytes_per_sector)
    
    return entries


#----NTFS----
def get_signed_byte(value):
    """Chuyển byte không dấu sang có dấu (cho MFT record size)."""
    return value if value < 0x80 else value - 256

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
    bytes_per_sector = read_little_endian(boot_sector, 0x0B, 2)
    sectors_per_cluster = read_little_endian(boot_sector, 0x0D, 1)
    total_sectors = read_little_endian(boot_sector, 0x28, 8)
    mft_cluster = read_little_endian(boot_sector, 0x30, 8)
    raw_mft_record_size = boot_sector[0x40]
    signed_mft_record_size = get_signed_byte(raw_mft_record_size)
    if signed_mft_record_size < 0:
        mft_record_size = 2 ** abs(signed_mft_record_size)
    else:
        mft_record_size = signed_mft_record_size * sectors_per_cluster * bytes_per_sector

    volume_serial = read_little_endian(boot_sector, 0x50, 8)
    
    info = {
        "Bytes per Sector": bytes_per_sector,
        "Sectors per Cluster": sectors_per_cluster,
        "Total Sectors": total_sectors,
        "MFT Cluster Number": mft_cluster,
        "MFT Record Size": mft_record_size,
        "Volume Serial Number": volume_serial,
    }
    return info

# ------------------------------
# Hàm đọc một MFT record và giải mã thông tin FILE_NAME
# ------------------------------
def parse_ntfs_mft_record(record_data, record_number):
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
    flags = read_little_endian(record_data, 22, 2)
    is_directory = bool(flags & 0x02)
    # Lấy offset các attribute từ record header (offset 20, 2 bytes)
    attr_offset = read_little_endian(record_data, 20, 2)
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
def read_all_mft_records(device, ntfs_info, max_records=1000):
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
                rec = parse_ntfs_mft_record(record_data, i)
                if rec:
                    records[i] = rec
    except Exception as e:
        print("❌ Lỗi khi đọc MFT:", e)
        sys.exit(1)
    return records

# ------------------------------
# Xây dựng cây thư mục từ danh sách MFT record (dựa trên parent reference)
# ------------------------------
def build_tree(records, root_record=5):
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

def print_tree(node, indent=""):
    """ In cây thư mục dạng đệ quy """
    if node is None:
        return
    icon = "📁" if node["is_directory"] else "📄"
    print(f"{indent}{icon} {node['name']} (Record {node['record_number']})")
    for child in sorted(node["children"], key=lambda x: x["name"]):
        print_tree(child, indent + "   ")


def main():
    device = get_device()
    boot_sector = read_boot_sector(device)
    filesystem = detect_filesystem(boot_sector)

    if filesystem == "FAT32":
        print("✅ Detected File System: FAT32")

        # In thông tin FAT32
        fat32_info = read_fat32_info(boot_sector)
        for k, v in fat32_info.items():
            print(f"🔹 {k}: {v}")

        # Lấy Root Cluster Index từ Boot Sector
        root_cluster = fat32_info["Root Cluster Index"]

        print("\n📂 Directory Tree (FAT32):")
        # Đọc toàn bộ cây thư mục
        read_tree(device, boot_sector, root_cluster)

    elif filesystem == "NTFS":
        print("✅ Detected File System: NTFS")

        # In thông tin NTFS
        ntfs_info = read_ntfs_info(boot_sector)
        for k, v in ntfs_info.items():
            print(f"🔹 {k}: {v}")

        # Lấy MFT Cluster Number từ Boot Sector
        mft_cluster = ntfs_info["MFT Cluster Number"]

        print("\n📂 Directory Tree (NTFS):")
        # Đọc toàn bộ MFT records và xây dựng cây thư mục
        records = read_all_mft_records(device, ntfs_info, max_records=1000)
        root = build_tree(records, root_record=5)
        if root is None:
            print("❌ Không tìm thấy root directory (record #5).")
            exit()

        print_tree(root)
        
    else:
        print("❌ Unknown File System")

if __name__ == "__main__":
    main()
