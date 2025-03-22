import sys

# ------------------------------
# Các hàm hỗ trợ đọc dữ liệu little endian
# ------------------------------
def read_little_endian(data, offset, length):
    """Đọc giá trị little endian từ mảng bytes."""
    value = 0
    for i in range(length):
        value += data[offset + i] << (8 * i)
    return value

def get_signed_byte(value):
    """Chuyển byte không dấu sang có dấu (cho MFT record size)."""
    return value if value < 0x80 else value - 256

# ------------------------------
# Đọc Boot Sector NTFS và phân tích các thông số cơ bản
# ------------------------------
def read_ntfs_boot_sector_from_device(device):
    """Đọc 512 byte đầu tiên của thiết bị (Boot Sector)"""
    try:
        with open(device, "rb") as disk:
            boot_sector = disk.read(512)
            return boot_sector
    except PermissionError:
        print("❌ Không đủ quyền truy cập! Hãy chạy bằng quyền Administrator hoặc sudo.")
        sys.exit(1)
    except FileNotFoundError:
        print("❌ Ổ đĩa không tồn tại hoặc không thể truy cập.")
        sys.exit(1)

def read_ntfs_boot_sector(boot_sector):
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

# ------------------------------
# Hàm lấy thiết bị từ người dùng (Windows)
# ------------------------------
def get_device():
    """Cho phép người dùng nhập ký tự ổ đĩa (VD: C, D, ...)"""
    while True:
        drive_letter = input("Nhập ký tự ổ đĩa (C, D, ...): ").strip().upper()
        if len(drive_letter) == 1 and drive_letter.isalpha():
            return fr"\\.\{drive_letter}:"
        else:
            print("❌ Vui lòng nhập đúng ký tự ổ đĩa (VD: C, D)")

# ------------------------------
# Main
# ------------------------------
def main():
    device = get_device()
    boot_sector = read_ntfs_boot_sector_from_device(device)
    # Kiểm tra OEM ID (offset 3-10), phải chứa "NTFS"
    oem_id = boot_sector[3:11].decode("ascii", errors="ignore").strip()
    if "NTFS" not in oem_id:
        print("❌ Hệ thống tập tin không phải là NTFS.")
        sys.exit(1)

    print("✅ Detected File System: NTFS")
    ntfs_info = read_ntfs_boot_sector(boot_sector)
    print("\nThông tin Boot Sector của NTFS:")
    for k, v in ntfs_info.items():
        print(f" - {k}: {v}")

    print("\nĐang đọc MFT (giới hạn {} record)...".format(1000))
    records = read_all_mft_records(device, ntfs_info, max_records=1000)
    if not records:
        print("❌ Không đọc được MFT records.")
        sys.exit(1)
    print(f"Đã đọc được {len(records)} record từ MFT.")

    print("\nXây dựng cây thư mục từ MFT (Root record #5)...")
    root = build_tree(records, root_record=5)
    if root is None:
        print("❌ Không tìm thấy root directory (record #5).")
        sys.exit(1)
    
    print("\nCây thư mục NTFS:")
    print_tree(root)

if __name__ == "__main__":
    main()
