import wmi

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