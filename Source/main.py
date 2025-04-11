import customtkinter as ctk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import pythoncom

from PIL import Image, ImageTk  

from file_system_reader import FileSystemReader
from fat32_reader import FAT32Reader
from ntfs_reader import NTFSReader
import wmi


class DiskExplorerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("23127211_23127524 - Disk Explorer")
        self.geometry("1200x800")
        ctk.set_appearance_mode("Light")
        ctk.set_default_color_theme("blue")

        self.current_reader = None
        self.fs_type = None
        self.current_cluster_stack = []  # For FAT32 navigation
        self.current_node_stack = []     # For NTFS navigation
        self.ntfs_records = None
        self.ntfs_root = None

        self.folder_icon = ImageTk.PhotoImage(Image.open("assets/folder.png").resize((20, 20), Image.LANCZOS))
        self.file_icon = ImageTk.PhotoImage(Image.open("assets/info.png").resize((20, 20), Image.LANCZOS))
        self.txt_file_icon = ImageTk.PhotoImage(Image.open("assets/txt.png").resize((20, 20), Image.LANCZOS))

        # Khu vực chọn ổ đĩa
        self.disk_frame = ctk.CTkFrame(self)
        self.disk_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

        self.disk_combo = ctk.CTkComboBox(self.disk_frame, width=300)
        self.disk_combo.pack(side="left", padx=5, pady=5)
        self.disk_combo.set("Select a Disk")  # Set the default text

        self.select_btn = ctk.CTkButton(self.disk_frame, text="Select Disk", command=self.select_disk)
        self.select_btn.pack(side="left", padx=5)

        # Khu vực chính hiển thị ổ đĩa
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # Biểu diễn cây cho các tệp và thư mục
        self.tree = ttk.Treeview(self.main_frame, columns=("Type", "Size", "Date"), show="tree headings")
        self.tree.grid(row=0, column=0, sticky="nsew")

        # Header cho các cột
        self.tree.heading("#0", text="File name")  
        self.tree.heading("Type", text="Type")
        self.tree.heading("Size", text="Size")
        self.tree.heading("Date", text="Date")

        # Cấu hình các cột
        self.tree.column("#0", width=300, anchor="w")  # File name column
        self.tree.column("Type", width=150, anchor="center")
        self.tree.column("Size", width=100, anchor="center")
        self.tree.column("Date", width=200, anchor="center")

        # Thêm thanh cuộn dọc cho cây
        vsb = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)

        # Cấu hình các cột và hàng cho khu vực chính
        self.grid_columnconfigure(0, weight=3) 
        self.grid_columnconfigure(1, weight=1) 
        self.grid_rowconfigure(1, weight=1)  

        # Khu vực hiển thị thông tin tệp
        self.info_frame = ctk.CTkFrame(self)
        self.info_frame.grid(row=1, column=1, padx=2, pady=2, sticky="nsew") 
        self.info_frame.grid_rowconfigure(0, weight=1)

        # Thêm nhãn cho khu vực thông tin
        self.info_label = ctk.CTkLabel(self.info_frame, text="File system Info", font=("Arial", 16, "bold"))
        self.info_label.pack(pady=5)

        # Thêm 1 ScrolledText widget để hiển thị thông tin tệp 
        self.info_text = ScrolledText(self.info_frame, wrap="word", state="disabled", height=10)
        self.info_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Bắt sự kiện nhấp đúp vào cây
        self.tree.bind("<Double-1>", self.on_item_double_click)

        # Hiển thị nội dung tệp
        self.refresh_disks()

    def format_file_size(self, size_in_bytes):
        """
        Định dạng kích thước tệp thành chuỗi dễ đọc hơn.
        """
        if size_in_bytes < 1024:
            return f"{size_in_bytes} B"  # Bytes
        elif size_in_bytes < 1024 ** 2:
            return f"{size_in_bytes / 1024:.2f} KB"  # Kilobytes
        elif size_in_bytes < 1024 ** 3:
            return f"{size_in_bytes / (1024 ** 2):.2f} MB"  # Megabytes
        else:
            return f"{size_in_bytes / (1024 ** 3):.2f} GB"  # Gigabytes

    def update_info_frame(self, info):
        """Cập nhật thông tin ổ đĩa."""
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, "end")  # xóa nội dung cũ

        self.info_text.insert("end", f"File System: {self.fs_type} \n")  # thêm tiêu đề
        for key, value in info.items():
            self.info_text.insert("end", f"{key}: {value}\n")  # thêm thông tin mới

        self.info_text.config(state="disabled")  # đặt lại thành chế độ chỉ đọc

    def refresh_disks(self):
        def _refresh():
            pythoncom.CoInitialize()  # Khởi tạo COM trước khi sử dụng WMI
            try:
                # Lấy danh sách ổ đĩa từ WMI
                partitions = []
                c = wmi.WMI()
                for p in c.Win32_LogicalDisk():
                    if p.DriveType == 2:  # Ổ đĩa rời
                        partitions.append({
                            "device_id": p.DeviceID,
                        })
                self.disk_combo.configure(values=[f"{p['device_id']} " for p in partitions])

                # Cập nhật thông tin ổ đĩa nếu đã chọn
                if self.fs_type == "FAT32" and self.current_cluster_stack:
                    self.populate_fat32_tree(self.current_cluster_stack[-1])
                elif self.fs_type == "NTFS" and self.current_node_stack:
                    self.populate_ntfs_tree(self.current_node_stack[-1])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to refresh: {str(e)}")
            finally:
                pythoncom.CoUninitialize()  # Xóa COM

        threading.Thread(target=_refresh, daemon=True).start()

    def navigate_back(self):
        """Quay lại thư mục trước đó."""
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
        """Chọn ổ đĩa để đọc."""
        selection = self.disk_combo.get()
        if not selection:
            return
            
        device_id = selection.split()[0]
        device = fr"\\.\{device_id}"

        def _load_disk():
            try:
                fs_reader = FileSystemReader(device)
                self.fs_type = fs_reader.detect_filesystem()
                
                # Xác định loại hệ thống tập tin
                if self.fs_type == "FAT32":
                    self.current_reader = FAT32Reader(device)
                    fat32_info = self.current_reader.read_fat32_info(fs_reader.boot_sector)
                    root_cluster = fat32_info["Root Cluster Index"]
                    self.current_cluster_stack = [root_cluster]
                    self.populate_fat32_tree(root_cluster)
                    self.update_info_frame(fat32_info)
                    
                elif self.fs_type == "NTFS":
                    self.current_reader = NTFSReader(device)
                    self.current_reader.ntfs_info = self.current_reader.read_ntfs_info(fs_reader.boot_sector)  # Store ntfs_info
                    self.ntfs_records = self.current_reader.read_all_mft_records(device, self.current_reader.ntfs_info)
                    self.ntfs_root = self.current_reader.build_tree(self.ntfs_records)
                    self.current_node_stack = [self.ntfs_root]
                    self.populate_ntfs_tree(self.ntfs_root)
                    self.update_info_frame(self.current_reader.ntfs_info)
                    
                else:
                    messagebox.showerror("Error", "Unsupported filesystem")
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read disk: {str(e)}")
        
        threading.Thread(target=_load_disk, daemon=True).start()

    def populate_fat32_tree(self, cluster):
        """Điền dữ liệu vào cây cho FAT32."""
        self.tree.delete(*self.tree.get_children())
        try:
            entries = self.current_reader.read_directory(
                self.current_reader.device, 
                self.current_reader.boot_sector, 
                cluster
            )
            # Thêm ".." vào cây nếu có thư mục cha
            if len(self.current_cluster_stack) > 1:
                self.tree.insert("", "end", text="..", values=("Parent Folder", "", ""), image=self.folder_icon)
            
            for entry in entries:
                if entry["Name"] == "." or entry["Name"] == "..":
                    continue

                creation_datetime = f"{entry['Creation Date']} {entry['Creation Time']}"
                if entry["Type"] == "Folder":
                    self.tree.insert("", "end", text=entry["Name"], 
                                 values=("Folder", entry["Size"], creation_datetime),
                                 image=self.folder_icon)
                elif entry["Name"].lower().endswith(".txt"):
                    self.tree.insert("", "end", text=entry["Name"], 
                                 values=("File", self.format_file_size(entry["Size"]), creation_datetime),
                                 image=self.txt_file_icon)
                else:
                    self.tree.insert("", "end", text=entry["Name"], 
                                 values=("File", self.format_file_size(entry["Size"]), creation_datetime),
                                 image=self.file_icon)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load directory: {str(e)}")

    def populate_ntfs_tree(self, node):
        """Điền dữ liệu vào cây cho NTFS."""
        self.tree.delete(*self.tree.get_children())
        try:
            # Nếu có thư mục cha, thêm ".." vào cây
            if len(self.current_node_stack) > 1:
                self.tree.insert("", "end", text="..", values=("Parent Folder", "", ""), image=self.folder_icon)
            
            for child in node["children"]:
                if child["is_directory"]:
                    self.tree.insert("", "end", text=child["name"], 
                                 values=("Folder", child["size"], child["creation_time"]),
                                 image=self.folder_icon)
                elif child["name"].lower().endswith(".txt"):
                    self.tree.insert("", "end", text=child["name"], 
                                    values=("File", self.format_file_size(child["size"]), child["creation_time"]),
                                    image=self.txt_file_icon)
                else:
                    self.tree.insert("", "end", text=child["name"], 
                                    values=("File", self.format_file_size(child["size"]), child["creation_time"]),
                                    image=self.file_icon)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load directory: {str(e)}")

    def on_item_double_click(self, event):
        """Xử lý sự kiện nhấp đúp vào một mục trong cây."""
        item = self.tree.selection()[0]
        name = self.tree.item(item, "text")
        entry_type = self.tree.item(item, "values")[0]

        # Nếu là "..", điều hướng về thư mục cha
        if name == "..":
            self.navigate_back()
            return

        # Nếu là thư mục, điều hướng vào thư mục đó
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
            # Nếu là tệp, hiển thị nội dung tệp
            if name.lower().endswith(".txt"):
                self.display_file_content(name)
            else:
                messagebox.showinfo("Info", "Only .txt files can be previewed")

    def display_file_content(self, filename):
        try:
            # Đọc nội dung tệp từ FAT32 hoặc NTFS
            content = ""
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
                        ).decode("utf-8", errors="replace")
                        break
            elif self.fs_type == "NTFS":
                current_node = self.current_node_stack[-1]
                for child in current_node["children"]:
                    if child["name"] == filename and not child["is_directory"]:
                        content = self.current_reader.read_file_content(
                            self.current_reader.device,
                            self.current_reader.ntfs_info,
                            child
                        ).decode("utf-8", errors="replace")
                        break

            # Mở một cửa sổ mới để hiển thị nội dung tệp
            new_window = ctk.CTkToplevel(self)
            new_window.title(f"Viewing: {filename}")
            new_window.geometry("800x600")

            # Thêm ScrolledText widget để hiển thị nội dung tệp
            text_widget = ScrolledText(new_window, wrap="word", state="normal")
            text_widget.pack(fill="both", expand=True, padx=10, pady=10)
            text_widget.insert("1.0", content)
            text_widget.config(state="disabled")  # Đặt lại thành chế độ chỉ đọc

        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")

if __name__ == "__main__":
    app = DiskExplorerApp()
    app.mainloop()
