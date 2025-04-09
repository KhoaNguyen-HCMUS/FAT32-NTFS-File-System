import sys

import customtkinter as ctk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import pythoncom

from disk_manager import DiskManager
from file_system_reader import FileSystemReader
from fat32_reader import FAT32Reader
from ntfs_reader import NTFSReader
import wmi


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
                    self.current_reader.ntfs_info = self.current_reader.read_ntfs_info(fs_reader.boot_sector)  # Store ntfs_info
                    self.ntfs_records = self.current_reader.read_all_mft_records(device, self.current_reader.ntfs_info)
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
                if entry["Name"] == "." or entry["Name"] == "..":
                    continue
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
