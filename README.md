# FAT32 - NTFS File System

## 1. Introduction

This is the Disk Explorer Application is a Python-based GUI tool designed to explore and interact with file systems on FAT32 and NTFS partitions. It allows users to navigate directories, view file details, and read the content of .txt files.

## 2. Execution
#### 1. Installation
Make sure you have connected with USB.
The program is written in Python and use some library, you need install library by:

```bash
pip install customtkinter pillow wmi
```
After that, you can run program with the following command:

```bash
python mai.py
```
#### 2. Usage
- Select a disk from the dropdown menu and click "Select Disk".

- Navigate through the file system:

	- Double-click folders to open them.
	- Double-click a .txt file to open its content in a new window.
	- Double-click ".." to return to the parent directory.
	- View file details in the tree view:

		- **File Name**: Name of the file or folder.
		- **Type**: File type (e.g., Folder, File).
		- **Size**: File size (formatted as B, KB, MB, or GB).
		- **Date**: Creation date of the file.

## 3. Detail Implementation

For more details, you can read the [report here](./Report/main.pdf).  
If you want to explore the source code, visit the [source folder](./Source/).
